// Tests of the gate publication core: the pure edit list over a synthetic image, and the runtime
// Publish / Inspect / RetargetKernels / Rollback path over synthetic in-memory provider mappings,
// including a replacement mapping that must be verified before anything is written into it.
#include "../../source/native/ampere_bundle.h"
#include <cstdio>
#include <cstring>
#include <vector>

using namespace ampere_bundle;
static int gFailures = 0;
static void Check(bool ok, const char* label) { if (!ok) { std::printf("FAIL %s\n", label); ++gFailures; } }

// The offsets 310.7.129.0 was originally pinned to; DiscoverLayout finds exactly these in that build.
static constexpr ProviderLayout kLayout_310_7_129{
    0x745000u,
    {0x181A0u, {0xB8, 0x90, 0x01, 0x00, 0x00, 0xC3, 0, 0}, 6, 1, 0x70},
    {0x17780u, {0xC7, 0x44, 0x24, 0x3C, 0x90, 0x01, 0x00, 0x00}, 8, 4, 0x70},
    {},
};

// A minimal PE64 mapping with the two exports DiscoverLayout needs and one kernel container that is
// already sm_86, so gate publication is exercised without any kernel edit.
struct MappedProvider {
    static constexpr size_t size = 0x3000;
    uint8_t* image = static_cast<uint8_t*>(VirtualAlloc(nullptr, size, MEM_COMMIT | MEM_RESERVE, PAGE_READWRITE));
    ~MappedProvider() { if (image) VirtualFree(image, 0, MEM_RELEASE); }
    HMODULE module() const { return reinterpret_cast<HMODULE>(image); }

    void Initialize() {
        auto* dos = reinterpret_cast<IMAGE_DOS_HEADER*>(image);
        dos->e_magic = IMAGE_DOS_SIGNATURE;
        dos->e_lfanew = 0x80;
        auto* nt = reinterpret_cast<IMAGE_NT_HEADERS64*>(image + 0x80);
        nt->Signature = IMAGE_NT_SIGNATURE;
        nt->OptionalHeader.Magic = IMAGE_NT_OPTIONAL_HDR64_MAGIC;
        nt->OptionalHeader.SizeOfImage = static_cast<DWORD>(size);
        nt->FileHeader.SizeOfOptionalHeader = sizeof(IMAGE_OPTIONAL_HEADER64);
        nt->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_EXPORT] = {0x300, sizeof(IMAGE_EXPORT_DIRECTORY)};
        auto* exports = reinterpret_cast<IMAGE_EXPORT_DIRECTORY*>(image + 0x300);
        exports->NumberOfFunctions = exports->NumberOfNames = 2;
        exports->AddressOfFunctions = 0x400;
        exports->AddressOfNames = 0x410;
        exports->AddressOfNameOrdinals = 0x420;
        const uint32_t functions[] = {0x800, 0x1000};
        const uint32_t names[] = {0x500, 0x540};
        const uint16_t ordinals[] = {0, 1};
        std::memcpy(image + 0x400, functions, sizeof functions);
        std::memcpy(image + 0x410, names, sizeof names);
        std::memcpy(image + 0x420, ordinals, sizeof ordinals);
        const char archName[] = "NVSDK_NGX_GetGPUArchitecture";
        const char reqName[] = "NVSDK_NGX_D3D12_GetFeatureRequirements";
        std::memcpy(image + 0x500, archName, sizeof archName);
        std::memcpy(image + 0x540, reqName, sizeof reqName);
        const uint8_t arch[] = {0xB8, 0x90, 1, 0, 0, 0xC3};
        const uint8_t req[] = {0xC7, 0x44, 0x24, 0x3C, 0x90, 1, 0, 0};
        std::memcpy(image + 0x800, arch, sizeof arch);
        std::memcpy(image + 0x1000, req, sizeof req);
        const uint32_t container[] = {0xBA55ED50, 0x00100001, 64, 0, 0x01010001, 64};
        std::memcpy(image + 0x2000, container, sizeof container);
        image[0x2010 + 28] = 86;
    }
};

static void TestRuntimePublication() {
    MappedProvider original, replacement;
    Check(original.image && replacement.image, "runtime provider allocations");
    if (!original.image || !replacement.image) return;
    original.Initialize();
    replacement.Initialize();
    ProviderLayout turing{};
    Check(DiscoverLayout(original.image, original.size, turing, 0x160) == Discovery::eOk,
        "Turing gate discovery");
    Check(turing.architecture.patchedValue == 0x60 && turing.discovery.patchedValue == 0x60,
        "Turing gates target 0x160");
    Check(original.image[0x801] == 0x90 && original.image[0x1004] == 0x90,
        "Turing discovery does not publish gates");
    Check(DiscoverLayout(original.image, original.size, turing, 0x150) == Discovery::eArchValue,
        "unsupported gate target rejected");
    Check(!Publish(original.module()) && CurrentStatus().state == State::eFailed, "publish without preparation fails");
    Prepare();
    Check(CurrentStatus().state == State::ePrepared && CurrentStatus().failure.empty(), "prepare resets a failed state");
    SetTargetArchitecture(0x160);
    Check(!Publish(original.module()) && CurrentStatus().state == State::ePrepared,
        "Turing refuses an image without validated selector sites");
    SetTargetArchitecture(0x170);
    Check(Publish(original.module()), "runtime publication succeeds");
    Prepare();
    Check(CurrentStatus().state == State::ePublished, "prepare after publish is a no-op");
    Check(original.image[0x801] == 0x70 && original.image[0x1004] == 0x70, "gates published");
    Check(RetargetKernels(original.module()), "kernels already sm_86: nothing to write");
    Check(CurrentStatus().kernelsRetargeted && CurrentStatus().containers == 1, "status reflects the plan");

    Live live;
    replacement.image[0x800] = 0x90; // same patch byte, different instruction
    Check(!Inspect(replacement.module(), live), "replacement instruction mismatch rejected");
    Check(!RetargetKernels(replacement.module()), "unverified replacement cannot retarget");
    Check(replacement.image[0x801] == 0x90 && replacement.image[0x1004] == 0x90, "rejected replacement gates unchanged");
    Check(Inspect(original.module(), live) && live.publishedBase == reinterpret_cast<uintptr_t>(original.image),
        "rejected replacement does not replace tracked provider");
    replacement.image[0x800] = 0xB8;
    replacement.image[0x1004] = 0x33;
    Check(!Inspect(replacement.module(), live), "unexpected replacement gate value rejected");
    Check(replacement.image[0x801] == 0x90, "all replacement sites checked before writes");
    replacement.image[0x1004] = 0x70; // an already-patched gate is acceptable
    Check(Inspect(replacement.module(), live) && live.healed, "valid replacement heals after rejection");
    Check(live.publishedBase == reinterpret_cast<uintptr_t>(replacement.image), "replacement is now the published image");
    Check(replacement.image[0x801] == 0x70 && replacement.image[0x1004] == 0x70, "replacement gates published");
    Check(RetargetKernels(replacement.module()), "verified replacement can retarget");
    Check(!RetargetKernels(original.module()), "the previous mapping is no longer accepted");
    Rollback();
    Check(replacement.image[0x801] == 0x90 && replacement.image[0x1004] == 0x90, "replacement rollback restores original gates");
    Check(CurrentStatus().state == State::eRolledBack, "rolled back");
    Prepare();
    Check(CurrentStatus().state == State::ePrepared && CurrentStatus().containers == 0, "prepare after rollback resets status");
}

static std::vector<uint8_t> Original(const ProviderLayout& l) {
    std::vector<uint8_t> image(l.sizeOfImage, 0xCC);
    std::memcpy(image.data() + l.architecture.rva, l.architecture.expected, l.architecture.length);
    std::memcpy(image.data() + l.discovery.rva, l.discovery.expected, l.discovery.length);
    if (l.discoveryVulkan.rva)
        std::memcpy(image.data() + l.discoveryVulkan.rva, l.discoveryVulkan.expected, l.discoveryVulkan.length);
    return image;
}

static void TestPureEdits() {
    const ProviderLayout& l = kLayout_310_7_129;
    std::vector<ByteEdit> edits;
    GateEdits(l, edits);
    Check(edits.size() == 2 && edits[0].rva < edits[1].rva, "two sorted gate edits without a Vulkan site");
    Check(edits[0].rva == l.discovery.rva + 4 && edits[0].before == 0x90 && edits[0].after == 0x70, "discovery edit");
    Check(edits[1].rva == l.architecture.rva + 1 && edits[1].before == 0x90 && edits[1].after == 0x70, "architecture edit");

    auto image = Original(l);
    const auto before = image;
    Check(VerifyImage(image.data(), image.size(), l) == ImageCheck::eOk, "original verifies");
    Check(ApplyEdits(image.data(), image.size(), edits), "apply");
    Check(image[l.architecture.rva + 1] == 0x70 && image[l.discovery.rva + 4] == 0x70, "both bytes patched");
    size_t differences = 0;
    for (size_t i = 0; i < image.size(); ++i) differences += image[i] != before[i];
    Check(differences == 2, "exactly two bytes differ");
    Check(VerifyImage(image.data(), image.size(), l) == ImageCheck::eArchitectureBytes, "patched image fails the strict check");
    Check(VerifyImage(image.data(), image.size(), l, true) == ImageCheck::eOk, "patched image passes with allowPatched");
    Check(!ApplyEdits(image.data(), image.size(), edits), "apply refuses an already patched image");
    RevertEdits(image.data(), image.size(), edits);
    Check(image == before, "revert restores the original");

    // A wrong non-patch byte is rejected by both checks; a wrong patch byte too.
    auto changed = before; changed[l.architecture.rva] = 0x90;
    Check(VerifyImage(changed.data(), changed.size(), l, true) == ImageCheck::eArchitectureBytes, "instruction mismatch rejected");
    changed = before; changed[l.discovery.rva + 4] = 0x33;
    Check(VerifyImage(changed.data(), changed.size(), l, true) == ImageCheck::eDiscoveryBytes, "unexpected patch value rejected");
    Check(!ApplyEdits(changed.data(), changed.size(), edits), "apply is all-or-nothing on a changed byte");
    Check(changed[l.architecture.rva + 1] == 0x90, "nothing written on refusal");
    Check(VerifyImage(before.data(), before.size() - 1, l) == ImageCheck::eSize, "size mismatch");
    Check(VerifyImage(nullptr, before.size(), l) == ImageCheck::eSize, "null image");

    // With a Vulkan site the third edit is present and reverts too.
    ProviderLayout vk = l;
    vk.discoveryVulkan = {0x17A80u, {0xC7, 0x44, 0x24, 0x2C, 0x90, 0x01, 0x00, 0x00}, 8, 4, 0x70};
    GateEdits(vk, edits);
    Check(edits.size() == 3, "three gate edits with a Vulkan site");
    auto vkImage = Original(vk);
    const auto vkBefore = vkImage;
    Check(ApplyEdits(vkImage.data(), vkImage.size(), edits) && vkImage[vk.discoveryVulkan.rva + 4] == 0x70, "vulkan byte patched");
    RevertEdits(vkImage.data(), vkImage.size(), edits);
    Check(vkImage == vkBefore, "vulkan revert restores");
    // Revert is tolerant: a byte no longer holding our value is left alone.
    ApplyEdits(vkImage.data(), vkImage.size(), edits);
    vkImage[vk.architecture.rva + 1] = 0x33;
    RevertEdits(vkImage.data(), vkImage.size(), edits);
    Check(vkImage[vk.architecture.rva + 1] == 0x33 && vkImage[vk.discovery.rva + 4] == 0x90, "revert only touches our values");
}

int main() {
    TestRuntimePublication();
    TestPureEdits();
    std::printf(gFailures ? "publication_tests: %d failure(s)\n" : "publication_tests: all passed\n", gFailures);
    return gFailures ? 1 : 0;
}
