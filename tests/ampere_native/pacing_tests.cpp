// CPU-only tests of the software-pacing pin over a synthetic plugin image, plus a self-check mode
// that plans (without writing) against a real sl.dlss_g: `ampere_pacing_tests <sl.dlss_g.dll>`.
#include "../../source/native/flip_metering.h"

#include <cstdio>
#include <cstring>
#include <string>
#include <vector>

using namespace flip_metering;
static int gFailures = 0;
static void Check(bool ok, const char* label) { if (!ok) { std::printf("FAIL %s\n", label); ++gFailures; } }

static void Put32(std::vector<uint8_t>& v, size_t at, uint32_t x) { std::memcpy(v.data() + at, &x, 4); }

static int SelfCheck(const wchar_t* path) {
    HMODULE module = LoadLibraryExW(path, nullptr, DONT_RESOLVE_DLL_REFERENCES);
    if (!module) { std::wprintf(L"cannot map %s (%lu)\n", path, GetLastError()); return 0; }
    auto* image = reinterpret_cast<uint8_t*>(module);
    const auto* dos = reinterpret_cast<const IMAGE_DOS_HEADER*>(image);
    const auto* nt = reinterpret_cast<const IMAGE_NT_HEADERS64*>(image + dos->e_lfanew);
    std::vector<Section> sections;
    const IMAGE_SECTION_HEADER* h = IMAGE_FIRST_SECTION(nt);
    for (unsigned i = 0; i < nt->FileHeader.NumberOfSections; ++i, ++h)
        sections.push_back({h->VirtualAddress, h->Misc.VirtualSize,
            (h->Characteristics & IMAGE_SCN_MEM_EXECUTE) != 0, (h->Characteristics & IMAGE_SCN_MEM_READ) != 0});
    Plan plan;
    const Outcome outcome = PlanSoftwarePacing(image, nt->OptionalHeader.SizeOfImage, sections.data(), sections.size(), plan);
    std::wprintf(L"file=%s outcome=%s marker=0x%X field=+0x%X value=%u sites=%zu alreadyPinned=%u\n", path,
        OutcomeName(outcome), plan.markerRva, plan.field, plan.value, plan.sites.size(), plan.alreadyPinned);
    for (const Site& s : plan.sites)
        std::wprintf(L"  site rva=0x%X len=%u %02X%02X%02X%02X%02X%02X%02X -> %02X%02X%02X%02X%02X%02X%02X\n", s.rva, s.length,
            s.before[0], s.before[1], s.before[2], s.before[3], s.before[4], s.before[5], s.before[6],
            s.after[0], s.after[1], s.after[2], s.after[3], s.after[4], s.after[5], s.after[6]);
    FreeLibrary(module);
    return 0;
}

static void RuntimeCheck(const std::vector<uint8_t>& source) {
    auto* image = static_cast<uint8_t*>(VirtualAlloc(nullptr, source.size(), MEM_RESERVE | MEM_COMMIT, PAGE_READWRITE));
    Check(image != nullptr, "allocate synthetic mapped PE");
    if (!image) return;
    std::memcpy(image, source.data(), source.size());
    std::memset(image, 0, 0x1000);
    auto* dos = reinterpret_cast<IMAGE_DOS_HEADER*>(image);
    dos->e_magic = IMAGE_DOS_SIGNATURE;
    dos->e_lfanew = sizeof(IMAGE_DOS_HEADER);
    auto* nt = reinterpret_cast<IMAGE_NT_HEADERS64*>(image + dos->e_lfanew);
    nt->Signature = IMAGE_NT_SIGNATURE;
    nt->FileHeader.SizeOfOptionalHeader = sizeof(IMAGE_OPTIONAL_HEADER64);
    nt->FileHeader.NumberOfSections = 2;
    nt->OptionalHeader.Magic = IMAGE_NT_OPTIONAL_HDR64_MAGIC;
    nt->OptionalHeader.SizeOfImage = static_cast<DWORD>(source.size());
    auto* sections = IMAGE_FIRST_SECTION(nt);
    sections[0].VirtualAddress = 0x1000;
    sections[0].Misc.VirtualSize = 0x1000;
    sections[0].Characteristics = IMAGE_SCN_MEM_READ;
    sections[1].VirtualAddress = 0x2000;
    sections[1].Misc.VirtualSize = 0x1000;
    sections[1].Characteristics = IMAGE_SCN_MEM_READ | IMAGE_SCN_MEM_EXECUTE;
    const auto module = reinterpret_cast<HMODULE>(image);
    const Result first = ForceSoftwarePacing(module);
    Check(first.outcome == Outcome::ePlanned && !first.pinnedBefore && first.sitesPatched == 2,
        "runtime first call patches both stores");
    const std::vector<uint8_t> pinned(image, image + source.size());
    for (unsigned i = 0; i < 3; ++i) {
        const Result again = ForceSoftwarePacing(module);
        Check(again.outcome == Outcome::eNothingToPin && again.pinnedBefore
            && again.field == first.field && again.value == first.value
            && again.sitesPatched == first.sitesPatched && again.alreadyPinned == first.alreadyPinned,
            "runtime repeated call returns cached result");
        Check(std::memcmp(image, pinned.data(), pinned.size()) == 0, "runtime repeated call leaves image unchanged");
    }
    const auto rejected = [&]() {
        const Result result = ForceSoftwarePacing(module);
        Check(result.outcome == Outcome::eNotDlssgPlugin && !result.pinnedBefore,
            "invalid mapped PE rejected before cache lookup");
        std::memcpy(image, pinned.data(), 0x1000);
    };
    dos->e_magic = 0;
    rejected();
    nt->Signature = 0;
    rejected();
    nt->OptionalHeader.Magic = IMAGE_NT_OPTIONAL_HDR32_MAGIC;
    rejected();
    nt->OptionalHeader.SizeOfImage = 0;
    rejected();
    nt->FileHeader.NumberOfSections = 0;
    rejected();
    sections[0].Misc.VirtualSize = 0;
    sections[1].VirtualAddress = nt->OptionalHeader.SizeOfImage;
    rejected();
    sections[0].Misc.VirtualSize = 0;
    sections[1].Misc.VirtualSize = nt->OptionalHeader.SizeOfImage;
    rejected();
    sections[0].Misc.VirtualSize = 0;
    Check(ForceSoftwarePacing(module).pinnedBefore, "one valid section still permits cached result");
    std::memcpy(image, pinned.data(), 0x1000);
    Restore();
    Check(std::memcmp(image + 0x1000, source.data() + 0x1000, source.size() - 0x1000) == 0,
        "runtime restore recovers original stores");
    Check(ForceSoftwarePacing(module).outcome == Outcome::ePlanned, "runtime restore clears cache");
    Restore();
    VirtualFree(image, 0, MEM_RELEASE);
}

int wmain(int argc, wchar_t** argv) {
    if (argc > 1) return SelfCheck(argv[1]);

    // Synthetic image: .rdata at 0x1000 holds the marker; .text at 0x2000 holds the code.
    std::vector<uint8_t> image(0x3000, 0x90);
    const char marker[] = "FG1 DLL has been detected";
    std::memcpy(image.data() + 0x1000, marker, sizeof marker);
    const uint32_t field = 0x4520;
    size_t at = 0x2000;
    // lea rcx, [rip+disp32] -> marker (48 8D 0D disp32); rip after = at+7.
    image[at] = 0x48; image[at + 1] = 0x8D; image[at + 2] = 0x0D;
    Put32(image, at + 3, static_cast<uint32_t>(0x1000 - (at + 7)));
    at += 7;
    // the fallback's own store: mov byte ptr [rbx+field], 1  (C6 83 disp32 01)
    image[at] = 0xC6; image[at + 1] = 0x83; Put32(image, at + 2, field); image[at + 6] = 1;
    const size_t fallbackStore = at; at += 7;
    // elsewhere: an opposite-value immediate store (should be flipped)
    at = 0x2100;
    image[at] = 0xC6; image[at + 1] = 0x81; Put32(image, at + 2, field); image[at + 6] = 0;
    const size_t oppositeStore = at;
    // a 7-byte register store: mov byte ptr [rsi+field], dil (40 88 BE disp32) (should be rewritten)
    at = 0x2200;
    image[at] = 0x40; image[at + 1] = 0x88; image[at + 2] = 0xBE; Put32(image, at + 3, field);
    const size_t registerStore = at;
    // an unrelated store of a different field (untouched), and a SIB-form store (untouched)
    at = 0x2300;
    image[at] = 0xC6; image[at + 1] = 0x81; Put32(image, at + 2, field + 8); image[at + 6] = 0;
    at = 0x2400;
    image[at] = 0xC6; image[at + 1] = 0x84; image[at + 2] = 0x24; Put32(image, at + 3, field); image[at + 7] = 0;
    const Section sections[] = {{0x1000, 0x1000, false, true}, {0x2000, 0x1000, true, true}};

    Plan plan;
    Check(PlanSoftwarePacing(image.data(), image.size(), sections, 2, plan) == Outcome::ePlanned, "planned");
    Check(plan.markerRva == 0x1000 && plan.field == field && plan.value == 1, "derived field and value");
    Check(plan.alreadyPinned == 1, "fallback store counted as already pinned");
    Check(plan.sites.size() == 2, "two sites to pin");
    auto before = image;
    Check(ApplyPlan(image.data(), image.size(), plan), "apply");
    Check(image[oppositeStore + 6] == 1, "immediate flipped to the fallback value");
    const uint8_t rewritten[7] = {0xC6, 0x86, 0x20, 0x45, 0x00, 0x00, 0x01};
    Check(std::memcmp(image.data() + registerStore, rewritten, 7) == 0, "register store rewritten to immediate form, same base");
    Check(image[fallbackStore + 6] == 1 && image[0x2300 + 6] == 0 && image[0x2400 + 7] == 0, "other stores untouched");
    size_t differences = 0, planned = 0;
    for (size_t i = 0; i < image.size(); ++i) differences += image[i] != before[i];
    for (const Site& s : plan.sites)
        for (size_t i = 0; i < s.length; ++i) planned += s.before[i] != s.after[i];
    Check(differences == planned && planned == 7, "exactly the planned bytes changed");
    Plan again;
    Check(PlanSoftwarePacing(image.data(), image.size(), sections, 2, again) == Outcome::eNothingToPin
          && again.alreadyPinned == 3, "second plan finds nothing left to pin");
    RevertPlan(image.data(), image.size(), plan);
    Check(image == before, "revert restores");
    // Without the marker it is not the plugin; with the marker but no store it is unreadable.
    std::vector<uint8_t> blank(0x3000, 0x90);
    Check(PlanSoftwarePacing(blank.data(), blank.size(), sections, 2, plan) == Outcome::eNotDlssgPlugin, "no marker");
    std::memcpy(blank.data() + 0x1000, marker, sizeof marker);
    Check(PlanSoftwarePacing(blank.data(), blank.size(), sections, 2, plan) == Outcome::eNoFallbackStore, "marker without store");
    // Opposite polarity: a fallback that writes 0 pins the others to 0.
    auto flipped = before;
    flipped[fallbackStore + 6] = 0; flipped[oppositeStore + 6] = 1;
    Check(PlanSoftwarePacing(flipped.data(), flipped.size(), sections, 2, plan) == Outcome::ePlanned
          && plan.value == 0 && plan.sites.size() == 2 && plan.sites[0].after[0] == 0, "polarity derived, not assumed");

    RuntimeCheck(before);

    std::printf(gFailures ? "pacing_tests: %d failure(s)\n" : "pacing_tests: all passed\n", gFailures);
    return gFailures ? 1 : 0;
}
