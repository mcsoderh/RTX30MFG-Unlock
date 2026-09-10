#include "../../source/native/turing_runtime.h"
#include "../../source/native/midpoint_fix.cpp"
#include "../provider_31091/data_image.h"

int wmain(int argc, wchar_t** argv)
{
    try
    {
        std::vector<ampere_bundle::ByteEdit> edits;
        std::vector<uint8_t> invalid(4096);
        Require(!turing_runtime::PlanSelectors(invalid.data(), invalid.size(), edits), "non-PE rejected");
        Require(!turing_runtime::Relocate(nullptr, 0), "null relocation rejected");
        if (argc != 2) return 0;
        DataImage image(argv[1]);
        auto module = reinterpret_cast<HMODULE>(image.base);
        Require(turing_runtime::PlanSelectors(image.base, image.bytes, edits), "real paired selectors discovered");
        const auto selectors = edits;
        image.base[edits[0].rva] = 0x7c;
        Require(!turing_runtime::PlanSelectors(image.base, image.bytes, edits) && edits.empty(), "unpaired selector rejected");
        image.base[selectors[0].rva] = selectors[0].before;
        const auto directory = image.nt->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_EXCEPTION];
        image.nt->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_EXCEPTION].Size = 0;
        Require(!turing_runtime::PlanSelectors(image.base, image.bytes, edits), "missing instruction provenance rejected");
        image.nt->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_EXCEPTION] = directory;
        using namespace midpoint_fix;
        dlssg_provider_policy::VersionTriplet version{};
        Require(dlssg_provider_policy::ReadProviderVersion(argv[1], version), "provider version");
        const auto* profile = ProfileForVersion(version);
        Require(profile != nullptr, "supported temporal profile");
        const uintptr_t entry = FindDescriptorEntry(module, static_cast<uint32_t>(image.bytes), *profile);
        Require(entry != 0, "hash-validated descriptor discovery");
        auto* table = reinterpret_cast<uintptr_t*>(entry - profile->temporalSlot * 8);
        const uintptr_t original = table[profile->temporalSlot];
        auto* desc = reinterpret_cast<uint8_t*>(original);
        auto* source = reinterpret_cast<uint8_t*>(ReadU64(desc + 8));
        std::vector<uint8_t> clone(kDescriptorBytes + kOutputCapacity + kScratchCapacity);
        std::memcpy(clone.data(), desc, kDescriptorBytes);
        std::memcpy(clone.data() + kDescriptorBytes, source, profile->sourceFatbinBytes);
        uint32_t output = 0;
        Failure failure{};
        Require(BuildTemporalFatbin(clone.data() + kDescriptorBytes,
            clone.data() + kDescriptorBytes + kOutputCapacity, *profile, output, failure), "real temporal clone built");
        const uintptr_t fatbin = reinterpret_cast<uintptr_t>(clone.data() + kDescriptorBytes);
        std::memcpy(clone.data() + 8, &fatbin, 8);
        std::memcpy(clone.data() + 16, &output, 4);
        const uint32_t sourceSize = static_cast<uint32_t>(profile->sourceFatbinBytes);
        std::memcpy(desc + 16, &sourceSize, 4);
        gProvider = module; gProfile = profile; gAllocation = clone.data();
        gDescriptorEntry = entry; gOriginalDescriptor = original;
        gReplacementDescriptor = reinterpret_cast<uintptr_t>(clone.data());
        gReady = true; gTuringTarget = true;
        table[profile->temporalSlot] = gReplacementDescriptor;
        uintptr_t found = 0, trusted = 0;
        Require(TuringDescriptors(module, image.bytes, found, trusted), "owned clone validated");
        table[profile->temporalSlot] += 8;
        Require(!turing_runtime::Relocate(module, image.bytes), "arbitrary external descriptor rejected");
        table[profile->temporalSlot] -= 8;
        const std::vector<uint8_t> before(image.base, image.base + image.bytes);
        const std::vector<uint8_t> cloneBefore = clone;
        for (int iteration = 0; iteration < 2; ++iteration)
        {
            Require(turing_runtime::Relocate(module, image.bytes), "full real provider relocation");
            Require(turing_runtime::Ready() && turing_runtime::Relocate(module, image.bytes), "repeated create idempotent");
            Require(table[profile->temporalSlot] == gReplacementDescriptor, "midpoint pointer identity preserved");
            const auto* lowered = reinterpret_cast<const uint8_t*>(ReadU64(clone.data() + 8));
            Require(ReadU32(lowered + 44) == 75, "clone sm75 architecture");
            const std::string text(reinterpret_cast<const char*>(lowered + 120));
            Require(text.find(profile->temporalInput) != std::string::npos, "corrected temporal input preserved");
            const uint8_t retained = lowered[0];
            turing_runtime::Rollback();
            Require(!turing_runtime::Ready(), "rollback clears readiness");
            Require(std::memcmp(image.base, before.data(), image.bytes) == 0, "complete image rollback including sizes");
            Require(clone == cloneBefore, "temporal clone contents restored");
            Require(lowered[0] == retained, "visible allocations survive rollback");
        }
        gProvider = nullptr; gProfile = nullptr; gAllocation = nullptr; gReady = false;
        std::cout << "TURING_RUNTIME_PASSED\n";
        return 0;
    }
    catch (const std::exception& error)
    {
        std::cerr << "FAIL " << error.what() << '\n';
        return 1;
    }
}
