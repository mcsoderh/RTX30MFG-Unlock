// CPU-only tests of the in-place kernel retarget and the gate-byte verification over synthetic images.
#include "../../source/native/ampere_bundle.h"

#include <algorithm>
#include <array>
#include <cstdio>
#include <cstring>
#include <string>
#include <vector>

namespace {
int failures = 0;
void Check(bool condition, const char* name) {
    if (!condition) { std::fprintf(stderr, "FAIL: %s\n", name); ++failures; }
}

// LZ4 block holding `text` as literals only (one sequence, no match).
std::vector<uint8_t> LiteralBlock(const std::string& text) {
    std::vector<uint8_t> out;
    out.push_back(0xF0);
    size_t rest = text.size() - 15;
    while (rest >= 255) { out.push_back(255); rest -= 255; }
    out.push_back(static_cast<uint8_t>(rest));
    out.insert(out.end(), text.begin(), text.end());
    return out;
}
void Literals(std::vector<uint8_t>& out, const std::string& text, bool last, uint16_t offset = 0, size_t match = 0) {
    const size_t n = text.size();
    uint8_t token = static_cast<uint8_t>(std::min<size_t>(n, 15) << 4);
    if (!last) token |= static_cast<uint8_t>(match - 4);
    out.push_back(token);
    if (n >= 15) { size_t rest = n - 15; while (rest >= 255) { out.push_back(255); rest -= 255; } out.push_back(static_cast<uint8_t>(rest)); }
    out.insert(out.end(), text.begin(), text.end());
    if (!last) { out.push_back(static_cast<uint8_t>(offset)); out.push_back(static_cast<uint8_t>(offset >> 8)); }
}

struct EntrySpec { uint16_t kind; uint32_t arch; std::vector<uint8_t> payload; uint32_t compressed; uint32_t unpacked; uint64_t flags; };
// One fatbin container from the given entries (header size 0x50, as the provider uses).
std::vector<uint8_t> Container(const std::vector<EntrySpec>& entries) {
    std::vector<uint8_t> c;
    auto put = [&](auto v) { const uint8_t* b = reinterpret_cast<const uint8_t*>(&v); c.insert(c.end(), b, b + sizeof v); };
    const uint32_t hs = 0x50;
    uint64_t total = 0;
    for (const auto& e : entries) total += hs + e.payload.size();
    put(uint32_t{0xBA55ED50}); put(uint16_t{1}); put(uint16_t{16}); put(total);
    for (const auto& e : entries) {
        put(e.kind); put(uint16_t{0x0101}); put(hs); put(uint64_t{e.payload.size()});
        uint32_t fields[16] = {};
        fields[0] = e.compressed; fields[1] = 0x40; fields[2] = 0x80005; fields[3] = e.arch;
        fields[6] = static_cast<uint32_t>(e.flags); fields[10] = e.unpacked; fields[12] = 0x48;
        for (uint32_t f : fields) put(f);
        c.insert(c.end(), e.payload.begin(), e.payload.end());
    }
    return c;
}
EntrySpec Ptx(uint32_t arch, const std::string& text, std::vector<uint8_t> block) {
    const uint32_t compressed = static_cast<uint32_t>(block.size());
    while (block.size() % 8) block.push_back(0);
    return {1, arch, block, compressed, static_cast<uint32_t>(text.size()), 0x2041};
}
EntrySpec Cubin(uint32_t arch) { return {2, arch, std::vector<uint8_t>(64, 0xEE), 0, 0, 0x11}; }

uint32_t U32(const std::vector<uint8_t>& v, size_t at) { uint32_t x; std::memcpy(&x, v.data() + at, 4); return x; }
uint64_t U64(const std::vector<uint8_t>& v, size_t at) { uint64_t x; std::memcpy(&x, v.data() + at, 8); return x; }
}  // namespace

static int SelfCheck(const wchar_t* path) {
    FILE* file = nullptr;
    if (_wfopen_s(&file, path, L"rb") != 0 || !file) { std::wprintf(L"cannot open %s\n", path); return 0; }
    std::vector<uint8_t> bytes;
    uint8_t chunk[1 << 16];
    for (size_t n; (n = std::fread(chunk, 1, sizeof chunk, file)) > 0;) bytes.insert(bytes.end(), chunk, chunk + n);
    std::fclose(file);
    ampere_bundle::RetargetPlan plan;
    const ampere_bundle::Retarget result = ampere_bundle::PlanRetarget(bytes.data(), bytes.size(), plan);
    std::wprintf(L"file=%s bytes=%zu plan=%s containers=%u retargeted=%u already=%u cubinsHidden=%u edits=%zu\n",
        path, bytes.size(), ampere_bundle::RetargetName(result), plan.containers, plan.retargeted,
        plan.alreadyRetargeted, plan.cubinsHidden, plan.edits.size());
    if (result == ampere_bundle::Retarget::eOk && ampere_bundle::ApplyEdits(bytes.data(), bytes.size(), plan.edits)) {
        ampere_bundle::RetargetPlan again;
        const ampere_bundle::Retarget second = ampere_bundle::PlanRetarget(bytes.data(), bytes.size(), again);
        std::wprintf(L"after apply: plan=%s already=%u edits=%zu\n", ampere_bundle::RetargetName(second),
            again.alreadyRetargeted, again.edits.size());
    }
    ampere_bundle::RevertEdits(bytes.data(), bytes.size(), plan.edits);
    size_t loweredCount = 0;
    for (size_t at = 0; at + 16 <= bytes.size(); at += 4)
    {
        if (U32(bytes, at) != 0xBA55ED50) continue;
        const uint64_t payload = U64(bytes, at + 8);
        if (payload > bytes.size() - at - 16) continue;
        std::vector<uint8_t> lowered;
        const auto converted = ampere_bundle::BuildTuringContainer(
            bytes.data() + at, static_cast<size_t>(payload) + 16, lowered);
        if (converted != ampere_bundle::Retarget::eOk)
        {
            std::wprintf(L"Turing container at 0x%zX rejected: %s\n", at, ampere_bundle::RetargetName(converted));
            return 1;
        }
        ++loweredCount;
        at += static_cast<size_t>(payload) + 12;
    }
    std::wprintf(L"Turing PTX-only containers rebuilt: %zu\n", loweredCount);
    return loweredCount ? 0 : 1;
}

int wmain(int argc, wchar_t** argv) {
    using namespace ampere_bundle;
    if (argc > 1) return SelfCheck(argv[1]);

    // LZ4 block decoder: one literal run, then a 4-byte match at offset 4, then a literal tail.
    {
        const uint8_t block[] = {0x40, 'a', 'b', 'c', 'd', 0x04, 0x00, 0x20, 'x', 'y'};  // "abcd" + match(4,@4) + "xy"
        uint8_t out[10] = {};
        Check(Lz4BlockDecompress(block, sizeof block, out, 10) && std::memcmp(out, "abcdabcdxy", 10) == 0, "lz4 match+literals");
        Check(!Lz4BlockDecompress(block, sizeof block, out, 9), "lz4 wrong output size refused");
        const uint8_t bad[] = {0x40, 'a', 'b', 'c', 'd', 0x09, 0x00, 0x20};  // offset beyond output
        Check(!Lz4BlockDecompress(bad, sizeof bad, out, 10), "lz4 bad offset refused");
        size_t literal = 0;
        Check(Lz4BlockDecompress(block, sizeof block, out, 10, 2, &literal) && literal == 3, "lz4 literal index of a literal byte");
        Check(Lz4BlockDecompress(block, sizeof block, out, 10, 5, &literal) && literal == SIZE_MAX, "lz4 match byte has no literal");
        Check(Lz4BlockDecompress(block, sizeof block, out, 10, 9, &literal) && literal == 9, "lz4 literal index in the tail");

        Check(!Lz4BlockDecompress(block, sizeof block, nullptr, 10), "walk without a wanted byte refused");
        Check(!Lz4BlockDecompress(block, sizeof block, nullptr, 10, 10, &literal), "walk wanted beyond output refused");
        Check(Lz4BlockDecompress(block, sizeof block, nullptr, 10, 2, &literal) && literal == 3, "walk literal index of a literal byte");
        Check(Lz4BlockDecompress(block, sizeof block, nullptr, 10, 5, &literal) && literal == SIZE_MAX, "walk match byte has no literal");
        Check(Lz4BlockDecompress(block, sizeof block, nullptr, 10, 9, &literal) && literal == 9, "walk literal index in the tail");
        Check(Lz4BlockDecompress(bad, sizeof bad, nullptr, 10, 2, &literal) && literal == 3, "walk stops before a malformed later sequence");
        Check(!Lz4BlockDecompress(bad, sizeof bad, nullptr, 10, 5, &literal) && literal == SIZE_MAX, "walk bad offset refused");
        const uint8_t zero[] = {0x40, 'a', 'b', 'c', 'd', 0x00, 0x00, 0x20};
        Check(!Lz4BlockDecompress(zero, sizeof zero, nullptr, 10, 5, &literal), "walk zero offset refused");
        Check(!Lz4BlockDecompress(block, 7, nullptr, 6, 5, &literal), "walk match beyond output refused");
        const uint8_t shortLiterals[] = {0x40, 'a', 'b'};
        Check(!Lz4BlockDecompress(shortLiterals, sizeof shortLiterals, nullptr, 10, 1, &literal), "walk truncated literal run refused");
        Check(!Lz4BlockDecompress(block, 5, nullptr, 3, 1, &literal), "walk literal run beyond output refused");
        const uint8_t noLength[] = {0xF0};
        Check(!Lz4BlockDecompress(noLength, sizeof noLength, nullptr, 20, 1, &literal), "walk truncated literal length refused");
        Check(!Lz4BlockDecompress(block, 6, nullptr, 10, 5, &literal), "walk truncated match offset refused");
        const uint8_t noMatchLength[] = {0x4F, 'a', 'b', 'c', 'd', 0x04, 0x00};
        Check(!Lz4BlockDecompress(noMatchLength, sizeof noMatchLength, nullptr, 40, 5, &literal), "walk truncated match length refused");
        Check(!Lz4BlockDecompress(block, 5, nullptr, 10, 6, &literal), "walk stream ends before wanted");
        for (size_t wanted = 0; wanted < sizeof out; ++wanted) {
            size_t decodedLiteral = SIZE_MAX, walkedLiteral = SIZE_MAX;
            Check(Lz4BlockDecompress(block, sizeof block, out, sizeof out, wanted, &decodedLiteral)
                && Lz4BlockDecompress(block, sizeof block, nullptr, sizeof out, wanted, &walkedLiteral)
                && decodedLiteral == walkedLiteral, "walk matches decode for every output byte");
        }
    }

    const std::string ptx89 = "//\n.version 8.5\n.target sm_89\n.address_size 64\n.visible .entry k(){ret;}\n";
    const std::string ptx120 = "//\n.version 8.7\n.target sm_120\n.address_size 64\n.visible .entry k(){ret;}\n";
    const auto single = Container({Ptx(89, ptx89, LiteralBlock(ptx89))});
    const auto mixed = Container({Ptx(120, ptx120, LiteralBlock(ptx120)), Ptx(89, ptx89, LiteralBlock(ptx89)), Cubin(89)});
    const auto unrelated = Container({Cubin(75)});
    {
        std::vector<uint8_t> lowered;
        const auto original = mixed;
        Check(BuildTuringContainer(mixed.data(), mixed.size(), lowered) == Retarget::eOk, "Turing mixed container lowers");
        Check(mixed == original, "Turing conversion leaves original identity intact");
        Check(U32(lowered, 16 + 28) == 75 && U64(lowered, 8) == lowered.size() - 16, "Turing header and size");
        Check(U32(lowered, 16 + 16) == 0 && (U64(lowered, 16 + 40) & 0x2000) == 0, "Turing uncompressed PTX");
        Check(lowered.size() == 16 + 0x50 + U64(lowered, 16 + 8), "Turing only one entry, no cubins");
        const std::string text(reinterpret_cast<const char*>(lowered.data() + 16 + 0x50));
        Check(text.find(".target sm_75") != text.npos, "Turing target directive");
        const auto rebuilt = lowered;
        Check(BuildTuringContainer(rebuilt.data(), rebuilt.size(), lowered) == Retarget::eNoContainers
            && lowered.empty(), "Turing rejects already lowered input");
        Check(BuildTuringContainer(mixed.data(), mixed.size() - 1, lowered) == Retarget::eLayout
            && lowered.empty(), "Turing truncated input clears output");
        auto duplicate = Container({Ptx(89, ptx89, LiteralBlock(ptx89)), Ptx(89, ptx89, LiteralBlock(ptx89))});
        Check(BuildTuringContainer(duplicate.data(), duplicate.size(), lowered) == Retarget::eLayout,
            "Turing rejects ambiguous source identity");
        const uint8_t elf[] = {0x7f, 'E', 'L', 'F'};
        Check(BuildTuringContainer(elf, sizeof elf, lowered) == Retarget::eLayout,
            "bare ELF cannot be substituted by name");
        std::string temporal = ptx89;
        temporal.insert(temporal.find("ret;"), "mov.f32 %f1, 0f3E800000; ");
        auto corrected = Container({Ptx(89, temporal, LiteralBlock(temporal))});
        Check(BuildTuringContainer(corrected.data(), corrected.size(), lowered) == Retarget::eOk,
            "corrected temporal PTX lowers");
        const std::string correctedText(reinterpret_cast<const char*>(lowered.data() + 16 + 0x50));
        Check(correctedText.find("0f3E800000") != correctedText.npos, "temporal correction preserved");
        std::vector<uint8_t> raw(temporal.begin(), temporal.end());
        raw.push_back(0);
        auto uncompressed = Container({EntrySpec{1, 89, raw, 0, 0, 0x41}});
        Check(BuildTuringContainer(uncompressed.data(), uncompressed.size(), lowered) == Retarget::eOk,
            "uncompressed temporal clone accepted");
    }

    // Plan over an image holding all three, apply, verify the edited bytes, and plan again (idempotent).
    {
        std::vector<uint8_t> image(64, 0);
        const size_t atSingle = image.size(); image.insert(image.end(), single.begin(), single.end()); image.insert(image.end(), 8, 0);
        const size_t atMixed = image.size(); image.insert(image.end(), mixed.begin(), mixed.end()); image.insert(image.end(), 8, 0);
        image.insert(image.end(), unrelated.begin(), unrelated.end()); image.insert(image.end(), 32, 0);

        RetargetPlan plan;
        Check(PlanRetarget(image.data(), image.size(), plan) == Retarget::eOk, "plan ok");
        Check(plan.containers == 2 && plan.retargeted == 2 && plan.alreadyRetargeted == 0 && plan.cubinsHidden == 1, "plan counts");
        // single: digit + arch byte; mixed: digit + arch byte + the payload-length bytes that change.
        Check(plan.edits.size() >= 5, "edit count");
        Check(std::is_sorted(plan.edits.begin(), plan.edits.end(), [](const ByteEdit& a, const ByteEdit& b) { return a.rva < b.rva; }), "edits sorted");
        auto before = image;
        Check(ApplyEdits(image.data(), image.size(), plan.edits), "apply");
        // single container: PTX entry header at +16, payload at +16+0x50.
        {
            std::vector<uint8_t> text(ptx89.size());
            const size_t payload = atSingle + 16 + 0x50;
            const uint32_t compressed = U32(image, atSingle + 16 + 16);
            Check(Lz4BlockDecompress(image.data() + payload, compressed, text.data(), text.size()), "single decodes after edit");
            const std::string edited(text.begin(), text.end());
            Check(edited.find(".target sm_86") != std::string::npos && edited.find("sm_89") == std::string::npos, "single retargeted text");
            Check(U32(image, atSingle + 16 + 28) == 86, "single arch field 86");
            Check(U64(image, atSingle + 8) == U64(before, atSingle + 8), "single payload length unchanged");
        }
        // mixed container: sm_120 entry first (untouched), sm_89 second, cubin dropped by the new length.
        {
            const size_t e120 = atMixed + 16;
            const size_t e89 = e120 + 0x50 + U64(image, e120 + 8);
            Check(U32(image, e120 + 28) == 120, "sm_120 entry untouched");
            Check(U32(image, e89 + 28) == 86, "mixed arch field 86");
            const uint64_t newEnd = (e89 + 0x50 + U64(image, e89 + 8)) - atMixed - 16;
            Check(U64(image, atMixed + 8) == newEnd, "mixed payload ends after the sm_86 PTX");
            Check(U64(before, atMixed + 8) > newEnd, "cubin bytes now outside the container");
        }
        RetargetPlan again;
        Check(PlanRetarget(image.data(), image.size(), again) == Retarget::eOk, "second plan ok");
        Check(again.edits.empty() && again.alreadyRetargeted == 2 && again.retargeted == 0, "second plan is a no-op");
        RevertEdits(image.data(), image.size(), plan.edits);
        Check(image == before, "revert restores the original image");
        Check(!ApplyEdits(image.data(), 8, plan.edits), "apply refuses out-of-range edits");
        auto tampered = image; tampered[plan.edits[0].rva] ^= 0xFF;
        Check(!ApplyEdits(tampered.data(), tampered.size(), plan.edits) , "apply is all-or-nothing on a changed byte");
    }

    // The digit produced by an LZ4 match (a shared literal) cannot be edited in place: refused.
    {
        const std::string text = "//sm_89\n.version 8.5\n.target sm_89\n.address_size 64\n.visible .entry k(){ret;}\n";
        const std::string head = "//sm_89\n.version 8.5\n.target ";          // then match "sm_89" from offset 2
        const std::string tail = text.substr(head.size() + 5);
        std::vector<uint8_t> block;
        Literals(block, head, false, static_cast<uint16_t>(head.size() - 2), 5);
        Literals(block, tail, true);
        std::vector<uint8_t> decoded(text.size());
        Check(Lz4BlockDecompress(block.data(), block.size(), decoded.data(), decoded.size())
              && std::string(decoded.begin(), decoded.end()) == text, "shared-literal fixture decodes");
        size_t literal = 0;
        Check(Lz4BlockDecompress(block.data(), block.size(), nullptr, text.size(), head.size() + 4, &literal)
              && literal == SIZE_MAX, "shared-literal digit comes from a match");
        std::vector<uint8_t> image(64, 0);
        const auto shared = Container({Ptx(89, text, block)});
        image.insert(image.end(), shared.begin(), shared.end()); image.insert(image.end(), 32, 0);
        RetargetPlan plan;
        Check(PlanRetarget(image.data(), image.size(), plan) == Retarget::eSharedLiteral, "shared literal refused");
    }
    // A non-cubin entry after the sm_89 PTX is an unreviewed layout; an uncompressed PTX is refused too.
    {
        std::vector<uint8_t> image(64, 0);
        const auto odd = Container({Ptx(89, ptx89, LiteralBlock(ptx89)), Ptx(120, ptx120, LiteralBlock(ptx120))});
        image.insert(image.end(), odd.begin(), odd.end()); image.insert(image.end(), 32, 0);
        RetargetPlan plan;
        Check(PlanRetarget(image.data(), image.size(), plan) == Retarget::eLayout, "ptx after sm_89 refused");
        EntrySpec raw{1, 89, std::vector<uint8_t>(ptx89.begin(), ptx89.end()), 0, 0, 0x41};
        while (raw.payload.size() % 8) raw.payload.push_back(0);
        std::vector<uint8_t> image2(64, 0);
        const auto plain = Container({raw});
        image2.insert(image2.end(), plain.begin(), plain.end()); image2.insert(image2.end(), 32, 0);
        Check(PlanRetarget(image2.data(), image2.size(), plan) == Retarget::eCompression, "uncompressed ptx refused");
        std::vector<uint8_t> none(256, 0);
        Check(PlanRetarget(none.data(), none.size(), plan) == Retarget::eNoContainers, "no containers");
    }

    // Gate-byte verification over a synthetic layout.
    {
        ProviderLayout layout{128, {0, {0xB8, 0x90, 1, 0, 0, 0xC3, 0, 0}, 6, 1, 0x70},
            {16, {0xC7, 0x44, 0x24, 0x3C, 0x90, 1, 0, 0}, 8, 4, 0x70}, {}};
        std::array<uint8_t, 128> image{};
        std::copy_n(layout.architecture.expected, 6, image.begin());
        std::copy_n(layout.discovery.expected, 8, image.begin() + 16);
        Check(VerifyImage(image.data(), image.size(), layout) == ImageCheck::eOk, "complete original layout");
        auto changed = image; changed[1] ^= 1;
        Check(VerifyImage(changed.data(), changed.size(), layout) == ImageCheck::eArchitectureBytes, "wrong architecture bytes");
        changed = image; changed[20] ^= 1;
        Check(VerifyImage(changed.data(), changed.size(), layout) == ImageCheck::eDiscoveryBytes, "wrong discovery bytes");
        auto invalid = layout; invalid.architecture.length = 9;
        Check(VerifyImage(image.data(), image.size(), invalid) == ImageCheck::eRange, "oversized expected byte array");
        invalid = layout; invalid.architecture.patchOffset = 6;
        Check(VerifyImage(image.data(), image.size(), invalid) == ImageCheck::eRange, "patch offset outside expected run");
        invalid = layout; invalid.discovery.rva = 2;
        Check(VerifyImage(image.data(), image.size(), invalid) == ImageCheck::eRange, "overlapping edits");
        invalid = layout; invalid.discovery.rva = 124;
        Check(VerifyImage(image.data(), image.size(), invalid) == ImageCheck::eRange, "site out of bounds");
        Check(VerifyImage(nullptr, 128, layout) == ImageCheck::eSize, "null image");
        // Optional Vulkan site participates once present.
        auto withVk = layout; withVk.discoveryVulkan = {32, {0xC7, 0x44, 0x24, 0x2C, 0x90, 1, 0, 0}, 8, 4, 0x70};
        std::copy_n(withVk.discoveryVulkan.expected, 8, image.begin() + 32);
        Check(VerifyImage(image.data(), image.size(), withVk) == ImageCheck::eOk, "vulkan site verified");
        changed = image; changed[36] ^= 1;
        Check(VerifyImage(changed.data(), changed.size(), withVk) == ImageCheck::eDiscoveryBytes, "wrong vulkan bytes");
    }
    std::printf(failures ? "bundle_tests: %d failure(s)\n" : "bundle_tests: all passed\n", failures);
    return failures ? 1 : 0;
}
