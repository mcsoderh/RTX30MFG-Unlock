#include "ampere_bundle.h"

#include <algorithm>
#include <array>
#include <cstring>
#include <mutex>

namespace ampere_bundle
{
namespace
{
// Every byte of the expected run must match; the patched byte may hold its patched value instead when
// `allowPatched` is set.
bool RunMatches(const uint8_t* image, size_t size, const BytePatch& p, bool allowPatched) noexcept
{
    if (p.rva > size || size - p.rva < p.length) return false;
    for (size_t i = 0; i < p.length; ++i)
    {
        const uint8_t byte = image[p.rva + i];
        if (byte == p.expected[i]) continue;
        if (allowPatched && i == p.patchOffset && byte == p.patchedValue) continue;
        return false;
    }
    return true;
}
}  // namespace

ImageCheck VerifyImage(const uint8_t* image, size_t size, const ProviderLayout& layout, bool allowPatched) noexcept
{
    if (!image || size != layout.sizeOfImage) return ImageCheck::eSize;
    std::array<std::pair<size_t, size_t>, 3> ranges{};
    const BytePatch* patches[] = {&layout.architecture, &layout.discovery, &layout.discoveryVulkan};
    size_t range = 0;
    for (size_t i = 0; i < 3; ++i) {
        const auto& patch = *patches[i];
        if (i == 2 && !patch.rva) continue;
        if (!patch.length || patch.length > sizeof patch.expected || patch.patchOffset >= patch.length
            || patch.rva > size || patch.length > size - patch.rva) return ImageCheck::eRange;
        ranges[range++] = {patch.rva, patch.length};
    }
    // Unused entries sort last and can never overlap a real one.
    for (size_t i = range; i < ranges.size(); ++i) ranges[i] = {SIZE_MAX, 0};
    std::sort(ranges.begin(), ranges.end());
    for (size_t i = 1; i < range; ++i)
        if (ranges[i].first < ranges[i - 1].first + ranges[i - 1].second) return ImageCheck::eRange;
    if (!RunMatches(image, size, layout.architecture, allowPatched)) return ImageCheck::eArchitectureBytes;
    if (!RunMatches(image, size, layout.discovery, allowPatched)) return ImageCheck::eDiscoveryBytes;
    if (layout.discoveryVulkan.rva && !RunMatches(image, size, layout.discoveryVulkan, allowPatched))
        return ImageCheck::eDiscoveryBytes;
    return ImageCheck::eOk;
}

void GateEdits(const ProviderLayout& layout, std::vector<ByteEdit>& out) noexcept
{
    out.clear();
    const BytePatch* patches[] = {&layout.architecture, &layout.discovery, &layout.discoveryVulkan};
    for (const BytePatch* p : patches)
        if (p->rva) out.push_back({p->rva + p->patchOffset, p->expected[p->patchOffset], p->patchedValue});
    std::sort(out.begin(), out.end(), [](const ByteEdit& a, const ByteEdit& b) { return a.rva < b.rva; });
}

bool ApplyEdits(uint8_t* image, size_t size, const std::vector<ByteEdit>& edits) noexcept
{
    if (!image) return false;
    for (const ByteEdit& e : edits)
        if (e.rva >= size || image[e.rva] != e.before) return false;
    for (const ByteEdit& e : edits) image[e.rva] = e.after;
    return true;
}

void RevertEdits(uint8_t* image, size_t size, const std::vector<ByteEdit>& edits) noexcept
{
    if (!image) return;
    for (const ByteEdit& e : edits)
        if (e.rva < size && image[e.rva] == e.after) image[e.rva] = e.before;
}

namespace
{
constexpr uint32_t kArchAmpere = 0x170u;

uint16_t Read16(const uint8_t* p) noexcept { uint16_t v; std::memcpy(&v, p, sizeof v); return v; }
uint32_t Read32(const uint8_t* p) noexcept { uint32_t v; std::memcpy(&v, p, sizeof v); return v; }
uint64_t Read64(const uint8_t* p) noexcept { uint64_t v; std::memcpy(&v, p, sizeof v); return v; }

struct PeView
{
    const uint8_t* image = nullptr;
    size_t size = 0;
    const IMAGE_NT_HEADERS64* nt = nullptr;

    bool Parse(const uint8_t* base, size_t bytes) noexcept
    {
        if (!base || bytes < sizeof(IMAGE_DOS_HEADER)) return false;
        const auto* dos = reinterpret_cast<const IMAGE_DOS_HEADER*>(base);
        if (dos->e_magic != IMAGE_DOS_SIGNATURE || dos->e_lfanew <= 0
            || static_cast<size_t>(dos->e_lfanew) + sizeof(IMAGE_NT_HEADERS64) > bytes) return false;
        const auto* headers = reinterpret_cast<const IMAGE_NT_HEADERS64*>(base + dos->e_lfanew);
        if (headers->Signature != IMAGE_NT_SIGNATURE
            || headers->OptionalHeader.Magic != IMAGE_NT_OPTIONAL_HDR64_MAGIC) return false;
        image = base; size = bytes; nt = headers;
        const auto* sections = IMAGE_FIRST_SECTION(headers);
        const auto* end = reinterpret_cast<const uint8_t*>(sections + headers->FileHeader.NumberOfSections);
        return end > base && static_cast<size_t>(end - base) <= bytes;
    }

    // Mapped-image addressing: an RVA is the offset from the image base.
    bool Contains(uint32_t rva, size_t bytes) const noexcept
    {
        return rva < size && bytes <= size - rva;
    }
    const uint8_t* At(uint32_t rva, size_t bytes) const noexcept
    {
        return Contains(rva, bytes) ? image + rva : nullptr;
    }
    uint32_t ExportRva(const char* name) const noexcept
    {
        const auto& dir = nt->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_EXPORT];
        if (!dir.VirtualAddress || !Contains(dir.VirtualAddress, sizeof(IMAGE_EXPORT_DIRECTORY))) return 0;
        const auto* e = reinterpret_cast<const IMAGE_EXPORT_DIRECTORY*>(image + dir.VirtualAddress);
        if (!Contains(e->AddressOfNames, 4ull * e->NumberOfNames)
            || !Contains(e->AddressOfNameOrdinals, 2ull * e->NumberOfNames)
            || !Contains(e->AddressOfFunctions, 4ull * e->NumberOfFunctions)) return 0;
        const auto* names = reinterpret_cast<const uint32_t*>(image + e->AddressOfNames);
        const auto* ordinals = reinterpret_cast<const uint16_t*>(image + e->AddressOfNameOrdinals);
        const auto* functions = reinterpret_cast<const uint32_t*>(image + e->AddressOfFunctions);
        const size_t wanted = std::strlen(name);
        for (uint32_t i = 0; i < e->NumberOfNames; ++i)
        {
            const uint8_t* candidate = At(names[i], wanted + 1);
            if (!candidate || std::memcmp(candidate, name, wanted + 1) != 0) continue;
            const uint16_t ordinal = ordinals[i];
            return ordinal < e->NumberOfFunctions ? functions[ordinal] : 0;
        }
        return 0;
    }
};

// The GetFeatureRequirements exports store the architecture constant into their stack record with
// `mov dword ptr [rsp+X], imm32`. Returns the offset of that unique store inside the export body.
bool FindRequirementsStore(const PeView& pe, uint32_t exportRva, uint32_t arch, uint32_t& site) noexcept
{
    constexpr uint32_t kWindow = 0x600;   // the export is a short wrapper around the internal checker
    const uint8_t* window = pe.At(exportRva, kWindow);
    if (!window) return false;
    bool unique = false;
    for (uint32_t at = 0; at + 8 <= kWindow; ++at)
    {
        if (window[at] != 0xC7 || window[at + 1] != 0x44 || window[at + 2] != 0x24) continue;
        if (Read32(window + at + 4) != arch) continue;
        if (unique) return false;
        site = at;
        unique = true;
    }
    return unique;
}
}  // namespace

const wchar_t* DiscoveryName(Discovery value) noexcept
{
    switch (value)
    {
    case Discovery::eOk: return L"ok";
    case Discovery::eNotPe: return L"not-a-pe-image";
    case Discovery::eArchExport: return L"architecture-export-missing";
    case Discovery::eArchBytes: return L"architecture-export-not-a-constant";
    case Discovery::eArchValue: return L"architecture-already-ampere-or-unexpected";
    case Discovery::eRequirementsExport: return L"requirements-export-missing";
    case Discovery::eRequirementsSite: return L"requirements-record-not-unique";
    }
    return L"unknown";
}

Discovery DiscoverLayout(const uint8_t* image, size_t size, ProviderLayout& out) noexcept
{
    PeView pe;
    if (!pe.Parse(image, size)) return Discovery::eNotPe;
    out = ProviderLayout{};
    out.sizeOfImage = pe.nt->OptionalHeader.SizeOfImage;
    if (out.sizeOfImage != size) return Discovery::eNotPe;

    // Site 1: NVSDK_NGX_GetGPUArchitecture is `mov eax, <arch>; ret` and nothing else.
    const uint32_t archRva = pe.ExportRva("NVSDK_NGX_GetGPUArchitecture");
    if (!archRva) return Discovery::eArchExport;
    const uint8_t* body = pe.At(archRva, 6);
    if (!body) return Discovery::eArchExport;
    if (body[0] != 0xB8 || body[5] != 0xC3) return Discovery::eArchBytes;
    const uint32_t arch = Read32(body + 1);
    // Only a 0x1xx minimum above Ampere is patchable by lowering the low byte to 0x70.
    if (arch <= kArchAmpere || (arch & ~0xFFu) != (kArchAmpere & ~0xFFu)) return Discovery::eArchValue;
    out.architecture.rva = archRva;
    std::memcpy(out.architecture.expected, body, 6);
    out.architecture.length = 6;
    out.architecture.patchOffset = 1;
    out.architecture.patchedValue = static_cast<uint8_t>(kArchAmpere & 0xFF);

    // Site 2: the same immediate stored into the GetFeatureRequirements stack record.
    const uint32_t reqRva = pe.ExportRva("NVSDK_NGX_D3D12_GetFeatureRequirements");
    if (!reqRva) return Discovery::eRequirementsExport;
    uint32_t site = 0;
    if (!FindRequirementsStore(pe, reqRva, arch, site)) return Discovery::eRequirementsSite;
    out.discovery.rva = reqRva + site;
    std::memcpy(out.discovery.expected, image + reqRva + site, 8);
    out.discovery.length = 8;
    out.discovery.patchOffset = 4;
    out.discovery.patchedValue = static_cast<uint8_t>(kArchAmpere & 0xFF);

    // Site 2b: the Vulkan discovery export stores the same constant. Optional: an absent export or an
    // ambiguous body leaves it unpatched, which only affects Vulkan titles.
    if (const uint32_t vkRva = pe.ExportRva("NVSDK_NGX_VULKAN_GetFeatureRequirements"))
    {
        uint32_t vkSite = 0;
        if (FindRequirementsStore(pe, vkRva, arch, vkSite))
        {
            out.discoveryVulkan.rva = vkRva + vkSite;
            std::memcpy(out.discoveryVulkan.expected, image + vkRva + vkSite, 8);
            out.discoveryVulkan.length = 8;
            out.discoveryVulkan.patchOffset = 4;
            out.discoveryVulkan.patchedValue = static_cast<uint8_t>(kArchAmpere & 0xFF);
        }
    }
    return Discovery::eOk;
}

bool Lz4BlockDecompress(const uint8_t* src, size_t srcSize, uint8_t* dst, size_t dstSize,
    size_t wanted, size_t* literal) noexcept
{
    if (literal) *literal = SIZE_MAX;
    if (!src || (!dst && wanted >= dstSize)) return false;
    size_t i = 0, o = 0;
    while (i < srcSize)
    {
        const uint8_t token = src[i++];
        size_t run = token >> 4;
        if (run == 15)
        {
            uint8_t b;
            do { if (i >= srcSize) return false; b = src[i++]; run += b; } while (b == 255);
        }
        if (run > srcSize - i || run > dstSize - o) return false;
        if (literal && wanted >= o && wanted - o < run) *literal = i + (wanted - o);
        if (dst) std::memcpy(dst + o, src + i, run);
        i += run; o += run;
        if (!dst && o > wanted) return true;
        if (i >= srcSize) break;                       // last sequence carries literals only
        if (srcSize - i < 2) return false;
        const size_t offset = src[i] | (static_cast<size_t>(src[i + 1]) << 8);
        i += 2;
        size_t match = token & 0xF;
        if (match == 15)
        {
            uint8_t b;
            do { if (i >= srcSize) return false; b = src[i++]; match += b; } while (b == 255);
        }
        match += 4;
        if (offset == 0 || offset > o || match > dstSize - o) return false;
        if (dst) for (size_t k = 0; k < match; ++k) dst[o + k] = dst[o - offset + k];   // overlapping copy by design
        o += match;
        if (!dst && o > wanted) return true;
    }
    return dst && o == dstSize;
}

namespace
{
constexpr uint32_t kFatbinMagic = 0xBA55ED50u;
constexpr uint16_t kKindPtx = 1, kKindCubin = 2;
constexpr uint64_t kFlagCompressed = 0x2000u;
constexpr uint32_t kArchSource = 89, kArchTarget = 86;
constexpr size_t kMaxContainerBytes = 64u << 20, kMaxPtxBytes = 16u << 20;
constexpr size_t kMaxEntries = 32, kMaxContainers = 512;

struct Entry
{
    size_t offset;         // from the container start
    size_t headerBytes;
    size_t payloadBytes;
    uint16_t kind;
    uint32_t arch;
    uint32_t compressedBytes;
    uint64_t flags;
    uint64_t unpackedBytes;
    size_t PayloadOffset() const noexcept { return offset + headerBytes; }
    size_t End() const noexcept { return PayloadOffset() + payloadBytes; }
};

// One container at `c` bounded by `avail`: fills its entry list and total size, or returns false when
// it is not a well-formed fatbin.
bool ParseContainer(const uint8_t* c, size_t avail, std::vector<Entry>& entries, size_t& total) noexcept
{
    entries.clear();
    if (avail < 16 || Read32(c) != kFatbinMagic || Read16(c + 4) != 1 || Read16(c + 6) != 16) return false;
    const uint64_t payload = Read64(c + 8);
    if (payload == 0 || payload > avail - 16 || payload > kMaxContainerBytes - 16) return false;
    total = 16 + static_cast<size_t>(payload);
    size_t off = 16;
    while (off < total)
    {
        if (total - off < 64 || entries.size() == kMaxEntries) return false;
        const uint8_t* e = c + off;
        const uint16_t kind = Read16(e);
        const uint32_t headerBytes = Read32(e + 4);
        const uint64_t payloadBytes = Read64(e + 8);
        if ((kind != kKindPtx && kind != kKindCubin) || Read16(e + 2) != 0x0101
            || headerBytes < 64 || headerBytes > 4096 || headerBytes > total - off
            || payloadBytes > total - off - headerBytes) return false;
        entries.push_back({off, headerBytes, static_cast<size_t>(payloadBytes), kind, Read32(e + 28),
            Read32(e + 16), Read64(e + 40), Read64(e + 56)});
        off = entries.back().End();
    }
    return off == total && !entries.empty();
}

void AddEdit(std::vector<ByteEdit>& edits, size_t rva, uint8_t before, uint8_t after) noexcept
{
    if (before != after) edits.push_back({static_cast<uint32_t>(rva), before, after});
}
}  // namespace

const wchar_t* RetargetName(Retarget value) noexcept
{
    switch (value)
    {
    case Retarget::eOk: return L"ok";
    case Retarget::eNoContainers: return L"no-sm89-ptx-containers";
    case Retarget::eLayout: return L"unreviewed-container-layout";
    case Retarget::eCompression: return L"ptx-not-lz4-compressed";
    case Retarget::eLz4: return L"lz4-block-invalid";
    case Retarget::eTarget: return L"target-directive-not-unique";
    case Retarget::eSharedLiteral: return L"target-digit-not-an-independent-literal";
    case Retarget::eBudget: return L"container-budget-exceeded";
    }
    return L"unknown";
}

Retarget PlanRetarget(const uint8_t* image, size_t size, RetargetPlan& out) noexcept
{
    out = RetargetPlan{};
    if (!image || size < 32) return Retarget::eNoContainers;
    static constexpr char kDirective[] = ".target sm_89";
    constexpr size_t kDirectiveBytes = sizeof(kDirective) - 1;
    std::vector<Entry> entries;
    std::vector<uint8_t> text, check, edited;
    for (size_t rva = 0; rva + 16 <= size; rva += 4)
    {
        if (Read32(image + rva) != kFatbinMagic) continue;
        size_t total = 0;
        if (!ParseContainer(image + rva, size - rva, entries, total)) continue;
        const uint8_t* c = image + rva;
        const auto ptx = std::find_if(entries.begin(), entries.end(), [](const Entry& e) {
            return e.kind == kKindPtx && (e.arch == kArchSource || e.arch == kArchTarget);
        });
        if (ptx == entries.end()) { rva += total - 4; continue; }
        if (++out.containers > kMaxContainers) return Retarget::eBudget;
        if (ptx->arch == kArchTarget) { ++out.alreadyRetargeted; rva += total - 4; continue; }

        // Every reviewed build compresses its PTX; the literal proof below needs that form.
        if (!(ptx->flags & kFlagCompressed) || !ptx->compressedBytes || ptx->compressedBytes > ptx->payloadBytes
            || !ptx->unpackedBytes || ptx->unpackedBytes > kMaxPtxBytes) return Retarget::eCompression;
        // Whatever follows the sm_89 PTX must be cubins, which the shortened payload length hides. An
        // sm_120 PTX ahead of it is left alone: an sm_86 device cannot select it.
        for (auto after = ptx + 1; after != entries.end(); ++after)
            if (after->kind != kKindCubin) return Retarget::eLayout;

        const uint8_t* compressed = c + ptx->PayloadOffset();
        text.resize(static_cast<size_t>(ptx->unpackedBytes));
        if (!Lz4BlockDecompress(compressed, ptx->compressedBytes, text.data(), text.size())) return Retarget::eLz4;
        // Exactly one `.target sm_89` directive, at the start of a line.
        auto hit = std::search(text.begin(), text.end(), kDirective, kDirective + kDirectiveBytes);
        if (hit == text.end()) return Retarget::eTarget;
        if (hit != text.begin() && *(hit - 1) != '\n') return Retarget::eTarget;
        if (std::search(hit + kDirectiveBytes, text.end(), kDirective, kDirective + kDirectiveBytes) != text.end())
            return Retarget::eTarget;
        const size_t digit = static_cast<size_t>(hit - text.begin()) + kDirectiveBytes - 1;

        // The digit must come out of its own literal, and editing that literal must change no other
        // output byte: decode the edited block and compare with the intended text.
        size_t literal = SIZE_MAX;
        if (!Lz4BlockDecompress(compressed, ptx->compressedBytes, nullptr, text.size(), digit, &literal)
            || literal == SIZE_MAX || literal >= ptx->compressedBytes || compressed[literal] != '9')
            return Retarget::eSharedLiteral;
        edited.assign(compressed, compressed + ptx->compressedBytes);
        edited[literal] = '6';
        check.resize(text.size());
        if (!Lz4BlockDecompress(edited.data(), edited.size(), check.data(), check.size())) return Retarget::eSharedLiteral;
        text[digit] = '6';
        if (check != text) return Retarget::eSharedLiteral;

        AddEdit(out.edits, rva + ptx->PayloadOffset() + literal, '9', '6');
        AddEdit(out.edits, rva + ptx->offset + 28, static_cast<uint8_t>(kArchSource), static_cast<uint8_t>(kArchTarget));
        if (ptx + 1 != entries.end())
        {
            const uint64_t before = Read64(c + 8);
            const uint64_t after = static_cast<uint64_t>(ptx->End() - 16);
            for (size_t i = 0; i < 8; ++i)
                AddEdit(out.edits, rva + 8 + i, static_cast<uint8_t>(before >> (8 * i)), static_cast<uint8_t>(after >> (8 * i)));
            ++out.cubinsHidden;
        }
        ++out.retargeted;
        rva += total - 4;
    }
    if (!out.containers) return Retarget::eNoContainers;
    std::sort(out.edits.begin(), out.edits.end(), [](const ByteEdit& a, const ByteEdit& b) { return a.rva < b.rva; });
    for (size_t i = 1; i < out.edits.size(); ++i)
        if (out.edits[i].rva == out.edits[i - 1].rva) return Retarget::eLayout;
    return Retarget::eOk;
}

namespace
{
std::mutex gStateMutex;
Status gStatus;
uint8_t* gProviderImage = nullptr;      // the mapping the edits below were made in
size_t gImageSize = 0;
std::vector<ByteEdit> gGateEdits;       // GateEdits(gStatus.layout), applied to gProviderImage
std::vector<ByteEdit> gKernelPlan;      // the proven kernel plan for gProviderImage
uint32_t gPlanRetargeted = 0, gPlanCubinsHidden = 0;   // what that plan changes, reported once applied
bool gGatesPublished = false;

// Applies a sorted edit list to a mapped image, one protection change per touched page, verifying every
// byte before and after; a byte already holding its target value is accepted. Returns how many edits
// are in their target state when it stops, so a partial run can be reverted with `forward` inverted.
size_t WriteEdits(uint8_t* image, const std::vector<ByteEdit>& edits, bool forward) noexcept
{
    constexpr uintptr_t kPage = 4096;
    size_t done = 0;
    while (done < edits.size())
    {
        const uintptr_t page = (reinterpret_cast<uintptr_t>(image) + edits[done].rva) & ~(kPage - 1);
        size_t end = done;
        while (end < edits.size()
            && ((reinterpret_cast<uintptr_t>(image) + edits[end].rva) & ~(kPage - 1)) == page) ++end;
        // Verify the whole page's worth first so nothing is written on a page that will fail.
        for (size_t i = done; i < end; ++i)
        {
            const uint8_t byte = image[edits[i].rva];
            if (byte != (forward ? edits[i].before : edits[i].after) && byte != (forward ? edits[i].after : edits[i].before))
                return done;
        }
        DWORD previous = 0;
        if (!VirtualProtect(reinterpret_cast<void*>(page), kPage, PAGE_EXECUTE_READWRITE, &previous)) return done;
        for (size_t i = done; i < end; ++i)
        {
            uint8_t& byte = image[edits[i].rva];
            const uint8_t value = forward ? edits[i].after : edits[i].before;
            byte = value;
            if (byte != value) break;
            ++done;
        }
        DWORD ignored = 0;
        VirtualProtect(reinterpret_cast<void*>(page), kPage, previous, &ignored);
        FlushInstructionCache(GetCurrentProcess(), reinterpret_cast<void*>(page), kPage);
        if (done != end) return done;
    }
    return done;
}

// All-or-nothing over the whole list: a stop part-way is undone before returning false.
bool WriteAll(uint8_t* image, const std::vector<ByteEdit>& edits, bool forward) noexcept
{
    const size_t done = WriteEdits(image, edits, forward);
    if (done == edits.size()) return true;
    std::vector<ByteEdit> partial(edits.begin(), edits.begin() + done);
    WriteEdits(image, partial, !forward);
    return false;
}

bool ImageBounds(HMODULE provider, uint8_t*& image, size_t& size) noexcept
{
    image = reinterpret_cast<uint8_t*>(provider);
    MEMORY_BASIC_INFORMATION info{};
    if (VirtualQuery(image, &info, sizeof info) != sizeof info || info.State != MEM_COMMIT) return false;
    const auto* dos = reinterpret_cast<const IMAGE_DOS_HEADER*>(image);
    if (dos->e_magic != IMAGE_DOS_SIGNATURE) return false;
    const auto* nt = reinterpret_cast<const IMAGE_NT_HEADERS64*>(image + dos->e_lfanew);
    if (nt->Signature != IMAGE_NT_SIGNATURE) return false;
    size = nt->OptionalHeader.SizeOfImage;
    return size != 0;
}

uint64_t Microseconds(LARGE_INTEGER start) noexcept
{
    LARGE_INTEGER now{}, frequency{};
    QueryPerformanceCounter(&now);
    QueryPerformanceFrequency(&frequency);
    return frequency.QuadPart ? static_cast<uint64_t>((now.QuadPart - start.QuadPart) * 1000000 / frequency.QuadPart) : 0;
}

// Adopt `image` as the published mapping with the plan proven for it.
void TrackImage(uint8_t* image, size_t size, RetargetPlan&& plan) noexcept
{
    gProviderImage = image;
    gImageSize = size;
    gKernelPlan = std::move(plan.edits);
    gPlanRetargeted = plan.retargeted;
    gPlanCubinsHidden = plan.cubinsHidden;
    gStatus.containers = plan.containers;
    gStatus.retargeted = 0;
    gStatus.cubinsHidden = 0;
    gStatus.kernelsRetargeted = gKernelPlan.empty();   // nothing left to do when every kernel is sm_86 already
    gStatus.retarget = Retarget::eOk;
}
}  // namespace

void Prepare() noexcept
{
    std::lock_guard<std::mutex> guard(gStateMutex);
    if (gStatus.state == State::ePrepared || gStatus.state == State::ePublished) return;
    gStatus = Status{};
    gStatus.state = State::ePrepared;
}

bool Publish(HMODULE provider) noexcept
{
    std::lock_guard<std::mutex> guard(gStateMutex);
    auto fail = [&](const wchar_t* reason) noexcept {
        gStatus.state = State::eFailed;
        gStatus.failure = reason;
        return false;
    };
    // A module that is not a patchable DLSS-G provider is declined without consuming the attempt: the
    // loader may map several (the game's own copy, the driver-store fallback, an NGX OTA build) and
    // the next one must still be eligible. Only a failure after the first byte is written is terminal.
    auto decline = [&](std::wstring reason) noexcept {
        gStatus.failure = std::move(reason);
        gStatus.state = State::ePrepared;
        return false;
    };
    if (gStatus.state != State::ePrepared) return fail(L"Publish without preparation");
    if (!provider) return fail(L"No provider module");

    uint8_t* image = nullptr;
    size_t imageSize = 0;
    if (!ImageBounds(provider, image, imageSize)) return decline(L"Provider is not a PE image");

    ProviderLayout discovered{};
    gStatus.discovery = DiscoverLayout(image, imageSize, discovered);
    if (gStatus.discovery != Discovery::eOk)
        return decline(std::wstring(L"Patch sites not found: ") + DiscoveryName(gStatus.discovery));
    gStatus.layout = discovered;
    gStatus.imageCheck = VerifyImage(image, imageSize, discovered);
    if (gStatus.imageCheck != ImageCheck::eOk) return decline(L"Provider image does not match the discovered layout");
    RetargetPlan plan;
    gStatus.retarget = PlanRetarget(image, imageSize, plan);
    if (gStatus.retarget != Retarget::eOk)
        return decline(std::wstring(L"Kernels not retargetable: ") + RetargetName(gStatus.retarget));

    GateEdits(discovered, gGateEdits);
    if (!WriteAll(image, gGateEdits, true)) return fail(L"Architecture byte publication failed");
    gGatesPublished = true;
    TrackImage(image, imageSize, std::move(plan));
    gStatus.state = State::ePublished;
    return true;
}

bool RetargetKernels(HMODULE provider) noexcept
{
    std::lock_guard<std::mutex> guard(gStateMutex);
    if (gStatus.state != State::ePublished || !provider) return false;
    if (reinterpret_cast<uint8_t*>(provider) != gProviderImage)
    {
        // Only Inspect may adopt a different mapping, and only after verifying it.
        gStatus.failure = L"Kernel retarget refused: image is not the published provider";
        return false;
    }
    if (gStatus.kernelsRetargeted) return true;
    LARGE_INTEGER start{};
    QueryPerformanceCounter(&start);
    if (!WriteAll(gProviderImage, gKernelPlan, true))
    {
        // The image no longer holds the bytes the plan was proven against: prove it again, once.
        RetargetPlan plan;
        gStatus.retarget = PlanRetarget(gProviderImage, gImageSize, plan);
        if (gStatus.retarget != Retarget::eOk)
        {
            gStatus.failure = std::wstring(L"Kernels not retargetable: ") + RetargetName(gStatus.retarget);
            gStatus.retargetMicroseconds = Microseconds(start);
            return false;
        }
        gKernelPlan = std::move(plan.edits);
        gPlanRetargeted = plan.retargeted;
        gPlanCubinsHidden = plan.cubinsHidden;
        gStatus.containers = plan.containers;
        if (!gKernelPlan.empty() && !WriteAll(gProviderImage, gKernelPlan, true))
        {
            gStatus.failure = L"Kernel retarget write failed";
            gStatus.retargetMicroseconds = Microseconds(start);
            return false;
        }
    }
    gStatus.retargeted = gPlanRetargeted;
    gStatus.cubinsHidden = gPlanCubinsHidden;
    gStatus.kernelsRetargeted = true;
    gStatus.retargetMicroseconds = Microseconds(start);
    return true;
}

void Rollback() noexcept
{
    std::lock_guard<std::mutex> guard(gStateMutex);
    if (gProviderImage)
    {
        if (gStatus.kernelsRetargeted) WriteEdits(gProviderImage, gKernelPlan, false);
        if (gGatesPublished) WriteEdits(gProviderImage, gGateEdits, false);
    }
    gStatus.kernelsRetargeted = false;
    gGatesPublished = false;
    gKernelPlan.clear();
    gProviderImage = nullptr;
    gImageSize = 0;
    gStatus.state = State::eRolledBack;
}

bool Inspect(HMODULE provider, Live& out) noexcept
{
    out = Live{};
    if (!provider) return false;
    std::lock_guard<std::mutex> guard(gStateMutex);
    const ProviderLayout& layout = gStatus.layout;
    uint8_t* image = nullptr;
    size_t imageSize = 0;
    out.providerBase = reinterpret_cast<uintptr_t>(provider);
    out.publishedBase = reinterpret_cast<uintptr_t>(gProviderImage);
    if (!ImageBounds(provider, image, imageSize) || imageSize != layout.sizeOfImage) return false;
    auto readBytes = [&]() noexcept {
        out.archByte = image[layout.architecture.rva + layout.architecture.patchOffset];
        out.discoveryByte = image[layout.discovery.rva + layout.discovery.patchOffset];
        if (layout.discoveryVulkan.rva)
            out.discoveryVulkanByte = image[layout.discoveryVulkan.rva + layout.discoveryVulkan.patchOffset];
    };
    if (image == gProviderImage) { readBytes(); return true; }
    if (gStatus.state != State::ePublished) return false;

    // A different mapping. It becomes the published image only if every gate site carries the exact
    // instruction bytes the layout was discovered from (each patch byte original or already patched)
    // and its kernels prove retargetable; nothing is written before both hold, and a failure leaves
    // the current published image in place so the next call can try again.
    if (VerifyImage(image, imageSize, layout, true) != ImageCheck::eOk) return false;
    RetargetPlan plan;
    if (PlanRetarget(image, imageSize, plan) != Retarget::eOk) return false;
    if (!WriteAll(image, gGateEdits, true)) return false;
    TrackImage(image, imageSize, std::move(plan));
    out.publishedBase = reinterpret_cast<uintptr_t>(gProviderImage);
    out.healed = true;
    readBytes();
    return true;
}

Status CurrentStatus() noexcept
{
    std::lock_guard<std::mutex> guard(gStateMutex);
    return gStatus;
}
}  // namespace ampere_bundle
