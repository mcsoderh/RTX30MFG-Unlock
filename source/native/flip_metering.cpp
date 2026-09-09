#include "flip_metering.h"

#include <algorithm>
#include <cstring>
#include <mutex>

namespace flip_metering
{
namespace
{
constexpr char kMarker[] = "FG1 DLL has been detected";
constexpr size_t kMarkerBytes = sizeof(kMarker) - 1;
constexpr uint32_t kMinField = 0x100, kMaxField = 0x20000;
constexpr size_t kFallbackWindow = 0x200;   // the fallback's store follows the log call closely

uint32_t Read32(const uint8_t* p) noexcept { uint32_t v; std::memcpy(&v, p, sizeof v); return v; }
int32_t ReadS32(const uint8_t* p) noexcept { int32_t v; std::memcpy(&v, p, sizeof v); return v; }

// `mov byte ptr [reg+disp32], ...` needs mod=10 and no SIB byte, or the displacement is not at +2.
bool Disp32ModRm(uint8_t modrm) noexcept { return modrm >= 0x80 && modrm <= 0xBF && (modrm & 7) != 4; }

bool SectionInImage(const Section& s, size_t size) noexcept
{
    return s.size && s.rva < size && s.size <= size - s.rva;
}
}  // namespace

const wchar_t* OutcomeName(Outcome value) noexcept
{
    switch (value)
    {
    case Outcome::eNotDlssgPlugin: return L"not-the-dlssg-plugin";
    case Outcome::eNoFallbackStore: return L"fallback-store-not-found";
    case Outcome::eNothingToPin: return L"nothing-to-pin";
    case Outcome::ePlanned: return L"planned";
    }
    return L"unknown";
}

Outcome PlanSoftwarePacing(const uint8_t* image, size_t size, const Section* sections, size_t count,
    Plan& out) noexcept
{
    out = Plan{};
    if (!image || !sections || !count) return out.outcome;

    // 1. The marker string identifies the plugin whatever the OTA layer named the file.
    for (size_t i = 0; i < count && !out.markerRva; ++i)
    {
        const Section& s = sections[i];
        if (!s.readable || !SectionInImage(s, size) || s.size < kMarkerBytes) continue;
        const uint8_t* begin = image + s.rva;
        const uint8_t* hit = std::search(begin, begin + s.size, kMarker, kMarker + kMarkerBytes);
        if (hit != begin + s.size) out.markerRva = s.rva + static_cast<uint32_t>(hit - begin);
    }
    if (!out.markerRva) return out.outcome = Outcome::eNotDlssgPlugin;

    // 2. The code that logs the marker (lea reg, [rip+disp32]) is the fallback path; within a short
    //    window it stores the pacing state with `mov byte ptr [reg+disp32], imm8`. That store gives
    //    both the field offset and the value that means "software pacing".
    bool derived = false;
    for (size_t i = 0; i < count && !derived; ++i)
    {
        const Section& s = sections[i];
        if (!s.executable || !SectionInImage(s, size) || s.size < 8) continue;
        const uint8_t* code = image + s.rva;
        for (size_t off = 0; off + 8 <= s.size && !derived; ++off)
        {
            if ((code[off] != 0x48 && code[off] != 0x4C) || code[off + 1] != 0x8D
                || (code[off + 2] & 0xC7) != 0x05) continue;
            const int64_t target = static_cast<int64_t>(s.rva) + static_cast<int64_t>(off) + 7 + ReadS32(code + off + 3);
            if (target != out.markerRva) continue;
            const size_t limit = std::min(off + kFallbackWindow, static_cast<size_t>(s.size));
            for (size_t w = off; w + 7 <= limit; ++w)
            {
                if (code[w] != 0xC6 || !Disp32ModRm(code[w + 1])) continue;
                const uint32_t field = Read32(code + w + 2);
                const uint8_t imm = code[w + 6];
                if (field <= kMinField || field >= kMaxField || imm > 1) continue;
                out.field = field;
                out.value = imm;
                derived = true;
                break;
            }
        }
    }
    if (!derived) return out.outcome = Outcome::eNoFallbackStore;

    // 3. Pin every other store of that field. Two encodings occur: the immediate form, whose imm8 is
    //    flipped in place, and (from 2.13) a register store `40 88 /r disp32` whose REX prefix exists
    //    only to name a byte register, making it exactly seven bytes: the same length as the
    //    immediate form with the same base register, so it can be rewritten in place. Any other
    //    encoding has a different length and is deliberately left alone.
    const uint8_t opposite = static_cast<uint8_t>(1 - out.value);
    for (size_t i = 0; i < count; ++i)
    {
        const Section& s = sections[i];
        if (!s.executable || !SectionInImage(s, size) || s.size < 7) continue;
        const uint8_t* code = image + s.rva;
        for (size_t off = 0; off + 7 <= s.size; ++off)
        {
            if (code[off] == 0xC6 && Disp32ModRm(code[off + 1]) && Read32(code + off + 2) == out.field)
            {
                if (code[off + 6] == out.value) { ++out.alreadyPinned; continue; }
                if (code[off + 6] != opposite) continue;
                Site site{s.rva + static_cast<uint32_t>(off) + 6, 1, {}, {}};
                site.before[0] = opposite;
                site.after[0] = static_cast<uint8_t>(out.value);
                out.sites.push_back(site);
                continue;
            }
            if (code[off] == 0x40 && code[off + 1] == 0x88 && Disp32ModRm(code[off + 2])
                && Read32(code + off + 3) == out.field)
            {
                Site site{s.rva + static_cast<uint32_t>(off), 7, {}, {}};
                std::memcpy(site.before, code + off, 7);
                site.after[0] = 0xC6;
                site.after[1] = static_cast<uint8_t>(0x80 | (code[off + 2] & 7));
                std::memcpy(site.after + 2, &out.field, sizeof out.field);
                site.after[6] = static_cast<uint8_t>(out.value);
                out.sites.push_back(site);
            }
        }
    }
    return out.outcome = out.sites.empty() ? Outcome::eNothingToPin : Outcome::ePlanned;
}

bool ApplyPlan(uint8_t* image, size_t size, const Plan& plan) noexcept
{
    if (!image) return false;
    for (const Site& s : plan.sites)
        if (s.rva >= size || s.length > size - s.rva || std::memcmp(image + s.rva, s.before, s.length) != 0) return false;
    for (const Site& s : plan.sites) std::memcpy(image + s.rva, s.after, s.length);
    return true;
}

void RevertPlan(uint8_t* image, size_t size, const Plan& plan) noexcept
{
    if (!image) return;
    for (const Site& s : plan.sites)
        if (s.rva < size && s.length <= size - s.rva && std::memcmp(image + s.rva, s.after, s.length) == 0)
            std::memcpy(image + s.rva, s.before, s.length);
}

namespace
{
std::mutex gMutex;
struct Pinned { uint8_t* image; Plan plan; };
std::vector<Pinned> gPinned;

const IMAGE_NT_HEADERS64* ReadHeaders(uint8_t* image, size_t& size) noexcept
{
    const auto* dos = reinterpret_cast<const IMAGE_DOS_HEADER*>(image);
    if (dos->e_magic != IMAGE_DOS_SIGNATURE) return nullptr;
    const auto* nt = reinterpret_cast<const IMAGE_NT_HEADERS64*>(image + dos->e_lfanew);
    if (nt->Signature != IMAGE_NT_SIGNATURE || nt->OptionalHeader.Magic != IMAGE_NT_OPTIONAL_HDR64_MAGIC) return nullptr;
    size = nt->OptionalHeader.SizeOfImage;
    const IMAGE_SECTION_HEADER* header = IMAGE_FIRST_SECTION(nt);
    bool validSection = false;
    for (unsigned i = 0; i < nt->FileHeader.NumberOfSections; ++i, ++header)
        if (SectionInImage({header->VirtualAddress, header->Misc.VirtualSize, false, false}, size)) validSection = true;
    return size != 0 && validSection ? nt : nullptr;
}

void ReadSections(const IMAGE_NT_HEADERS64* nt, size_t size, std::vector<Section>& sections) noexcept
{
    const IMAGE_SECTION_HEADER* header = IMAGE_FIRST_SECTION(nt);
    for (unsigned i = 0; i < nt->FileHeader.NumberOfSections; ++i, ++header)
    {
        Section s{header->VirtualAddress, header->Misc.VirtualSize,
            (header->Characteristics & IMAGE_SCN_MEM_EXECUTE) != 0,
            (header->Characteristics & IMAGE_SCN_MEM_READ) != 0};
        if (SectionInImage(s, size)) sections.push_back(s);
    }
}

bool WriteSite(uint8_t* image, const Site& site, bool forward) noexcept
{
    uint8_t* at = image + site.rva;
    const uint8_t* expected = forward ? site.before : site.after;
    const uint8_t* value = forward ? site.after : site.before;
    if (std::memcmp(at, value, site.length) == 0) return true;
    if (std::memcmp(at, expected, site.length) != 0) return false;
    DWORD previous = 0;
    if (!VirtualProtect(at, site.length, PAGE_EXECUTE_READWRITE, &previous)) return false;
    std::memcpy(at, value, site.length);
    const bool ok = std::memcmp(at, value, site.length) == 0;
    DWORD ignored = 0;
    VirtualProtect(at, site.length, previous, &ignored);
    FlushInstructionCache(GetCurrentProcess(), at, site.length);
    return ok;
}
}  // namespace

Result ForceSoftwarePacing(HMODULE module) noexcept
{
    Result result;
    if (!module) return result;
    std::lock_guard<std::mutex> guard(gMutex);
    auto* image = reinterpret_cast<uint8_t*>(module);
    size_t size = 0;
    const auto* nt = ReadHeaders(image, size);
    if (!nt) return result;
    for (const Pinned& p : gPinned)
    {
        if (p.image != image) continue;
        result.outcome = Outcome::eNothingToPin;
        result.field = p.plan.field;
        result.value = p.plan.value;
        result.sitesPatched = static_cast<uint32_t>(p.plan.sites.size());
        result.alreadyPinned = p.plan.alreadyPinned;
        result.pinnedBefore = true;
        return result;
    }
    std::vector<Section> sections;
    ReadSections(nt, size, sections);
    Plan plan;
    result.outcome = PlanSoftwarePacing(image, size, sections.data(), sections.size(), plan);
    result.field = plan.field;
    result.value = plan.value;
    result.alreadyPinned = plan.alreadyPinned;
    if (result.outcome != Outcome::ePlanned) return result;
    size_t written = 0;
    for (; written < plan.sites.size(); ++written)
        if (!WriteSite(image, plan.sites[written], true)) break;
    if (written != plan.sites.size())
    {
        for (size_t i = 0; i < written; ++i) WriteSite(image, plan.sites[i], false);
        result.outcome = Outcome::eNothingToPin;
        return result;
    }
    result.sitesPatched = static_cast<uint32_t>(plan.sites.size());
    gPinned.push_back({image, std::move(plan)});
    return result;
}

void Restore() noexcept
{
    std::lock_guard<std::mutex> guard(gMutex);
    for (auto it = gPinned.rbegin(); it != gPinned.rend(); ++it)
        for (const Site& site : it->plan.sites) WriteSite(it->image, site, false);
    gPinned.clear();
}
}  // namespace flip_metering
