#include "turing_runtime.h"
#include "midpoint_fix.h"
#include "third_party/minhook/src/hde/hde64.h"

#include <algorithm>
#include <array>
#include <cstring>
#include <mutex>

namespace turing_runtime
{
namespace
{
constexpr uint32_t kDescriptors = 25;
uintptr_t gTableAddress = 0;

bool Readable(const void* pointer, size_t bytes) noexcept
{
    uintptr_t at = reinterpret_cast<uintptr_t>(pointer);
    if (!at || bytes > UINTPTR_MAX - at) return false;
    const uintptr_t end = at + bytes;
    while (at < end)
    {
        MEMORY_BASIC_INFORMATION info{};
        if (VirtualQuery(reinterpret_cast<const void*>(at), &info, sizeof info) != sizeof info
            || info.State != MEM_COMMIT || (info.Protect & PAGE_GUARD)) return false;
        const DWORD protection = info.Protect & 0xff;
        if (protection != PAGE_READONLY && protection != PAGE_READWRITE && protection != PAGE_WRITECOPY
            && protection != PAGE_EXECUTE_READ && protection != PAGE_EXECUTE_READWRITE
            && protection != PAGE_EXECUTE_WRITECOPY) return false;
        const uintptr_t base = reinterpret_cast<uintptr_t>(info.BaseAddress);
        if (info.RegionSize > UINTPTR_MAX - base || base + info.RegionSize <= at) return false;
        at = std::min(end, base + info.RegionSize);
    }
    return true;
}

struct Code
{
    const uint8_t* image = nullptr;
    size_t size = 0;
    std::vector<uint32_t> owner;
    std::vector<uint8_t> length;
    std::vector<std::pair<uint32_t, uint32_t>> ranges;

    bool Parse(const uint8_t* p, size_t bytes)
    {
        if (!p || bytes < sizeof(IMAGE_NT_HEADERS64) || bytes > (256u << 20)
            || !Readable(p, bytes)) return false;
        IMAGE_DOS_HEADER dos{};
        std::memcpy(&dos, p, sizeof dos);
        if (dos.e_magic != IMAGE_DOS_SIGNATURE || dos.e_lfanew <= 0
            || size_t(dos.e_lfanew) > bytes - sizeof(IMAGE_NT_HEADERS64)) return false;
        IMAGE_NT_HEADERS64 nt{};
        std::memcpy(&nt, p + dos.e_lfanew, sizeof nt);
        if (nt.Signature != IMAGE_NT_SIGNATURE || nt.FileHeader.Machine != IMAGE_FILE_MACHINE_AMD64
            || nt.OptionalHeader.Magic != IMAGE_NT_OPTIONAL_HDR64_MAGIC
            || nt.OptionalHeader.SizeOfImage != bytes
            || nt.FileHeader.SizeOfOptionalHeader != sizeof(IMAGE_OPTIONAL_HEADER64)
            || nt.OptionalHeader.NumberOfRvaAndSizes <= IMAGE_DIRECTORY_ENTRY_EXCEPTION) return false;
        const size_t sections = size_t(dos.e_lfanew) + sizeof nt;
        if (sections > bytes || nt.FileHeader.NumberOfSections > (bytes - sections) / sizeof(IMAGE_SECTION_HEADER)) return false;
        for (size_t i = 0; i < nt.FileHeader.NumberOfSections; ++i)
        {
            IMAGE_SECTION_HEADER s{};
            std::memcpy(&s, p + sections + i * sizeof s, sizeof s);
            const size_t n = std::max(s.Misc.VirtualSize, s.SizeOfRawData);
            if (s.VirtualAddress > bytes || n > bytes - s.VirtualAddress) return false;
            if (s.Characteristics & IMAGE_SCN_MEM_EXECUTE)
            {
                if (!(s.Characteristics & IMAGE_SCN_MEM_READ) || !n) return false;
                ranges.emplace_back(s.VirtualAddress, s.VirtualAddress + static_cast<uint32_t>(n));
            }
        }
        std::sort(ranges.begin(), ranges.end());
        for (size_t i = 1; i < ranges.size(); ++i)
            if (ranges[i].first < ranges[i - 1].second) return false;
        const auto d = nt.OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_EXCEPTION];
        if (!d.Size || d.Size % sizeof(RUNTIME_FUNCTION) || d.VirtualAddress > bytes
            || d.Size > bytes - d.VirtualAddress) return false;
        image = p; size = bytes;
        owner.resize(bytes); length.resize(bytes);
        uint32_t last = 0;
        for (size_t i = 0; i < d.Size; i += sizeof(RUNTIME_FUNCTION))
        {
            RUNTIME_FUNCTION f{};
            std::memcpy(&f, p + d.VirtualAddress + i, sizeof f);
            if (f.BeginAddress < last || f.BeginAddress >= f.EndAddress || !Executable(f.BeginAddress, f.EndAddress)) return false;
            last = f.EndAddress;
            for (uint32_t at = f.BeginAddress; at < f.EndAddress;)
            {
                uint8_t buffer[32]{};
                std::memcpy(buffer, p + at, std::min<size_t>(sizeof buffer, f.EndAddress - at));
                hde64s h{};
                hde64_disasm(buffer, &h);
                if (!h.len || (h.flags & F_ERROR) || h.len > f.EndAddress - at) break;
                owner[at] = f.BeginAddress;
                length[at] = h.len;
                at += h.len;
            }
        }
        return !ranges.empty();
    }
    bool Executable(uint32_t begin, uint32_t end) const
    {
        for (const auto& r : ranges) if (begin >= r.first && end <= r.second) return true;
        return false;
    }
    uint32_t Call(uint32_t at) const
    {
        if (at >= size || length[at] != 5 || image[at] != 0xe8) return 0;
        int32_t disp = 0;
        std::memcpy(&disp, image + at + 1, 4);
        const int64_t target = int64_t(at) + 5 + disp;
        if (target <= 0 || target >= int64_t(size) || owner[target] != target) return 0;
        return static_cast<uint32_t>(target);
    }
};
constexpr uint32_t kFatbinMagic = 0xBA55ED50u;
constexpr size_t kDescriptorBytes = 48;

std::mutex gMutex;
HMODULE gProvider = nullptr;
uint8_t* gHeap = nullptr;
std::vector<ampere_bundle::ByteEdit> gEdits;
std::array<uintptr_t, kDescriptors> gTable{};
struct CloneUndo
{
    uint8_t* descriptor = nullptr;
    uintptr_t fatbin = 0;
    uint32_t bytes = 0;
};
std::array<CloneUndo, kDescriptors> gClones{};
uint32_t gCloneCount = 0;
bool gReady = false;
uint32_t gContainers = 0;

template<class T>
T Read(const uint8_t* p) noexcept
{
    T value{};
    std::memcpy(&value, p, sizeof value);
    return value;
}

size_t WriteEdits(uint8_t* image, const std::vector<ampere_bundle::ByteEdit>& edits, bool forward) noexcept
{
    constexpr uintptr_t kPage = 4096;
    size_t done = 0;
    while (done < edits.size())
    {
        const uintptr_t page = (reinterpret_cast<uintptr_t>(image) + edits[done].rva) & ~(kPage - 1);
        size_t end = done;
        while (end < edits.size()
            && ((reinterpret_cast<uintptr_t>(image) + edits[end].rva) & ~(kPage - 1)) == page) ++end;
        for (size_t i = done; i < end; ++i)
        {
            const uint8_t byte = image[edits[i].rva];
            if (byte != (forward ? edits[i].before : edits[i].after)
                && byte != (forward ? edits[i].after : edits[i].before))
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

bool WriteAll(uint8_t* image, const std::vector<ampere_bundle::ByteEdit>& edits, bool forward) noexcept
{
    const size_t done = WriteEdits(image, edits, forward);
    if (done == edits.size()) return true;
    std::vector<ampere_bundle::ByteEdit> partial(edits.begin(), edits.begin() + done);
    WriteEdits(image, partial, !forward);
    return false;
}

void AddDisp(std::vector<ampere_bundle::ByteEdit>& edits, uint32_t rva, int32_t before, int32_t after) noexcept
{
    uint8_t b[4]{}, a[4]{};
    std::memcpy(b, &before, 4);
    std::memcpy(a, &after, 4);
    for (uint32_t i = 0; i < 4; ++i)
        if (b[i] != a[i]) edits.push_back({rva + i, b[i], a[i]});
}

uint8_t* Nearby(uintptr_t base, size_t imageSize, size_t bytes) noexcept
{
    const uintptr_t hints[] = {base + imageSize,
        base > bytes + 0x10000u ? base - bytes - 0x10000u : 0};
    for (uintptr_t hint : hints)
    {
        if (!hint) continue;
        if (auto* p = static_cast<uint8_t*>(
                VirtualAlloc(reinterpret_cast<void*>(hint), bytes, MEM_RESERVE | MEM_COMMIT, PAGE_READWRITE)))
            return p;
    }
    return static_cast<uint8_t*>(VirtualAlloc(nullptr, bytes, MEM_RESERVE | MEM_COMMIT, PAGE_READWRITE));
}

bool Fits(uintptr_t insn, uintptr_t target, int32_t& disp) noexcept
{
    const intptr_t delta = static_cast<intptr_t>(target) - static_cast<intptr_t>(insn + 7);
    if (delta < INT32_MIN || delta > INT32_MAX) return false;
    disp = static_cast<int32_t>(delta);
    return true;
}

bool PatchDescriptor(uint8_t* descriptor, uintptr_t fatbin, uint32_t bytes) noexcept
{
    DWORD previous = 0;
    if (!VirtualProtect(descriptor, kDescriptorBytes, PAGE_READWRITE, &previous)) return false;
    std::memcpy(descriptor + 8, &fatbin, sizeof fatbin);
    std::memcpy(descriptor + 16, &bytes, sizeof bytes);
    DWORD ignored = 0;
    VirtualProtect(descriptor, kDescriptorBytes, previous, &ignored);
    return true;
}

void Reset() noexcept
{
    if (gHeap)
    {
        gHeap = nullptr;
    }
    gEdits.clear();
    gTable = {};
    gClones = {};
    gCloneCount = 0;
    gProvider = nullptr;
    gReady = false;
}

bool ImageLive(HMODULE module) noexcept
{
    MEMORY_BASIC_INFORMATION info{};
    return module && VirtualQuery(module, &info, sizeof info) == sizeof info && info.State == MEM_COMMIT;
}

void Restore() noexcept
{
    if (gProvider && ImageLive(gProvider) && !gEdits.empty())
        WriteEdits(reinterpret_cast<uint8_t*>(gProvider), gEdits, false);
    if (gProvider && ImageLive(gProvider) && gTable[0])
    {
        auto* table = reinterpret_cast<uintptr_t*>(gTableAddress);
        DWORD previous = 0;
        if (VirtualProtect(table, kDescriptors * sizeof(uintptr_t), PAGE_EXECUTE_READWRITE, &previous))
        {
            for (uint32_t i = 0; i < kDescriptors; ++i) table[i] = gTable[i];
            DWORD ignored = 0;
            VirtualProtect(table, kDescriptors * sizeof(uintptr_t), previous, &ignored);
        }
    }
    for (uint32_t i = 0; i < gCloneCount; ++i)
        if (gClones[i].descriptor)
            PatchDescriptor(gClones[i].descriptor, gClones[i].fatbin, gClones[i].bytes);
    Reset();
}

struct Item
{
    uint32_t rva = 0;
    const uint8_t* source = nullptr;
    size_t sourceBytes = 0;
    std::vector<uint8_t> lowered;
    uint32_t heap = 0;
    std::vector<uint32_t> leas;
};
}

bool PlanSelectors(const uint8_t* image, size_t size, std::vector<ampere_bundle::ByteEdit>& out) noexcept
{
    out.clear();
    try
    {
        Code code;
        if (!code.Parse(image, size)) return false;
        std::vector<ampere_bundle::ByteEdit> edits;
        uint32_t function = 0, allocator = 0, firstCtor = 0;
        for (uint32_t at = 5; at + 80 < size; ++at)
        {
            if (code.length[at] != 3 || image[at] != 0x83 || image[at + 1] != 0xf8
                || image[at + 2] != 0x59) continue;
            if (image[at + 3] != 0x7e || code.length[at + 3] != 2) continue;
            const uint32_t branch = at + 5 + image[at + 4];
            if (image[at + 4] < 0x1f || image[at + 4] > 0x26
                || code.owner[branch] != code.owner[at] || code.length[branch] != 2
                || image[branch] != 0x7c || image[branch + 1] != image[at + 4]
                || code.length[at - 5] != 5 || image[at - 5] != 0xb9) return false;
            const uint32_t alloc = code.Call(at + 5);
            if (!alloc || code.Call(branch + 2) != alloc) return false;
            uint32_t ctor = 0;
            for (uint32_t p = at + 10; p < branch; p += code.length[p])
            {
                if (!code.length[p]) return false;
                if (image[p] == 0xe8)
                {
                    if (ctor || !(ctor = code.Call(p))) return false;
                }
            }
            if (!ctor || ctor == alloc || (function && function != code.owner[at])
                || (allocator && allocator != alloc) || ctor == firstCtor) return false;
            if (!firstCtor) firstCtor = ctor;
            function = code.owner[at]; allocator = alloc;
            edits.push_back({at + 3, 0x7e, 0x90});
            edits.push_back({at + 4, image[at + 4], 0x90});
        }
        if (edits.size() != 4) return false;
        out = std::move(edits);
        return true;
    }
    catch (...) { return false; }
}

bool LeaTarget(const uint8_t* insn, uint32_t insnRva, uint32_t& targetRva) noexcept
{
    if (!insn || insn[0] != 0x48 || insn[1] != 0x8D || (insn[2] & 0xC7) != 0x05) return false;
    targetRva = insnRva + 7u + static_cast<uint32_t>(Read<int32_t>(insn + 3));
    return true;
}

bool Ready() noexcept
{
    std::lock_guard lock(gMutex);
    return gReady;
}

uint32_t ContainerCount() noexcept
{
    std::lock_guard lock(gMutex);
    return gReady ? gContainers : 0;
}

void Rollback() noexcept
{
    std::lock_guard lock(gMutex);
    Restore();
}

bool Relocate(HMODULE provider, size_t size) noexcept
{
    std::lock_guard lock(gMutex);
    if (!provider || size < sizeof(IMAGE_NT_HEADERS64) || size > UINT32_MAX) return false;
    auto* image = reinterpret_cast<uint8_t*>(provider);
    if (gReady && gProvider == provider) return true;
    if (gReady) Restore();

    std::vector<ampere_bundle::ByteEdit> selectors;
    if (!PlanSelectors(image, size, selectors)) return false;

    uint8_t* heap = nullptr;
    try
    {
        Code code;
        if (!code.Parse(image, size)) return false;
        uintptr_t tableAddress = 0, trustedClone = 0;
        if (!midpoint_fix::TuringDescriptors(provider, size, tableAddress, trustedClone)) return false;
        std::vector<Item> items;
        for (size_t rva = 0; rva + 16 <= size; rva += 4)
        {
            if (Read<uint32_t>(image + rva) != kFatbinMagic) continue;
            const uint64_t payload = Read<uint64_t>(image + rva + 8);
            if (!payload || payload > size - rva - 16) continue;
            const size_t bytes = 16 + static_cast<size_t>(payload);
            Item item;
            item.rva = static_cast<uint32_t>(rva);
            item.source = image + rva;
            item.sourceBytes = bytes;
            const auto result = ampere_bundle::BuildTuringContainer(item.source, bytes, item.lowered);
            if (result == ampere_bundle::Retarget::eNoContainers || result == ampere_bundle::Retarget::eLayout)
                continue;
            if (result != ampere_bundle::Retarget::eOk) return false;
            items.push_back(std::move(item));
            if (items.size() > 512) return false;
            rva += bytes - 4;
        }
        if (items.empty()) return false;

        for (size_t at = 0; at + 7 <= size; ++at)
        {
            uint32_t target = 0;
            if (!code.Executable(static_cast<uint32_t>(at), static_cast<uint32_t>(at + 7))
                || !LeaTarget(image + at, static_cast<uint32_t>(at), target)) continue;
            for (auto& it : items)
            {
                if (it.rva != target) continue;
                if (code.length[at] != 7) return false;
                it.leas.push_back(static_cast<uint32_t>(at));
                break;
            }
        }
        size_t leaCount = 0;
        for (const auto& it : items) leaCount += it.leas.size();
        if (!leaCount) return false;

        struct Slot
        {
            Item* item = nullptr;
            uint8_t* clone = nullptr;
            uintptr_t fatbin = 0;
            uint32_t bytes = 0;
            std::vector<uint8_t> lowered;
            uint32_t heap = 0;
        };
        const uintptr_t base = reinterpret_cast<uintptr_t>(image);
        auto* table = reinterpret_cast<uintptr_t*>(tableAddress);
        std::array<uintptr_t, kDescriptors> originalTable{};
        std::array<Slot, kDescriptors> slots{};
        for (uint32_t i = 0; i < kDescriptors; ++i)
        {
            originalTable[i] = table[i];
            const bool inImage = table[i] >= base && table[i] <= base + size - kDescriptorBytes;
            if (!inImage)
            {
                auto* desc = reinterpret_cast<uint8_t*>(table[i]);
                if (table[i] != trustedClone) return false;
                slots[i].clone = desc;
                slots[i].fatbin = Read<uintptr_t>(desc + 8);
                slots[i].bytes = Read<uint32_t>(desc + 16);
                if (!slots[i].fatbin || !slots[i].bytes || slots[i].bytes > (64u << 20)
                    || !Readable(reinterpret_cast<const void*>(slots[i].fatbin), slots[i].bytes)) return false;
                if (ampere_bundle::BuildTuringContainer(reinterpret_cast<const uint8_t*>(slots[i].fatbin),
                        slots[i].bytes, slots[i].lowered) != ampere_bundle::Retarget::eOk)
                    return false;
                continue;
            }
            const uintptr_t fatbin = Read<uintptr_t>(reinterpret_cast<const uint8_t*>(table[i]) + 8);
            if (fatbin < base || fatbin >= base + size) return false;
            const uint32_t rva = static_cast<uint32_t>(fatbin - base);
            for (auto& it : items)
                if (it.rva == rva) { slots[i].item = &it; break; }
            if (!slots[i].item) return false;
        }

        size_t heapBytes = kDescriptors * kDescriptorBytes;
        for (auto& it : items)
        {
            it.heap = static_cast<uint32_t>(heapBytes);
            heapBytes += (it.lowered.size() + 15) & ~size_t{15};
        }
        for (auto& slot : slots)
        {
            if (!slot.clone) continue;
            slot.heap = static_cast<uint32_t>(heapBytes);
            heapBytes += (slot.lowered.size() + 15) & ~size_t{15};
        }

        heap = Nearby(base, size, heapBytes);
        if (!heap) return false;
        for (auto& it : items)
            std::memcpy(heap + it.heap, it.lowered.data(), it.lowered.size());
        for (auto& slot : slots)
            if (slot.clone) std::memcpy(heap + slot.heap, slot.lowered.data(), slot.lowered.size());
        for (uint32_t i = 0; i < kDescriptors; ++i)
        {
            if (slots[i].clone) continue;
            auto* desc = reinterpret_cast<const uint8_t*>(table[i]);
            std::memcpy(heap + i * kDescriptorBytes, desc, kDescriptorBytes);
            const uintptr_t replacement = reinterpret_cast<uintptr_t>(heap + slots[i].item->heap);
            const uint32_t bytes = static_cast<uint32_t>(slots[i].item->lowered.size());
            std::memcpy(heap + i * kDescriptorBytes + 8, &replacement, sizeof replacement);
            std::memcpy(heap + i * kDescriptorBytes + 16, &bytes, sizeof bytes);
        }

        std::vector<ampere_bundle::ByteEdit> edits = std::move(selectors);
        for (auto& it : items)
        {
            const uintptr_t target = reinterpret_cast<uintptr_t>(heap + it.heap);
            for (uint32_t insn : it.leas)
            {
                int32_t after = 0;
                if (!Fits(base + insn, target, after))
                {
                    VirtualFree(heap, 0, MEM_RELEASE);
                    return false;
                }
                uint32_t sizeSite = 0;
                if (image[insn + 2] == 0x15)
                {
                    uint32_t start = insn;
                    for (uint32_t p = insn > 80 ? insn - 80 : 0; p < insn; ++p)
                        if (code.owner[p] == code.owner[insn] && code.length[p]
                            && (image[p] == 0xe8 || image[p] == 0xc3 || image[p] == 0xeb
                                || (image[p] >= 0x70 && image[p] <= 0x7f))) start = p + code.length[p];
                    if (start == insn)
                    {
                        for (uint32_t p = insn > 80 ? insn - 80 : 0; p < insn; ++p)
                            if (code.owner[p] == code.owner[insn] && code.length[p]) { start = p; break; }
                    }
                    bool called = false;
                    for (uint32_t p = start; p < size && p < insn + 96;)
                    {
                        const uint8_t n = code.length[p];
                        if (!n || code.owner[p] != code.owner[insn]) break;
                        if (image[p] == 0xe8)
                        {
                            if (p < insn) { sizeSite = 0; p += n; continue; }
                            called = code.Call(p) != 0;
                            break;
                        }
                        if (n == 6 && image[p] == 0x41 && image[p + 1] == 0xb8)
                        {
                            if (sizeSite) { sizeSite = 0; break; }
                            sizeSite = p + 2;
                        }
                        else if (p >= insn && p != insn)
                        {
                            const bool mov = image[p] == 0x8b || image[p] == 0x89
                                || (image[p] == 0x48 && (image[p + 1] == 0x8b || image[p + 1] == 0x89));
                            if (!mov) break;
                        }
                        p += n;
                    }
                    if (!called || !sizeSite) { VirtualFree(heap, 0, MEM_RELEASE); return false; }
                }
                else if (image[insn + 2] == 0x05)
                {
                    const uint32_t store = insn + 7;
                    const uint32_t load = store + code.length[store];
                    if (load + 9 >= size || image[store] != 0x48 || image[store + 1] != 0x89
                        || (image[store + 2] != 0x03 && image[store + 2] != 0x43)
                        || code.length[load] != 6 || image[load] != 0x8b || image[load + 1] != 0x05
                        || code.length[load + 6] != 3 || image[load + 6] != 0x89 || image[load + 7] != 0x43
                        || image[load + 8] != (image[store + 2] == 0x03 ? 8 : image[store + 3] + 8))
                    { VirtualFree(heap, 0, MEM_RELEASE); return false; }
                    const int64_t targetSize = int64_t(load) + 6 + Read<int32_t>(image + load + 2);
                    if (targetSize < 0 || targetSize + 4 > int64_t(size)
                        || code.Executable(static_cast<uint32_t>(targetSize), static_cast<uint32_t>(targetSize + 4)))
                    { VirtualFree(heap, 0, MEM_RELEASE); return false; }
                    sizeSite = static_cast<uint32_t>(targetSize);
                }
                if (!sizeSite || Read<uint32_t>(image + sizeSite) != it.sourceBytes || it.lowered.size() > INT32_MAX)
                { VirtualFree(heap, 0, MEM_RELEASE); return false; }
                AddDisp(edits, sizeSite, Read<int32_t>(image + sizeSite), static_cast<int32_t>(it.lowered.size()));
                AddDisp(edits, insn + 3, Read<int32_t>(image + insn + 3), after);
            }
        }
        std::sort(edits.begin(), edits.end(),
            [](const ampere_bundle::ByteEdit& a, const ampere_bundle::ByteEdit& b) { return a.rva < b.rva; });
        for (size_t i = 1; i < edits.size(); ++i)
            if (edits[i].rva == edits[i - 1].rva)
            {
                VirtualFree(heap, 0, MEM_RELEASE);
                return false;
            }

        DWORD previous = 0;
        if (!VirtualProtect(table, kDescriptors * sizeof(uintptr_t), PAGE_EXECUTE_READWRITE, &previous))
        {
            VirtualFree(heap, 0, MEM_RELEASE);
            return false;
        }
        gHeap = heap;
        gProvider = provider;
        gTableAddress = tableAddress;
        gTable = originalTable;
        for (uint32_t i = 0; i < kDescriptors; ++i)
            if (!slots[i].clone) table[i] = reinterpret_cast<uintptr_t>(heap + i * kDescriptorBytes);
        DWORD ignored = 0;
        VirtualProtect(table, kDescriptors * sizeof(uintptr_t), previous, &ignored);

        std::array<CloneUndo, kDescriptors> applied{};
        uint32_t appliedCount = 0;
        bool clonesOk = true;
        for (uint32_t i = 0; i < kDescriptors && clonesOk; ++i)
        {
            if (!slots[i].clone) continue;
            const uintptr_t replacement = reinterpret_cast<uintptr_t>(heap + slots[i].heap);
            const uint32_t bytes = static_cast<uint32_t>(slots[i].lowered.size());
            if (!PatchDescriptor(slots[i].clone, replacement, bytes)) { clonesOk = false; break; }
            applied[appliedCount++] = {slots[i].clone, slots[i].fatbin, slots[i].bytes};
        }
        if (!clonesOk || !WriteAll(image, edits, true))
        {
            for (uint32_t i = 0; i < appliedCount; ++i)
                PatchDescriptor(applied[i].descriptor, applied[i].fatbin, applied[i].bytes);
            if (VirtualProtect(table, kDescriptors * sizeof(uintptr_t), PAGE_EXECUTE_READWRITE, &previous))
            {
                for (uint32_t i = 0; i < kDescriptors; ++i) table[i] = originalTable[i];
                VirtualProtect(table, kDescriptors * sizeof(uintptr_t), previous, &ignored);
            }
            Reset();
            return false;
        }

        DWORD heapProt = 0;
        VirtualProtect(heap, heapBytes, PAGE_READONLY, &heapProt);
        gHeap = heap;
        gEdits = std::move(edits);
        gTable = originalTable;
        gClones = applied;
        gCloneCount = appliedCount;
        gProvider = provider;
        gContainers = static_cast<uint32_t>(items.size());
        gReady = true;
        return true;
    }
    catch (...)
    {
        if (heap && heap != gHeap) VirtualFree(heap, 0, MEM_RELEASE);
        return false;
    }
}
}
