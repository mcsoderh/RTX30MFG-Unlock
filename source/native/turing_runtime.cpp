#include "turing_runtime.h"

#include <algorithm>
#include <array>
#include <cstring>
#include <mutex>

namespace turing_runtime
{
namespace
{
constexpr uint32_t kImage = 0x745000u;
constexpr uint32_t kTable = 0x657070u;
constexpr uint32_t kDescriptors = 25;
constexpr uint32_t kDirect = 45;
constexpr uint32_t kContainers = 70;
constexpr uint32_t kSelector[] = {0x51928u, 0x51A67u};
constexpr uint8_t kCmpJle[] = {0x83, 0xF8, 0x59, 0x7E, 0x21};
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

uint8_t* Nearby(uintptr_t base, size_t bytes) noexcept
{
    const uintptr_t hints[] = {base + kImage,
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
        VirtualFree(gHeap, 0, MEM_RELEASE);
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
        auto* table = reinterpret_cast<uintptr_t*>(reinterpret_cast<uint8_t*>(gProvider) + kTable);
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
    for (uint32_t rva : kSelector)
    {
        if (rva + 5 > size) return false;
        const uint8_t* p = image + rva;
        if (std::memcmp(p, kCmpJle, 3) != 0) return false;
        if (p[3] == 0x7E && p[4] == 0x21)
        {
            out.push_back({rva + 3, 0x7E, 0x90});
            out.push_back({rva + 4, 0x21, 0x90});
        }
        else if (p[3] != 0x90 || p[4] != 0x90) return false;
    }
    return true;
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

void Rollback() noexcept
{
    std::lock_guard lock(gMutex);
    Restore();
}

bool Relocate(HMODULE provider, size_t size) noexcept
{
    std::lock_guard lock(gMutex);
    if (!provider || size != kImage) return false;
    auto* image = reinterpret_cast<uint8_t*>(provider);
    if (gReady && gProvider == provider) return true;
    if (gReady) Restore();

    std::vector<ampere_bundle::ByteEdit> selectors;
    if (!PlanSelectors(image, size, selectors)) return false;

    uint8_t* heap = nullptr;
    try
    {
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
            if (items.size() > kContainers) return false;
            rva += bytes - 4;
        }
        if (items.size() != kContainers) return false;

        for (size_t at = 0; at + 7 <= size; ++at)
        {
            uint32_t target = 0;
            if (!LeaTarget(image + at, static_cast<uint32_t>(at), target)) continue;
            for (auto& it : items)
            {
                if (it.rva != target) continue;
                it.leas.push_back(static_cast<uint32_t>(at));
                break;
            }
        }
        size_t leaCount = 0;
        for (const auto& it : items) leaCount += it.leas.size();
        if (leaCount != kDirect) return false;

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
        auto* table = reinterpret_cast<uintptr_t*>(image + kTable);
        std::array<uintptr_t, kDescriptors> originalTable{};
        std::array<Slot, kDescriptors> slots{};
        for (uint32_t i = 0; i < kDescriptors; ++i)
        {
            originalTable[i] = table[i];
            const bool inImage = table[i] >= base && table[i] <= base + size - kDescriptorBytes;
            if (!inImage)
            {
                auto* desc = reinterpret_cast<uint8_t*>(table[i]);
                MEMORY_BASIC_INFORMATION info{};
                if (!desc || VirtualQuery(desc, &info, sizeof info) != sizeof info || info.State != MEM_COMMIT)
                    return false;
                slots[i].clone = desc;
                slots[i].fatbin = Read<uintptr_t>(desc + 8);
                slots[i].bytes = Read<uint32_t>(desc + 16);
                if (!slots[i].fatbin || !slots[i].bytes) return false;
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

        heap = Nearby(base, heapBytes);
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
            VirtualFree(heap, 0, MEM_RELEASE);
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
        gReady = true;
        return true;
    }
    catch (...)
    {
        if (heap) VirtualFree(heap, 0, MEM_RELEASE);
        return false;
    }
}
}
