#pragma once

#include <Windows.h>

#include <cstddef>
#include <cstdint>
#include <vector>

// Software pacing for the Streamline DLSS-G plugin (sl.dlss_g).
//
// Blackwell paces multi-frame output with hardware flip metering. Once the provider's architecture
// gates say multi-frame is available, the plugin takes that path on any GPU; Ada and Ampere have no
// such hardware, and on the Vulkan present path every generated frame then waits tens of
// milliseconds (observed: a 225-290 ms gap per real frame at 6x, ~35 ms at 2x). The plugin carries
// its own software fallback ("RSYNC"), reached at run time when it detects an FG1-era DLL, and this
// module forces that fallback by pinning the state field the fallback writes.
//
// Nothing here is hardcoded to a build: the field's offset AND polarity move between plugin
// versions (+0x38bc=0 in 2.7.1, +0x44a0=1 in 2.11.1, +0x4520=1 in 2.14.0), so both are derived from
// the image itself: locate the marker string, the code that references it, and the byte store that
// code performs; that (offset, value) pair is the wanted state. Every other store of that field is
// then pinned to the same value.
namespace flip_metering
{
struct Section { uint32_t rva; uint32_t size; bool executable; bool readable; };

enum class Outcome : uint32_t
{
    eNotDlssgPlugin = 0,   // marker string absent: not the DLSS-G plugin
    eNoFallbackStore,      // marker present, but the fallback's own store could not be read
    eNothingToPin,         // derived, and no store writes the opposite value (already pinned or unpatchable)
    ePlanned,
};
const wchar_t* OutcomeName(Outcome value) noexcept;

// One code edit: either the immediate of a `mov byte ptr [reg+disp32], imm8` (1 byte) or a whole
// `mov byte ptr [reg+disp32], reg8` rewritten into the immediate form (7 bytes, same length).
struct Site
{
    uint32_t rva;
    uint8_t length;
    uint8_t before[7];
    uint8_t after[7];
};

struct Plan
{
    Outcome outcome = Outcome::eNotDlssgPlugin;
    uint32_t markerRva = 0;
    uint32_t field = 0;        // byte offset of the pacing state inside the plugin's context object
    uint32_t value = 0;        // the value the software fallback writes there
    uint32_t alreadyPinned = 0;   // immediate stores that already write `value`
    std::vector<Site> sites;
};

// Pure over a byte view of a mapped image plus its section table.
Outcome PlanSoftwarePacing(const uint8_t* image, size_t size, const Section* sections, size_t count,
    Plan& out) noexcept;
// Pure over a writable byte view: all-or-nothing (every `before` run is checked first).
bool ApplyPlan(uint8_t* image, size_t size, const Plan& plan) noexcept;
void RevertPlan(uint8_t* image, size_t size, const Plan& plan) noexcept;

// Process level: derive and pin inside the mapped module. Idempotent per module; the outcome of a
// second call on a pinned module is eNothingToPin with `pinnedBefore` set.
struct Result
{
    Outcome outcome = Outcome::eNotDlssgPlugin;
    uint32_t field = 0, value = 0;
    uint32_t sitesPatched = 0, alreadyPinned = 0;
    bool pinnedBefore = false;
};
Result ForceSoftwarePacing(HMODULE module) noexcept;
// Put every patched store back.
void Restore() noexcept;
}
