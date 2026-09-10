#pragma once

#include <cstdint>
#include <string_view>

// Ampere (GA10x, compute capability 8.6) admission policy. Pure decision logic over caller-supplied
// facts; no OS calls, no provider memory access. Every negative yields a specific reason and leaves
// the Ada path (dlssg_provider_policy) untouched. Admission is eligibility only: whether the mapped
// provider can actually be patched is decided at publication, where every byte is verified first.
namespace ampere_policy
{
enum class Reason : uint32_t
{
    eAdmitted = 0,
    eMultiplierUnsupported,  // multiplier outside 2x..5x (one to four generated frames)
    eGraphicsDeviceQuery = 4,    // the active adapter could not be enumerated
    eCudaUnavailable,        // nvcuda missing or enumeration failed
    eNonNvidia,              // active graphics adapter is not NVIDIA
    eAdapterNotUnique,       // no NVIDIA CUDA devices, or not exactly one graphics LUID match
    eNotAmpereGa10x,         // compute capability is not exactly 8.6
    eAdapterChanged,         // feature created on a different adapter than admission saw
    eTuringRouteUnverified,
};

struct Inputs
{
    uint32_t requestedMultiplier = 0;   // 2 == one generated frame
    bool graphicsDeviceQueried = false; // the active adapter was enumerated and its LUID read
    bool nvidiaAdapter = false;         // that adapter's vendor is NVIDIA
    bool cudaAvailable = false;
    uint32_t nvidiaCudaDevices = 0;     // CUDA devices enumerated
    uint32_t luidMatches = 0;           // CUDA devices whose LUID equals the active graphics adapter's
    int ccMajor = 0;
    int ccMinor = 0;
    bool turingRtx = false;
};

constexpr bool IsTuringRtx(int major, int minor, std::string_view name) noexcept
{
    if (major != 7 || minor != 5) return false;
    if (name == "NVIDIA TITAN RTX" || name == "TITAN RTX") return true;
    const size_t at = name.find("RTX ");
    return at != name.npos && (at == 0 || name[at - 1] == ' ')
        && at + 4 < name.size() && name[at + 4] >= '0' && name[at + 4] <= '9';
}

struct Decision
{
    bool admitted = false;
    Reason reason = Reason::eMultiplierUnsupported;
};

constexpr Decision Decide(const Inputs& in) noexcept
{
    if (in.requestedMultiplier < 2u || in.requestedMultiplier > 5u) return {false, Reason::eMultiplierUnsupported};
    if (!in.graphicsDeviceQueried) return {false, Reason::eGraphicsDeviceQuery};
    if (!in.cudaAvailable) return {false, Reason::eCudaUnavailable};
    if (!in.nvidiaAdapter) return {false, Reason::eNonNvidia};
    if (in.nvidiaCudaDevices == 0u || in.luidMatches != 1u) return {false, Reason::eAdapterNotUnique};
    if (in.ccMajor == 7 && in.ccMinor == 5 && in.turingRtx)
        return {true, Reason::eAdmitted};
    if (in.ccMajor != 8 || in.ccMinor != 6) return {false, Reason::eNotAmpereGa10x};
    return {true, Reason::eAdmitted};
}

static_assert(!Decide(Inputs{}).admitted);
static_assert(Decide(Inputs{}).reason == Reason::eMultiplierUnsupported);

const wchar_t* ReasonName(Reason reason) noexcept;
}
