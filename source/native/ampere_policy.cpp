#include "ampere_policy.h"

namespace ampere_policy
{
const wchar_t* ReasonName(Reason reason) noexcept
{
    switch (reason)
    {
    case Reason::eAdmitted: return L"admitted";
    case Reason::eMultiplierUnsupported: return L"multiplier-unsupported";
    case Reason::eGraphicsDeviceQuery: return L"graphics-device-query";
    case Reason::eCudaUnavailable: return L"cuda-unavailable";
    case Reason::eNonNvidia: return L"non-nvidia";
    case Reason::eAdapterNotUnique: return L"adapter-not-unique";
    case Reason::eNotAmpereGa10x: return L"not-ampere-ga10x";
    case Reason::eAdapterChanged: return L"adapter-changed";
    }
    return L"unknown";
}
}
