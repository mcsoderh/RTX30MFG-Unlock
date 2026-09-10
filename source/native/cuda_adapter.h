#pragma once

#include <Windows.h>

#include <array>
#include <cstdint>
#include <cstring>
#include "ampere_policy.h"

namespace cuda_adapter
{
inline bool QueryDevices(uint64_t graphicsLuid, uint32_t& devices, uint32_t& matches, int& major,
    int& minor, bool* turingRtx = nullptr) noexcept
{
    if (turingRtx) *turingRtx = false;
    using CuInit = int(WINAPI*)(unsigned);
    using CuCount = int(WINAPI*)(int*);
    using CuGet = int(WINAPI*)(int*, int);
    using CuCap = int(WINAPI*)(int*, int*, int);
    using CuLuid = int(WINAPI*)(char*, unsigned*, int);
    using CuName = int(WINAPI*)(char*, int, int);
    HMODULE cuda = LoadLibraryExW(L"nvcuda.dll", nullptr, LOAD_LIBRARY_SEARCH_SYSTEM32);
    if (!cuda) return false;
    auto initialize = reinterpret_cast<CuInit>(GetProcAddress(cuda, "cuInit"));
    auto getCount = reinterpret_cast<CuCount>(GetProcAddress(cuda, "cuDeviceGetCount"));
    auto getDevice = reinterpret_cast<CuGet>(GetProcAddress(cuda, "cuDeviceGet"));
    auto getCapability = reinterpret_cast<CuCap>(GetProcAddress(cuda, "cuDeviceComputeCapability"));
    auto getLuid = reinterpret_cast<CuLuid>(GetProcAddress(cuda, "cuDeviceGetLuid"));
    auto getName = reinterpret_cast<CuName>(GetProcAddress(cuda, "cuDeviceGetName"));
    int count = 0;
    bool complete = initialize && getCount && getDevice && getCapability && getLuid
        && initialize(0) == 0 && getCount(&count) == 0 && count > 0;
    for (int ordinal = 0; complete && ordinal < count; ++ordinal)
    {
        int device = 0, candidateMajor = 0, candidateMinor = 0;
        std::array<char, sizeof(LUID)> raw{};
        unsigned nodeMask = 0;
        if (getDevice(&device, ordinal) != 0
            || getCapability(&candidateMajor, &candidateMinor, device) != 0
            || getLuid(raw.data(), &nodeMask, device) != 0)
        {
            complete = false;
            break;
        }
        ++devices;
        uint64_t candidate = 0;
        std::memcpy(&candidate, raw.data(), sizeof candidate);
        if (candidate == graphicsLuid)
        {
            ++matches;
            major = candidateMajor;
            minor = candidateMinor;
            if (turingRtx)
            {
                std::array<char, 256> name{};
                *turingRtx = getName && getName(name.data(), static_cast<int>(name.size()), device) == 0
                    && name.back() == '\0' && ampere_policy::IsTuringRtx(major, minor, name.data());
            }
        }
    }
    FreeLibrary(cuda);
    return complete;
}
}
