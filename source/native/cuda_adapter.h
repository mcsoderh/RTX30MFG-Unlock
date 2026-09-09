#pragma once

#include <Windows.h>

#include <array>
#include <cstdint>
#include <cstring>

namespace cuda_adapter
{
inline bool QueryDevices(uint64_t graphicsLuid, uint32_t& devices, uint32_t& matches, int& major,
    int& minor) noexcept
{
    using CuInit = int(WINAPI*)(unsigned);
    using CuCount = int(WINAPI*)(int*);
    using CuGet = int(WINAPI*)(int*, int);
    using CuCap = int(WINAPI*)(int*, int*, int);
    using CuLuid = int(WINAPI*)(char*, unsigned*, int);
    HMODULE cuda = LoadLibraryExW(L"nvcuda.dll", nullptr, LOAD_LIBRARY_SEARCH_SYSTEM32);
    if (!cuda) return false;
    auto initialize = reinterpret_cast<CuInit>(GetProcAddress(cuda, "cuInit"));
    auto getCount = reinterpret_cast<CuCount>(GetProcAddress(cuda, "cuDeviceGetCount"));
    auto getDevice = reinterpret_cast<CuGet>(GetProcAddress(cuda, "cuDeviceGet"));
    auto getCapability = reinterpret_cast<CuCap>(GetProcAddress(cuda, "cuDeviceComputeCapability"));
    auto getLuid = reinterpret_cast<CuLuid>(GetProcAddress(cuda, "cuDeviceGetLuid"));
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
        }
    }
    FreeLibrary(cuda);
    return complete;
}
}
