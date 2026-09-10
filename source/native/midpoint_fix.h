#pragma once

#include <Windows.h>

#include <cstdint>

namespace midpoint_fix
{
using LogCallback = void (*)(const wchar_t* message);

void SetLogCallback(LogCallback callback) noexcept;
bool ObserveD3D12Device(void* device) noexcept;
bool ObserveVulkanPhysicalDevice(void* physicalDevice) noexcept;
bool PatchProvider(HMODULE module, const wchar_t* path) noexcept;
bool AdapterVerified() noexcept;
// Ampere hosting (GA10x, compute capability 8.6): the adapter check accepts 8.6 beside Ada's 8.9 and
// the rebuilt temporal kernel is emitted for sm_86, matching the provider's other kernels once
// ampere_bundle has retargeted them in place. Off by default; set before the adapter is observed.
void SetAmpereTarget(bool enabled) noexcept;
void SetTuringTarget(bool enabled) noexcept;
bool Ready() noexcept;
uint32_t FailureCode() noexcept;
}
