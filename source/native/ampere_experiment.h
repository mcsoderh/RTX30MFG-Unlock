#pragma once

#include <Windows.h>

#include <string>
#include <string_view>

#include "ampere_policy.h"

// Runtime glue for the Ampere path. It engages only on a single NVIDIA adapter of compute capability
// 8.6, so the same core is inert on every other GPU.
//
// Split by loader-lock safety:
//   Initialize()      - called from PatchWorker. Does the DXGI/CUDA/driver queries, evaluates
//                       ampere_policy, and selects the provider the runtime will be pointed at.
//   OnProviderLoaded()- called from the loader DLL-notification for the provider. Under loader
//                       lock; validates the mapped image and publishes its gate edits.
//   ConfirmAdapter()  - called at the pre-create point with the real device LUID. A mismatch
//                       against the LUID admission was decided on rolls the publication back and
//                       reports that a restart is required.
namespace ampere_experiment
{
struct State
{
    bool admitted = false;
    ampere_policy::Reason reason = ampere_policy::Reason::eMultiplierUnsupported;
    bool prepared = false;       // ampere_bundle ready to publish
    bool published = false;      // the provider gate edits are live
    bool restartRequired = false;
    uint64_t admittedLuid = 0;   // adapter the decision was made against
    uint32_t driverObserved = 0; // installed driver, for the log
    uint32_t providerRedirects = 0;  // NGX provider loads redirected to the selected copy
    std::wstring redirectedFrom; // the last provider path the runtime asked for before redirection
    std::wstring providerSelected;   // the DLSS-G provider this process was pointed at
    uint64_t providerSelectedVersion = 0;  // its file version, packed major<<48|minor<<32|build<<16|revision
    std::wstring detail;         // first failure detail, for the log
};

// Gathers admission facts once, early, off the loader lock. Returns eligibility;
// State::prepared and State::published report publication readiness and completion.
bool Initialize(uint32_t requestedMultiplier) noexcept;

// Loader-lock safe. Publishes the gate edits into the just-mapped provider when admitted. Kernels
// are retargeted later, at the pre-create point (ampere_bundle::RetargetKernels), after the
// temporal fix has read the original container it rebuilds.
// baseName is the notification's base DLL name; anything but a DLSS-G provider is ignored.
void OnProviderLoaded(HMODULE module, std::wstring_view baseName, std::wstring_view fullPath) noexcept;

// Re-verify the adapter the feature is actually being created on. Returns false when the
// publication was rolled back and the process must restart before trying again.
bool ConfirmAdapter(uint64_t activeLuid) noexcept;

// Undo the provider edits.
void Shutdown() noexcept;

bool IsAdmitted() noexcept;
bool IsPublished() noexcept;
State Current() noexcept;
}
