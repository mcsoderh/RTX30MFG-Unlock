#pragma once

#include <Windows.h>

#include <cstddef>
#include <cstdint>
#include <string>
#include <vector>

// Ampere publication into the mapped DLSS-G provider. Nothing is shipped and nothing on disk changes:
// every edit is made to the provider's own image at run time and reverted on rollback.
//
//   1. NVSDK_NGX_GetGPUArchitecture is "mov eax, 0x190; ret" -> the immediate's low byte becomes 0x70
//      (Ampere). 2. NVSDK_NGX_D3D12_GetFeatureRequirements (and the Vulkan export when present)
//      stores the same constant into its result record -> the same byte edit. Both are located from
//      the image itself (DiscoverLayout): no offsets or versions are pinned, and a build whose sites
//      do not have the reviewed shape is left untouched.
//   3. Kernels. Every DLSS-G kernel container is a fatbin whose kernel is LZ4-compressed sm_89 PTX
//      (sometimes beside an sm_120 PTX and an sm_89 cubin). The PTX is retargeted IN PLACE: the one
//      LZ4 literal holding the 9 of ".target sm_89" becomes 6, the entry's architecture field becomes
//      86, and the container's payload length is shortened so a trailing sm_89 cubin is no longer
//      selectable. The driver then JIT-compiles the same PTX for sm_86 through whichever creation
//      path the provider uses (NVAPI per-kernel, NVAPI CUDA module, Vulkan binary import), so no
//      creation entry point needs wrapping.
namespace ampere_bundle
{
struct BytePatch
{
    uint32_t rva;            // start of the expected byte run
    uint8_t expected[8];
    uint8_t length;          // bytes compared
    uint8_t patchOffset;     // which byte changes
    uint8_t patchedValue;
};

struct ProviderLayout
{
    uint32_t sizeOfImage;
    BytePatch architecture;
    BytePatch discovery;
    // The Vulkan discovery export carries the same architecture constant as the D3D12 one; Streamline
    // reads it in Vulkan titles. Zero rva when the build has no Vulkan export.
    BytePatch discoveryVulkan;
};

// Locates the gate bytes in any DLSS-G provider build, from the image alone: the architecture constant
// is the whole body of the NVSDK_NGX_GetGPUArchitecture export (mov eax, imm32; ret) and the advertised
// minimum is the same immediate stored into the GetFeatureRequirements stack record. Pure and read-only.
enum class Discovery : uint32_t
{
    eOk = 0, eNotPe, eArchExport, eArchBytes, eArchValue, eRequirementsExport, eRequirementsSite,
};
Discovery DiscoverLayout(const uint8_t* image, size_t size, ProviderLayout& out) noexcept;
const wchar_t* DiscoveryName(Discovery value) noexcept;

// Pure, testable over a byte view of the mapped image (or a synthetic buffer). Every byte of every
// expected run must match; with `allowPatched` the patched byte itself may already hold its patched
// value, which is how a second mapping of the same provider is recognised.
enum class ImageCheck : uint32_t { eOk = 0, eSize, eArchitectureBytes, eDiscoveryBytes, eRange };
ImageCheck VerifyImage(const uint8_t* image, size_t size, const ProviderLayout& layout,
    bool allowPatched = false) noexcept;

// One byte edit inside the image, with the value expected before it and the value written.
struct ByteEdit { uint32_t rva; uint8_t before; uint8_t after; };
// The gate edits a layout implies (two, or three with a Vulkan export), sorted by rva.
void GateEdits(const ProviderLayout& layout, std::vector<ByteEdit>& out) noexcept;
// Pure over a writable byte view: all-or-nothing (every `before` byte is checked first). RevertEdits
// restores `before` wherever `after` is still present.
bool ApplyEdits(uint8_t* image, size_t size, const std::vector<ByteEdit>& edits) noexcept;
void RevertEdits(uint8_t* image, size_t size, const std::vector<ByteEdit>& edits) noexcept;

// Plain LZ4 block decoder (no frame). Returns true only if exactly dstSize bytes were produced. With
// `literal`, also reports which input byte is the literal that produced output byte `wanted` (SIZE_MAX
// when that byte came out of a match copy). A null `dst` writes nothing: the sequences are walked with
// the same bounds checks only until output byte `wanted` has been placed, and true means it was reached.
bool Lz4BlockDecompress(const uint8_t* src, size_t srcSize, uint8_t* dst, size_t dstSize,
    size_t wanted = SIZE_MAX, size_t* literal = nullptr) noexcept;

// In-place kernel retargeting, planned purely over a byte view and applied separately.
enum class Retarget : uint32_t
{
    eOk = 0,
    eNoContainers,    // no fatbin with an sm_89 (or sm_86) PTX entry anywhere in the image
    eLayout,          // an entry after the sm_89 PTX is not a cubin, or a header field is malformed
    eCompression,     // the PTX entry is not the LZ4-compressed form every reviewed build uses
    eLz4,             // the compressed block does not decode to its declared size
    eTarget,          // the PTX does not carry exactly one ".target sm_89" directive
    eSharedLiteral,   // the target digit is not an independent literal, so it cannot be edited in place
    eBudget,          // more containers or edits than any reviewed build has
};
struct RetargetPlan
{
    std::vector<ByteEdit> edits;   // sorted by rva; empty when everything was already retargeted
    uint32_t containers = 0;       // containers carrying an sm_89 or sm_86 PTX entry
    uint32_t retargeted = 0;       // containers this plan changes
    uint32_t alreadyRetargeted = 0;
    uint32_t cubinsHidden = 0;     // trailing sm_89 cubins dropped by shortening the payload length
};
Retarget PlanRetarget(const uint8_t* image, size_t size, RetargetPlan& out) noexcept;
const wchar_t* RetargetName(Retarget value) noexcept;

enum class State : uint32_t { eIdle = 0, ePrepared, ePublished, eRolledBack, eFailed };
struct Status
{
    State state = State::eIdle;
    ImageCheck imageCheck = ImageCheck::eOk;
    Discovery discovery = Discovery::eOk;  // how the gate bytes were located in the mapped provider
    Retarget retarget = Retarget::eOk;     // outcome of the last kernel plan
    uint32_t containers = 0;               // kernel containers found in the published provider
    uint32_t retargeted = 0;               // ... edited in place
    uint32_t cubinsHidden = 0;
    bool kernelsRetargeted = false;        // every container in the image is sm_86 now
    uint64_t retargetMicroseconds = 0;     // wall time of the last RetargetKernels that did work
    ProviderLayout layout{};               // the discovered layout actually published
    std::wstring failure;
};

void Prepare() noexcept;
// Apply the gate edits to the loaded provider and prove its kernels retargetable. Must run before the
// NGX runtime validates the snippet, i.e. from the loader DLL-loaded notification for the provider.
// The kernel plan is kept for RetargetKernels, so the containers are decoded once.
bool Publish(HMODULE provider) noexcept;
// Apply the kept kernel plan to the published provider in place. Call at the pre-create point, AFTER
// midpoint_fix::PatchProvider: the temporal fix verifies the original bytes of its source container
// before rebuilding it (into its own allocation, so the plan's bytes stay valid), and the rebuilt copy
// is emitted for sm_86 by midpoint_fix itself. Refuses an image other than the published one; a second
// call on the same image returns immediately.
bool RetargetKernels(HMODULE provider) noexcept;
// Restore every edited byte.
void Rollback() noexcept;
Status CurrentStatus() noexcept;

// Live view of the provider image the feature is actually being created on, read at the NGX
// CreateFeature pre-call. For a different mapping than the published one, every gate site is verified
// against the published layout (each may be original or already patched) and the kernels are proven
// retargetable before anything is written; only then does it become the published image. Returns
// false, and changes nothing, for an image that fails that verification.
struct Live
{
    uintptr_t providerBase = 0, publishedBase = 0;
    uint8_t archByte = 0, discoveryByte = 0, discoveryVulkanByte = 0;
    bool healed = false;
};
bool Inspect(HMODULE provider, Live& out) noexcept;
}
