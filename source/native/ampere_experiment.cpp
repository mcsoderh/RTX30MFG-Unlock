#include "ampere_experiment.h"

#include <dxgi1_6.h>

#include <algorithm>
#include <atomic>
#include <filesystem>
#include <mutex>
#include <vector>

#include "ampere_bundle.h"
#include "cuda_adapter.h"
#include <MinHook.h>
#include "dlssg_provider_policy.h"

#pragma comment(lib, "dxgi.lib")

namespace ampere_experiment
{
namespace
{
std::mutex gMutex;
State gState;

std::wstring ModulePath(HMODULE module) noexcept
{
    std::wstring path(32768, L'\0');
    const DWORD length = GetModuleFileNameW(module, path.data(), static_cast<DWORD>(path.size()));
    path.resize(length < path.size() ? length : 0);
    return path;
}

bool EqualsNoCase(std::wstring_view a, std::wstring_view b) noexcept
{
    return a.size() == b.size()
        && std::equal(a.begin(), a.end(), b.begin(), [](wchar_t x, wchar_t y) {
               return towlower(x) == towlower(y);
           });
}

bool ContainsNoCase(std::wstring_view haystack, std::wstring_view needle) noexcept
{
    return needle.empty()
        || std::search(haystack.begin(), haystack.end(), needle.begin(), needle.end(),
               [](wchar_t x, wchar_t y) { return towlower(x) == towlower(y); }) != haystack.end();
}

bool ReadFileVersion(const std::filesystem::path& path, VS_FIXEDFILEINFO& version) noexcept
{
    DWORD ignored = 0;
    const DWORD size = GetFileVersionInfoSizeW(path.c_str(), &ignored);
    if (!size) return false;
    std::vector<uint8_t> blob(size);
    if (!GetFileVersionInfoW(path.c_str(), 0, size, blob.data())) return false;
    VS_FIXEDFILEINFO* info = nullptr;
    UINT length = 0;
    if (!VerQueryValueW(blob.data(), L"\\", reinterpret_cast<void**>(&info), &length) || !info)
        return false;
    version = *info;
    return true;
}

// Installed NVIDIA driver, read from the system NVAPI component by absolute path. An in-process
// NvAPI query is hookable and some wrapper chains (DLSS Enabler was observed doing this) report a
// spoofed version; a file-version read of the system binary is not. 32.0.16.1074 -> 61074 (610.74).
bool DriverVersion(uint32_t& version) noexcept
{
    wchar_t systemDirectory[MAX_PATH]{};
    if (!GetSystemDirectoryW(systemDirectory, MAX_PATH)) return false;
    const std::wstring path = std::wstring(systemDirectory) + L"\\nvapi64.dll";
    VS_FIXEDFILEINFO info{};
    if (!ReadFileVersion(path, info)) return false;
    wchar_t digits[32]{};
    swprintf_s(digits, L"%u%u", HIWORD(info.dwFileVersionLS), LOWORD(info.dwFileVersionLS));
    std::wstring text(digits);
    if (text.size() > 5) text = text.substr(text.size() - 5);
    version = static_cast<uint32_t>(_wtoi(text.c_str()));
    return version != 0;
}

// Exactly one NVIDIA hardware adapter; returns its LUID.
bool SingleNvidiaAdapter(uint64_t& luid) noexcept
{
    IDXGIFactory6* factory = nullptr;
    if (FAILED(CreateDXGIFactory2(0, IID_PPV_ARGS(&factory)))) return false;
    uint32_t found = 0;
    for (UINT i = 0;; ++i)
    {
        IDXGIAdapter1* adapter = nullptr;
        if (factory->EnumAdapters1(i, &adapter) == DXGI_ERROR_NOT_FOUND) break;
        DXGI_ADAPTER_DESC1 desc{};
        adapter->GetDesc1(&desc);
        const bool usable = (desc.Flags & DXGI_ADAPTER_FLAG_SOFTWARE) == 0 && desc.VendorId == 0x10DE;
        if (usable)
        {
            ++found;
            luid = static_cast<uint64_t>(desc.AdapterLuid.LowPart)
                | (static_cast<uint64_t>(static_cast<uint32_t>(desc.AdapterLuid.HighPart)) << 32);
        }
        adapter->Release();
    }
    factory->Release();
    return found == 1;
}

// Packed file version of any module, for ordering provider candidates. Zero when unreadable.
uint64_t FileVersionOf(const std::filesystem::path& path) noexcept
{
    VS_FIXEDFILEINFO info{};
    if (!ReadFileVersion(path, info)) return 0;
    return (static_cast<uint64_t>(HIWORD(info.dwFileVersionMS)) << 48)
        | (static_cast<uint64_t>(LOWORD(info.dwFileVersionMS)) << 32)
        | (static_cast<uint64_t>(HIWORD(info.dwFileVersionLS)) << 16)
        | static_cast<uint64_t>(LOWORD(info.dwFileVersionLS));
}

// Every DLSS-G provider already present on this machine. A game ships one copy and it can be years
// older than the Streamline DLSS-G plugin the NGX runtime actually loads from its OTA cache; pairing
// a 2.14 plugin with a 310.1.0 provider produced frames but a black screen, so the newest supported
// provider the user already has is selected instead. Nothing is downloaded and nothing is distributed.
void CollectProviderCandidates(const std::filesystem::path& gameDirectory,
    std::vector<std::filesystem::path>& out) noexcept
{
    std::error_code error;
    auto consider = [&](std::filesystem::path candidate) noexcept {
        if (std::filesystem::is_regular_file(candidate, error)) out.push_back(std::move(candidate));
        error.clear();
    };
    consider(gameDirectory / L"nvngx_dlssg.dll");
    // The driver's own copy, beside the NGX runtime core in the active driver store package.
    HMODULE runtime = GetModuleHandleW(L"_nvngx.dll");
    wchar_t runtimePath[MAX_PATH]{};
    if (runtime && GetModuleFileNameW(runtime, runtimePath, MAX_PATH))
        consider(std::filesystem::path(runtimePath).parent_path() / L"nvngx_dlssg.dll");
    // NGX OTA cache: NVIDIA delivers provider builds here to pair with the Streamline plugins it
    // also delivers, which is exactly the pairing the runtime ends up using.
    wchar_t programData[MAX_PATH]{};
    if (!GetEnvironmentVariableW(L"ProgramData", programData, MAX_PATH)) return;
    const std::filesystem::path versions = std::filesystem::path(programData)
        / L"NVIDIA" / L"NGX" / L"models" / L"dlssg" / L"versions";
    for (std::filesystem::directory_iterator version(versions, error), end;
         !error && version != end; version.increment(error))
    {
        const std::filesystem::path files = version->path() / L"files";
        for (std::filesystem::directory_iterator file(files, error), last;
             !error && file != last; file.increment(error))
        {
            if (file->is_regular_file(error)) consider(file->path());
        }
        error.clear();
    }
}

// LoadLibraryExW is the single entry every LoadLibrary variant funnels into (kernelbase). The hook
// touches only requests for a DLSS-G provider file and maps the selected provider instead.
using LoadLibraryExW_t = HMODULE(WINAPI*)(LPCWSTR, HANDLE, DWORD);
LoadLibraryExW_t gRealLoadLibraryExW = nullptr;
std::wstring gRedirectTarget;                 // canonical path of the selected provider
std::wstring gSelectedProvider;               // same, readable from the loader callback
std::atomic<bool> gRedirectArmed{false};
std::atomic<uint32_t> gRedirectCount{0};
std::mutex gRedirectMutex;
std::wstring gRedirectedFrom;

bool IsProviderRequest(std::wstring_view path) noexcept
{
    const size_t slash = path.find_last_of(L"\\/");
    const std::wstring_view name = slash == std::wstring_view::npos ? path : path.substr(slash + 1);
    if (EqualsNoCase(name, L"nvngx_dlssg.dll")) return true;
    // NGX OTA cache: ...\NVIDIA\NGX\models\dlssg\versions\<n>\files\<arch>_<appid>.bin
    return ContainsNoCase(path, L"\\ngx\\models\\dlssg\\");
}

HMODULE WINAPI LoadLibraryExWHook(LPCWSTR fileName, HANDLE file, DWORD flags) noexcept
{
    if (fileName && gRedirectArmed.load(std::memory_order_acquire))
    {
        const std::wstring_view requested(fileName);
        if (IsProviderRequest(requested) && !EqualsNoCase(requested, gRedirectTarget))
        {
            gRedirectCount.fetch_add(1, std::memory_order_relaxed);
            {
                std::lock_guard<std::mutex> guard(gRedirectMutex);
                gRedirectedFrom.assign(requested);
            }
            return gRealLoadLibraryExW(gRedirectTarget.c_str(), file, flags);
        }
    }
    return gRealLoadLibraryExW(fileName, file, flags);
}

bool InstallProviderRedirect(const std::wstring& target) noexcept
{
    if (gRedirectArmed.load(std::memory_order_acquire)) return true;
    HMODULE kernelbase = GetModuleHandleW(L"kernelbase.dll");
    void* entry = kernelbase ? reinterpret_cast<void*>(GetProcAddress(kernelbase, "LoadLibraryExW")) : nullptr;
    if (!entry) return false;
    MH_STATUS status = MH_Initialize();
    if (status != MH_OK && status != MH_ERROR_ALREADY_INITIALIZED) return false;
    void* trampoline = nullptr;
    if (MH_CreateHook(entry, reinterpret_cast<void*>(&LoadLibraryExWHook), &trampoline) != MH_OK || !trampoline)
        return false;
    gRedirectTarget = target;
    gRealLoadLibraryExW = reinterpret_cast<LoadLibraryExW_t>(trampoline);
    if (MH_EnableHook(entry) != MH_OK) { MH_RemoveHook(entry); return false; }
    gRedirectArmed.store(true, std::memory_order_release);
    return true;
}
}  // namespace

bool Initialize(uint32_t requestedMultiplier) noexcept
{
    std::lock_guard<std::mutex> guard(gMutex);
    gState = State{};

    ampere_policy::Inputs in{};
    in.requestedMultiplier = requestedMultiplier;

    auto decide = [&]() noexcept {
        const ampere_policy::Decision decision = ampere_policy::Decide(in);
        gState.admitted = decision.admitted;
        gState.reason = decision.reason;
        return decision.admitted;
    };
    // Cheap gate first, so a refused multiplier does no hardware queries.
    if (in.requestedMultiplier < 2u || in.requestedMultiplier > 5u) return decide();

    uint64_t luid = 0;
    in.graphicsDeviceQueried = SingleNvidiaAdapter(luid);
    in.nvidiaAdapter = in.graphicsDeviceQueried;
    gState.admittedLuid = luid;
    if (in.graphicsDeviceQueried)
    {
        uint32_t devices = 0, matches = 0;
        int major = 0, minor = 0;
        in.cudaAvailable = cuda_adapter::QueryDevices(luid, devices, matches, major, minor, &in.turingRtx);
        in.nvidiaCudaDevices = devices;
        in.luidMatches = matches;
        in.ccMajor = major;
        in.ccMinor = minor;
    }
    uint32_t driver = 0;
    if (DriverVersion(driver)) gState.driverObserved = driver;

    ampere_bundle::Prepare();
    gState.prepared = true;
    const bool admitted = decide();
    if (!admitted) return false;
    if (in.turingRtx && in.ccMajor == 7 && in.ccMinor == 5)
    {
        gState.turing = true;
        ampere_bundle::SetTargetArchitecture(0x160u);
    }

    // Which provider this process should use: the newest build already on this machine among the
    // builds this mod is known to drive. The game's own copy is often much older than the Streamline
    // DLSS-G plugin the NGX runtime loads from its OTA cache, and that mismatch generates frames that
    // present black; an unlisted build is one whose DLSS-G route the mod will not commit to.
    const std::filesystem::path executablePath(ModulePath(nullptr));
    std::vector<std::filesystem::path> candidates;
    CollectProviderCandidates(executablePath.parent_path(), candidates);
    std::filesystem::path best;
    uint64_t bestVersion = 0;
    for (const auto& candidate : candidates)
    {
        const uint64_t version = FileVersionOf(candidate);
        const dlssg_provider_policy::VersionTriplet triplet{
            static_cast<uint16_t>((version >> 48) & 0xFFFF),
            static_cast<uint16_t>((version >> 32) & 0xFFFF),
            static_cast<uint16_t>((version >> 16) & 0xFFFF)};
        if (!dlssg_provider_policy::IsSupportedVersion(triplet)) continue;
        if (version > bestVersion) { bestVersion = version; best = candidate; }
    }
    if (bestVersion == 0)
    {
        gState.detail = L"No supported DLSS-G provider found on this machine";
        return true;   // publication simply never happens; the game runs untouched
    }
    std::error_code error;
    gState.providerSelected = std::filesystem::weakly_canonical(best, error).wstring();
    if (error) { gState.providerSelected = best.wstring(); error.clear(); }
    gState.providerSelectedVersion = bestVersion;
    gSelectedProvider = gState.providerSelected;
    const std::filesystem::path gameCopy = executablePath.parent_path() / L"nvngx_dlssg.dll";
    if (!EqualsNoCase(best.wstring(), gameCopy.wstring()) && !InstallProviderRedirect(gState.providerSelected))
        gState.detail = L"Provider redirect hook failed";
    return true;
}

void OnProviderLoaded(HMODULE module, std::wstring_view baseName, std::wstring_view fullPath) noexcept
{
    // Loader lock: no file I/O. A DLSS-G provider does not have to be called nvngx_dlssg.dll: NVIDIA's
    // own NGX OTA cache stores provider builds as <arch>_<appid>.bin, and that is what the loader
    // reports when the runtime is pointed at one. Match the selected provider by path as well.
    if (!module || baseName.empty()) return;
    const bool namedProvider = EqualsNoCase(baseName, L"nvngx_dlssg.dll");
    const bool selectedProvider = !fullPath.empty() && !gSelectedProvider.empty()
        && EqualsNoCase(fullPath, gSelectedProvider);
    if (!namedProvider && !selectedProvider) return;
    std::lock_guard<std::mutex> guard(gMutex);
    if (!gState.admitted || !gState.prepared || gState.published || gState.restartRequired) return;
    // ampere_bundle::Publish decides: it must find every gate site and re-verify its bytes, and prove
    // every kernel container retargetable, or nothing is written.
    gState.published = ampere_bundle::Publish(module);
    if (!gState.published) gState.detail = ampere_bundle::CurrentStatus().failure;
}

bool ConfirmAdapter(uint64_t activeLuid) noexcept
{
    std::lock_guard<std::mutex> guard(gMutex);
    if (!gState.published) return gState.admitted && !gState.restartRequired;
    if (activeLuid && gState.admittedLuid && activeLuid == gState.admittedLuid) return true;
    ampere_bundle::Rollback();
    gState.published = false;
    gState.admitted = false;
    gState.restartRequired = true;
    gState.reason = ampere_policy::Reason::eAdapterChanged;
    gState.detail = L"Feature creation targeted a different adapter; restart required";
    return false;
}

void Shutdown() noexcept
{
    std::lock_guard<std::mutex> guard(gMutex);
    if (gState.published) ampere_bundle::Rollback();
    gState.published = false;
}

bool IsAdmitted() noexcept
{
    std::lock_guard<std::mutex> guard(gMutex);
    return gState.admitted;
}

bool IsPublished() noexcept
{
    std::lock_guard<std::mutex> guard(gMutex);
    return gState.published;
}

State Current() noexcept
{
    std::lock_guard<std::mutex> redirect(gRedirectMutex);
    std::lock_guard<std::mutex> state(gMutex);
    gState.providerRedirects = gRedirectCount.load(std::memory_order_relaxed);
    gState.redirectedFrom = gRedirectedFrom;
    return gState;
}
}  // namespace ampere_experiment
