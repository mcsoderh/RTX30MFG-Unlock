// Refusal contract for the Ampere runtime glue, machine-independent: an unsupported multiplier must
// refuse before any hardware query, and publication must stay inert without admission.
// `ampere_experiment_tests --check` additionally evaluates this machine and prints the admission
// reason (exit 0 always; the report is the answer).
#include "../../source/native/ampere_experiment.h"
#include <cstdio>
#include <cwchar>

static int gFailures = 0;
static void Check(bool ok, const char* what) {
    if (!ok) { std::printf("FAIL %s\n", what); ++gFailures; }
}

static int SelfCheck() {
    const bool admitted = ampere_experiment::Initialize(2u);
    const ampere_experiment::State state = ampere_experiment::Current();
    std::wprintf(L"admitted=%d\nreason=%s\nprepared=%d\nluid=0x%016llX\ndriver=%u\nprovider=%s\ndetail=%s\n",
        admitted ? 1 : 0, ampere_policy::ReasonName(state.reason), state.prepared ? 1 : 0,
        static_cast<unsigned long long>(state.admittedLuid), state.driverObserved,
        state.providerSelected.empty() ? L"(none)" : state.providerSelected.c_str(),
        state.detail.empty() ? L"(none)" : state.detail.c_str());
    ampere_experiment::Shutdown();
    return 0;
}

int wmain(int argc, wchar_t** argv) {
    if (argc > 1 && std::wcscmp(argv[1], L"--check") == 0) return SelfCheck();

    for (uint32_t multiplier : {0u, 1u, 6u}) {
        Check(!ampere_experiment::Initialize(multiplier), "unsupported multiplier refuses");
        const ampere_experiment::State state = ampere_experiment::Current();
        Check(!state.admitted, "not admitted");
        Check(ampere_experiment::IsAdmitted() == state.admitted, "admission query matches snapshot");
        Check(ampere_experiment::IsPublished() == state.published, "publication query matches snapshot");
        Check(state.reason == ampere_policy::Reason::eMultiplierUnsupported, "reason is multiplier-unsupported");
        Check(!state.prepared && !state.published, "nothing prepared or published");
        Check(state.admittedLuid == 0, "no adapter identity gathered before the cheap gate");
    }
    // Publication is inert without admission, even if a module handle is handed to it.
    ampere_experiment::OnProviderLoaded(GetModuleHandleW(nullptr), L"nvngx_dlssg.dll", L"C:\\nvngx_dlssg.dll");
    Check(!ampere_experiment::IsPublished(), "publication refused without admission");
    Check(!ampere_experiment::ConfirmAdapter(1u), "adapter confirmation refuses without admission");
    ampere_experiment::Shutdown();
    Check(!ampere_experiment::IsPublished(), "shutdown leaves publication inactive");

    std::printf(gFailures ? "experiment_tests: %d failure(s)\n" : "experiment_tests: all passed\n", gFailures);
    return gFailures ? 1 : 0;
}
