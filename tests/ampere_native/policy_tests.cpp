// CPU-only policy fixtures. True fields model independently collected facts; they are not claims
// that this machine passed any runtime check.
#include "../../source/native/ampere_policy.h"
#include <cstdio>
#include <cwchar>
#include <initializer_list>
#include <utility>

using namespace ampere_policy;
static int gFailures = 0;
#define EXPECT(cond) do { if (!(cond)) { std::printf("FAIL %s:%d %s\n", __FILE__, __LINE__, #cond); ++gFailures; } } while (0)

static Inputs Fixture()
{
    Inputs in{};
    in.requestedMultiplier = 2;
    in.graphicsDeviceQueried = true;
    in.nvidiaAdapter = true;
    in.cudaAvailable = true;
    in.nvidiaCudaDevices = 1;
    in.luidMatches = 1;
    in.ccMajor = 8;
    in.ccMinor = 6;
    return in;
}

static void expectReason(const Inputs& in, Reason reason, const char* label)
{
    const Decision d = Decide(in);
    if (d.admitted || d.reason != reason) {
        std::printf("FAIL %s: admitted=%d reason=%u expected=%u\n", label, d.admitted,
                    unsigned(d.reason), unsigned(reason));
        ++gFailures;
    }
}

int main()
{
    const Decision ok = Decide(Fixture());
    EXPECT(ok.admitted && ok.reason == Reason::eAdmitted);
    expectReason(Inputs{}, Reason::eMultiplierUnsupported, "empty input");

    struct MissingFact { bool Inputs::* field; Reason reason; const char* label; };
    for (const auto& test : {
        MissingFact{&Inputs::graphicsDeviceQueried, Reason::eGraphicsDeviceQuery, "adapter query failed"},
        MissingFact{&Inputs::cudaAvailable, Reason::eCudaUnavailable, "CUDA absent or enumeration failed"},
        MissingFact{&Inputs::nvidiaAdapter, Reason::eNonNvidia, "active graphics adapter is not NVIDIA"},
    }) {
        Inputs in = Fixture();
        in.*(test.field) = false;
        expectReason(in, test.reason, test.label);
    }

    Inputs in;
    // Multiplier includes the real frame: 2..5 represent 1..4 generated frames and are admitted.
    for (uint32_t m : {0u, 1u, 6u, UINT32_MAX}) {
        in = Fixture(); in.requestedMultiplier = m;
        expectReason(in, Reason::eMultiplierUnsupported, "outside 2x..5x");
    }
    for (uint32_t m : {3u, 4u, 5u}) {
        in = Fixture(); in.requestedMultiplier = m;
        EXPECT(Decide(in).admitted);
    }
    for (uint32_t matches : {0u, 2u, UINT32_MAX}) {
        in = Fixture(); in.luidMatches = matches;
        expectReason(in, Reason::eAdapterNotUnique, "zero/ambiguous graphics LUID matches");
    }
    in = Fixture(); in.nvidiaCudaDevices = 0;
    expectReason(in, Reason::eAdapterNotUnique, "no NVIDIA CUDA devices");
    // Extra GPUs do not invalidate a uniquely identified current adapter.
    in = Fixture(); in.nvidiaCudaDevices = 2;
    EXPECT(Decide(in).admitted);
    for (auto cc : {std::pair{7, 5}, {8, 0}, {8, 9}, {12, 0}, {0, 0}, {8, 7}}) {
        in = Fixture(); in.ccMajor = cc.first; in.ccMinor = cc.second;
        expectReason(in, Reason::eNotAmpereGa10x, "CC not 8.6");
    }
    for (Reason reason : {Reason::eAdmitted, Reason::eMultiplierUnsupported,
        Reason::eGraphicsDeviceQuery, Reason::eCudaUnavailable, Reason::eNonNvidia,
        Reason::eAdapterNotUnique, Reason::eNotAmpereGa10x, Reason::eAdapterChanged}) {
        const wchar_t* name = ReasonName(reason);
        EXPECT(name != nullptr && name[0] != L'\0' && std::wcscmp(name, L"unknown") != 0);
    }
    EXPECT(IsTuringRtx(7, 5, "NVIDIA GeForce RTX 2080 Ti"));
    EXPECT(IsTuringRtx(7, 5, "Quadro RTX 4000"));
    EXPECT(IsTuringRtx(7, 5, "NVIDIA TITAN RTX"));
    EXPECT(!IsTuringRtx(7, 5, "NVIDIA GeForce GTX 1660 Ti"));
    EXPECT(!IsTuringRtx(8, 6, "NVIDIA GeForce RTX 3080"));
    EXPECT(!IsTuringRtx(7, 5, "NOTRTX 2080"));
    in = Fixture(); in.ccMajor = 7; in.ccMinor = 5; in.turingRtx = true;
    EXPECT(Decide(in).admitted && Decide(in).reason == Reason::eAdmitted);
    EXPECT(std::wcscmp(ReasonName(Reason::eTuringRouteUnverified), L"turing-network-route-unverified") == 0);
    EXPECT(std::wcscmp(ReasonName(static_cast<Reason>(999)), L"unknown") == 0);
    std::printf(gFailures ? "policy_tests: %d failure(s)\n" : "policy_tests: all passed\n", gFailures);
    return gFailures ? 1 : 0;
}
