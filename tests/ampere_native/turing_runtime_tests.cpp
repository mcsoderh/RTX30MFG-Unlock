#include "../../source/native/turing_runtime.h"
#include <cstdio>
#include <cstring>
#include <vector>

static int gFailures = 0;
static void Check(bool ok, const char* label)
{
    if (!ok) { std::printf("FAIL %s\n", label); ++gFailures; }
}

int main()
{
    std::vector<uint8_t> image(0x51B00, 0);
    const uint8_t site[] = {0x83, 0xF8, 0x59, 0x7E, 0x21};
    std::memcpy(image.data() + 0x51928, site, sizeof site);
    std::memcpy(image.data() + 0x51A67, site, sizeof site);
    std::vector<ampere_bundle::ByteEdit> edits;
    Check(turing_runtime::PlanSelectors(image.data(), image.size(), edits) && edits.size() == 4,
        "validated CreateImpl selectors");
    Check(edits[0].rva == 0x5192B && edits[0].before == 0x7E && edits[0].after == 0x90, "DL1 jle nop");
    Check(edits[2].rva == 0x51A6A && edits[2].before == 0x7E && edits[2].after == 0x90, "DL2 jle nop");
    image[0x5192B] = 0x7C;
    Check(!turing_runtime::PlanSelectors(image.data(), image.size(), edits) && edits.empty(),
        "Ampere/Ada jcc shape rejected");
    image[0x5192B] = 0x90;
    image[0x5192C] = 0x90;
    Check(turing_runtime::PlanSelectors(image.data(), image.size(), edits) && edits.size() == 2,
        "already routed Turing selectors accepted");
    image[0x51928] = 0x81;
    Check(!turing_runtime::PlanSelectors(image.data(), image.size(), edits), "cmp mismatch rejected");

    uint8_t lea[7] = {0x48, 0x8D, 0x15, 0, 0, 0, 0};
    const int32_t disp = 0x1988E0 - (0x64FA4 + 7);
    std::memcpy(lea + 3, &disp, 4);
    uint32_t target = 0;
    Check(turing_runtime::LeaTarget(lea, 0x64FA4, target) && target == 0x1988E0, "network lea rdx target");
    lea[2] = 0x05;
    const int32_t capture = 0x713450 - (0x22DA8 + 7);
    std::memcpy(lea + 3, &capture, 4);
    Check(turing_runtime::LeaTarget(lea, 0x22DA8, target) && target == 0x713450, "capture lea rax target");
    lea[0] = 0x4C;
    Check(!turing_runtime::LeaTarget(lea, 0x22DA8, target), "non-rex.w lea rejected");
    Check(!turing_runtime::Ready(), "relocation requires live provider");
    Check(!turing_runtime::Relocate(nullptr, 0x745000u), "null provider rejected");

    std::printf(gFailures ? "turing_runtime_tests: %d failure(s)\n" : "turing_runtime_tests: all passed\n",
        gFailures);
    return gFailures ? 1 : 0;
}
