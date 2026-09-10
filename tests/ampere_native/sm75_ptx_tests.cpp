#include "../../source/native/sm75_ptx.h"

#include <cstdio>
#include <filesystem>
#include <fstream>
#include <iterator>
#include <initializer_list>
#include <string>

using namespace sm75_ptx;
static int gFailures = 0;
#define EXPECT(cond) do { if (!(cond)) { std::printf("FAIL %s:%d %s\n", __FILE__, __LINE__, #cond); ++gFailures; } } while (0)

static std::string Module(const std::string& body)
{
    return ".version 8.4\n.target sm_89\n.address_size 64\n.visible .entry test()\n{\n" + body + "\n}\n";
}

static void Refuse(const std::string& source, Result result)
{
    Lowered out{"stale", 1, 2, 3, 4};
    EXPECT(Lower(source, out) == result);
    EXPECT(out.ptx.empty());
    EXPECT(out.minmaxScalar == 0 && out.minmaxPacked == 0 && out.convertPacked == 0 && out.mmaK16 == 0);
}

int main(int argc, char** argv)
{
    if (argc != 1)
    {
        if (argc != 3)
        {
            std::fprintf(stderr, "Usage: sm75_ptx_tests [input.ptx output.ptx]\n");
            return 2;
        }
        std::error_code error;
        if (std::filesystem::equivalent(argv[1], argv[2], error))
        {
            std::fprintf(stderr, "Input and output must differ\n");
            return 2;
        }
        std::ifstream input(argv[1], std::ios::binary);
        if (!input) return 2;
        const std::string original((std::istreambuf_iterator<char>(input)), std::istreambuf_iterator<char>());
        if (input.bad()) return 2;
        Lowered lowered;
        const Result result = Lower(original, lowered);
        std::printf("result=%d scalar=%zu packed=%zu cvt=%zu mma=%zu\n", static_cast<int>(result),
            lowered.minmaxScalar, lowered.minmaxPacked, lowered.convertPacked, lowered.mmaK16);
        if (result != Result::eOk) return 1;
        std::ofstream output(argv[2], std::ios::binary);
        output.write(lowered.ptx.data(), static_cast<std::streamsize>(lowered.ptx.size()));
        output.close();
        return output ? 0 : 2;
    }
    Lowered out;
    const std::string unchanged = Module("ret;");
    EXPECT(Lower(unchanged, out) == Result::eOk);
    std::string expected = unchanged;
    expected.replace(expected.find("sm_89"), 5, "sm_75");
    EXPECT(out.ptx == expected);
    EXPECT(Lower(out.ptx, out) == Result::eOk);
    EXPECT(out.ptx == expected);

    for (const std::string op : {"min", "max"})
    {
        EXPECT(Lower(Module("{ " + op + ".f16 %h0, %h0, %h1; }"), out) == Result::eOk);
        EXPECT(out.minmaxScalar == 1 && out.minmaxPacked == 0);
        EXPECT(out.ptx.find("cvt.f32.f16 %sm75_a, %h0;\ncvt.f32.f16 %sm75_b, %h1;\n" + op +
            ".f32 %sm75_r, %sm75_a, %sm75_b;\ncvt.rn.f16.f32 %h0, %sm75_r;") != std::string::npos);
        EXPECT(out.ptx.find(".ftz") == std::string::npos);
        EXPECT(Lower(Module(op + ".f16x2 %r0, %r0, %r1;"), out) == Result::eOk);
        EXPECT(out.minmaxPacked == 1);
        EXPECT(out.ptx.find("mov.b32 {%sm75_al, %sm75_ah}, %r0;") != std::string::npos);
        EXPECT(out.ptx.find("mov.b32 {%sm75_bl, %sm75_bh}, %r1;") != std::string::npos);
        EXPECT(out.ptx.find("cvt.f32.f16 %sm75_a, %sm75_ah;") != std::string::npos);
        EXPECT(out.ptx.find("mov.b32 %r0, {%sm75_lo, %sm75_hi};") != std::string::npos);
    }

    EXPECT(Lower(Module("{ cvt.rn.f16x2.f32\n%r0, %f1,\n%f2;\n}\nret;"), out) == Result::eOk);
    EXPECT(out.convertPacked == 1);
    EXPECT(out.ptx.find("cvt.rn.f16.f32 %sm75_lo, %f2;\ncvt.rn.f16.f32 %sm75_hi, %f1;\nmov.b32 %r0, {%sm75_lo, %sm75_hi};") != std::string::npos);
    EXPECT(out.ptx.find("}\n}\nret;") != std::string::npos);

    EXPECT(Lower(Module("mma.sync.aligned.m16n8k16.row.col.f16.f16.f16.f16\n{%a2,%a3}, {%a0,%a1,%a2,%a3}, {%b0,%b1}, {%a2,%a3};"), out) == Result::eOk);
    EXPECT(out.mmaK16 == 1);
    EXPECT(out.ptx.find("{%sm75_d0, %sm75_d1}, {%a0, %a1}, {%b0}, {%a2, %a3};") != std::string::npos);
    EXPECT(out.ptx.find("{%a2, %a3}, {%a2, %a3}, {%b1}, {%sm75_d0, %sm75_d1};") != std::string::npos);
    EXPECT(out.ptx.find("m16n8k16") == std::string::npos);

    EXPECT(Lower(Module(".reg .f32 %sm75_a;\n.reg .b32 %sm75__r<4>;\nmin.f16 %h0,%h1,%h2; max.f16 %h0,%h1,%h2;"), out) == Result::eOk);
    EXPECT(out.minmaxScalar == 2);
    EXPECT(out.ptx.find(".reg .f32 %sm75___a, %sm75___b, %sm75___r;") != std::string::npos);

    const std::string trivia = "// min.nan.f16 %h0,%h1,%h2;\n/* mma.bad.m16n8k16 */\n.file 1 \"cvt.bad.f16x2\"\n";
    EXPECT(Lower(trivia + Module("ld.shared::cta.b32 %r0, [%r1];\nret;"), out) == Result::eOk);
    EXPECT(out.ptx.starts_with(trivia));
    EXPECT(out.ptx.find("ld.shared.b32") != std::string::npos);
    EXPECT(Lower(Module("cvta.to.shared::cta %rd0, %rd1;"), out) == Result::eOk);
    EXPECT(out.ptx.find("cvta.to.shared %rd0") != std::string::npos);

    for (const std::string body : {
        "min.nan.f16 %h0,%h1,%h2;", "max.ftz.f16x2 %r0,%r1,%r2;",
        "min.f16 %h0,%h1,0x0000;", "@%p min.f16 %h0,%h1,%h2;",
        "@!%p max.f16x2 %r0,%r1,%r2;", "min.f16 %h0,%h1,%h2",
        "min.f16 %h0,%h1,%h2,%h3;", "cvt.rz.f16x2.f32 %r0,%f0,%f1;",
        "cvt.rn.relu.f16x2.f32 %r0,%f0,%f1;", "cvt.rn.f16x2.f32 %r0,%f0;",
        "mma.sync.aligned.m16n8k16.row.col.f32.f16.f16.f32 {%r0,%r1}, {%r2,%r3,%r4,%r5}, {%r6,%r7}, {%r0,%r1};",
        "mma.sync.aligned.m16n8k16.row.col.f16.f16.f16.f16 {%r0,%r1}, {%r2,%r3}, {%r6,%r7}, {%r0,%r1};"})
        Refuse(Module("min.f16 %h0,%h1,%h2;\n" + body), Result::eUnsupported);

    Refuse("", Result::eTarget);
    Refuse(".target sm_80\n", Result::eTarget);
    Refuse(".target sm_89, texmode_independent\n", Result::eTarget);
    Refuse(".target sm_89\n, texmode_independent\n", Result::eTarget);
    Refuse(".target sm_89\n.target sm_86\n", Result::eTarget);
    Refuse("// .target sm_89\n", Result::eTarget);
    Refuse(Module("/* unfinished"), Result::eSyntax);
    Refuse(Module("\"unfinished"), Result::eSyntax);
    Refuse(Module("{"), Result::eSyntax);
    Refuse(Module("}"), Result::eSyntax);
    Refuse(Module(std::string("ret;\0", 5)), Result::eSyntax);
    EXPECT(Lower(".target sm_86\r\n{ min.f16 %h0, /* x */ %h1, %h2; }\r\n", out) == Result::eOk);
    EXPECT(out.ptx.find(".target sm_75\r\n") == 0);
    std::printf(gFailures ? "sm75_ptx_tests: %d failure(s)\n" : "sm75_ptx_tests: all passed\n", gFailures);
    return gFailures ? 1 : 0;
}
