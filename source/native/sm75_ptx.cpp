#include "sm75_ptx.h"

#include <array>
#include <cctype>
#include <utility>
#include <vector>

namespace sm75_ptx
{
namespace
{
struct Token
{
    size_t begin;
    size_t end;
    std::string_view text;
};

bool Word(char c)
{
    return std::isalnum(static_cast<unsigned char>(c)) || c == '_' || c == '.' || c == '%' || c == '$';
}

bool Lex(std::string_view text, std::vector<Token>& tokens)
{
    for (size_t i = 0; i < text.size();)
    {
        if (text[i] == '\0') return false;
        if (std::isspace(static_cast<unsigned char>(text[i]))) { ++i; continue; }
        if (text.substr(i, 2) == "//")
        {
            const auto end = text.find('\n', i + 2);
            i = end == text.npos ? text.size() : end;
            continue;
        }
        if (text.substr(i, 2) == "/*")
        {
            const auto end = text.find("*/", i + 2);
            if (end == text.npos) return false;
            i = end + 2;
            continue;
        }
        const size_t begin = i++;
        if (text[begin] == '"')
        {
            bool closed = false;
            while (i < text.size())
            {
                if (text[i] == '\\') { i += 2; continue; }
                if (text[i++] == '"') { closed = true; break; }
            }
            if (!closed) return false;
        }
        else if (Word(text[begin]))
        {
            while (i < text.size() && Word(text[i])) ++i;
        }
        tokens.push_back({begin, i, text.substr(begin, i - begin)});
    }
    return true;
}

bool Register(std::string_view s)
{
    if (s.size() < 2 || s[0] != '%') return false;
    for (size_t i = 1; i < s.size(); ++i)
        if (!Word(s[i]) || s[i] == '%') return false;
    return true;
}

class Operands
{
public:
    Operands(const std::vector<Token>& tokens, size_t start) : next(start), tokens_(tokens) {}
    bool Take(std::string_view text)
    {
        if (next == tokens_.size() || tokens_[next].text != text) return false;
        ++next;
        return true;
    }
    bool Reg(std::string& out)
    {
        if (next == tokens_.size() || !Register(tokens_[next].text)) return false;
        out = tokens_[next++].text;
        return true;
    }
    template<size_t N> bool Group(std::array<std::string, N>& out)
    {
        if (!Take("{")) return false;
        for (size_t i = 0; i < N; ++i)
            if ((i && !Take(",")) || !Reg(out[i])) return false;
        return Take("}");
    }
    size_t next;
private:
    const std::vector<Token>& tokens_;
};

std::string Pair(const std::string& a, const std::string& b)
{
    return "{" + a + ", " + b + "}";
}
}

Result Lower(std::string_view original, Lowered& out) noexcept
{
    try
    {
        Lowered lowered;
        std::vector<Token> tokens;
        if (original.find('\0') != original.npos || !Lex(original, tokens))
        {
            out = {};
            return Result::eSyntax;
        }
        std::string prefix = "%sm75_";
        while (original.find(prefix) != original.npos) prefix += '_';
        const auto t = [&](const char* name) { return prefix + name; };
        size_t copied = 0;
        size_t targets = 0;
        int depth = 0;
        const auto fail = [&](Result result) { out = {}; return result; };
        const auto emit = [&](size_t begin, size_t end, const std::string& replacement)
        {
            lowered.ptx.append(original.substr(copied, begin - copied));
            lowered.ptx += replacement;
            copied = end;
        };
        for (size_t i = 0; i < tokens.size(); ++i)
        {
            const auto op = tokens[i].text;
            if (op == "{") ++depth;
            if (op == "}" && --depth < 0) return fail(Result::eSyntax);
            if (op == ".target")
            {
                if (++targets != 1 || depth != 0 || i + 1 == tokens.size()) return fail(Result::eTarget);
                const auto& arch = tokens[++i];
                if (arch.text != "sm_89" && arch.text != "sm_86" && arch.text != "sm_75")
                    return fail(Result::eTarget);
                if (i + 1 < tokens.size() && original.substr(arch.end, tokens[i + 1].begin - arch.end).find('\n') == original.npos)
                    return fail(Result::eTarget);
                if (i + 1 < tokens.size() && tokens[i + 1].text == ",") return fail(Result::eTarget);
                emit(arch.begin, arch.end, "sm_75");
                continue;
            }
            const bool minmax = (op.starts_with("min.") || op.starts_with("max.")) && op.find("f16") != op.npos;
            const bool convert = op.starts_with("cvt.") && op.find("f16x2") != op.npos;
            const bool mma = op.starts_with("mma.") && op.find("m16n8k16") != op.npos;
            if (!minmax && !convert && !mma)
            {
                if (op.ends_with(".shared") && i + 3 < tokens.size() && tokens[i + 1].text == ":" &&
                    tokens[i + 2].text == ":" && (tokens[i + 3].text == "cta" || tokens[i + 3].text.starts_with("cta.")))
                {
                    emit(tokens[i].begin, tokens[i + 3].end, std::string(op) + std::string(tokens[i + 3].text.substr(3)));
                    i += 3;
                }
                continue;
            }
            if (!depth || !i) return fail(Result::eUnsupported);
            const auto previous = tokens[i - 1].text;
            if (previous != "{" && previous != "}" && previous != ";" && previous != ":")
                return fail(Result::eUnsupported);
            Operands args(tokens, i + 1);
            std::string body = "{\n";
            const auto line = [&](const std::string& s) { body += s + "\n"; };
            if (minmax || convert)
            {
                const bool packed = op == "min.f16x2" || op == "max.f16x2";
                if (minmax && !packed && op != "min.f16" && op != "max.f16") return fail(Result::eUnsupported);
                if (convert && op != "cvt.rn.f16x2.f32") return fail(Result::eUnsupported);
                std::string d, a, b;
                if (!args.Reg(d) || !args.Take(",") || !args.Reg(a) || !args.Take(",") || !args.Reg(b) || !args.Take(";"))
                    return fail(Result::eUnsupported);
                if (convert)
                {
                    line(".reg .b16 " + t("lo") + ", " + t("hi") + ";");
                    line("cvt.rn.f16.f32 " + t("lo") + ", " + b + ";");
                    line("cvt.rn.f16.f32 " + t("hi") + ", " + a + ";");
                    line("mov.b32 " + d + ", " + Pair(t("lo"), t("hi")) + ";");
                    ++lowered.convertPacked;
                }
                else
                {
                    line(".reg .f32 " + t("a") + ", " + t("b") + ", " + t("r") + ";");
                    if (packed)
                    {
                        line(".reg .b16 " + t("al") + ", " + t("ah") + ", " + t("bl") + ", " + t("bh") + ", " + t("lo") + ", " + t("hi") + ";");
                        line("mov.b32 " + Pair(t("al"), t("ah")) + ", " + a + ";");
                        line("mov.b32 " + Pair(t("bl"), t("bh")) + ", " + b + ";");
                    }
                    for (int lane = 0; lane < (packed ? 2 : 1); ++lane)
                    {
                        line("cvt.f32.f16 " + t("a") + ", " + (packed ? t(lane ? "ah" : "al") : a) + ";");
                        line("cvt.f32.f16 " + t("b") + ", " + (packed ? t(lane ? "bh" : "bl") : b) + ";");
                        line(std::string(op.substr(0, 3)) + ".f32 " + t("r") + ", " + t("a") + ", " + t("b") + ";");
                        line("cvt.rn.f16.f32 " + (packed ? t(lane ? "hi" : "lo") : d) + ", " + t("r") + ";");
                    }
                    if (packed)
                    {
                        line("mov.b32 " + d + ", " + Pair(t("lo"), t("hi")) + ";");
                        ++lowered.minmaxPacked;
                    }
                    else ++lowered.minmaxScalar;
                }
            }
            else
            {
                if (op != "mma.sync.aligned.m16n8k16.row.col.f16.f16.f16.f16") return fail(Result::eUnsupported);
                std::array<std::string, 2> d, b, c;
                std::array<std::string, 4> a;
                if (!args.Group(d) || !args.Take(",") || !args.Group(a) || !args.Take(",") ||
                    !args.Group(b) || !args.Take(",") || !args.Group(c) || !args.Take(";")) return fail(Result::eUnsupported);
                line(".reg .b32 " + t("d0") + ", " + t("d1") + ";");
                const std::string k8 = "mma.sync.aligned.m16n8k8.row.col.f16.f16.f16.f16 ";
                line(k8 + Pair(t("d0"), t("d1")) + ", " + Pair(a[0], a[1]) + ", {" + b[0] + "}, " + Pair(c[0], c[1]) + ";");
                line(k8 + Pair(d[0], d[1]) + ", " + Pair(a[2], a[3]) + ", {" + b[1] + "}, " + Pair(t("d0"), t("d1")) + ";");
                ++lowered.mmaK16;
            }
            body += "}";
            emit(tokens[i].begin, tokens[args.next - 1].end, body);
            i = args.next - 1;
        }
        if (depth) return fail(Result::eSyntax);
        if (targets != 1) return fail(Result::eTarget);
        lowered.ptx.append(original.substr(copied));
        out = std::move(lowered);
        return Result::eOk;
    }
    catch (...)
    {
        out = {};
        return Result::eResource;
    }
}
}
