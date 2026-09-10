#pragma once

#include <cstddef>
#include <string>
#include <string_view>

namespace sm75_ptx
{
enum class Result { eOk, eTarget, eSyntax, eUnsupported, eResource };

struct Lowered
{
    std::string ptx;
    size_t minmaxScalar = 0;
    size_t minmaxPacked = 0;
    size_t convertPacked = 0;
    size_t mmaK16 = 0;
};

Result Lower(std::string_view original, Lowered& out) noexcept;
}
