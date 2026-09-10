#pragma once

#include "ampere_bundle.h"

#include <Windows.h>

#include <cstddef>
#include <cstdint>
#include <vector>

namespace turing_runtime
{
bool PlanSelectors(const uint8_t* image, size_t size, std::vector<ampere_bundle::ByteEdit>& out) noexcept;
bool LeaTarget(const uint8_t* insn, uint32_t insnRva, uint32_t& targetRva) noexcept;
bool Relocate(HMODULE provider, size_t size) noexcept;
void Rollback() noexcept;
bool Ready() noexcept;
}
