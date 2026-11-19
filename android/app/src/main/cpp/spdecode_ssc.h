#pragma once
#include <string>
#include <vector>
namespace spdecode::offline {
// SSC Custom (dev.epro.ssc, 4.3.13 / 96): .ssc files and ssc:// text.
// Returns the decoded profile as a JSON object (mapped key names),
// matching decoders/Python/SSCCUSTOM.py, including its two known quirks:
// two-layer files keep single-letter keys inside CONFIGS, and L3 inner
// fields of 16 hex chars or fewer are left encrypted (length guard).
// Throws std::runtime_error with an SSC_* code on invalid input.
std::string decodeSsc(const std::vector<unsigned char>& raw);
}
