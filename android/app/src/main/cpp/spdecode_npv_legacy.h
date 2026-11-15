#pragma once
#include <string>
#include <vector>
namespace spdecode::offline {
std::string decodeNpvLegacy(const std::vector<unsigned char>& data);
}
