#pragma once
#include <string>
#include <vector>
namespace spdecode::offline {
bool isNpvText(const std::vector<unsigned char>& data);
std::string decodeNpvText(const std::vector<unsigned char>& data);
}
