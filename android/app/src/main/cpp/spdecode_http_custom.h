#pragma once
#include <string>
#include <vector>
namespace spdecode::offline {
std::string decodeHttpCustom(const std::vector<unsigned char>& raw,
                             const std::string& password,
                             const std::string& hwid);
}
