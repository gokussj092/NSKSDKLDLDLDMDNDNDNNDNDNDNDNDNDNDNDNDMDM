#pragma once
#include <string>
#include <vector>
namespace spdecode::offline {
std::string decodeHttpInjector(const std::vector<unsigned char>& raw);
}
