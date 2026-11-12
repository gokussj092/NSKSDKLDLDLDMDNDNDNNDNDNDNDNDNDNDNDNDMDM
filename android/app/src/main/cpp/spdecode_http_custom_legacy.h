#pragma once
#include <string>
#include <vector>
namespace spdecode::offline {
bool decodeLegacyHttpCustom(const std::vector<unsigned char>& raw,std::string& result);
}
