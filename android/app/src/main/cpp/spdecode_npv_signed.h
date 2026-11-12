#pragma once
#include <string>
#include <vector>
namespace spdecode::offline {
std::string decodeNpvSigned(const std::vector<unsigned char>& data,
                            const std::string& password,
                            const std::string& recipientJson);
}
