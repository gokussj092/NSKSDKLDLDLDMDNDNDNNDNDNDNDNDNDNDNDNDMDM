#pragma once
#include <string>
#include <vector>

namespace spdecode::offline {
/// Dark Tunnel .dark and dt://, dtunnel://, dark:// offline native decoder.
/// Returns complete normalized JSON. No Java cryptography, fallback or network.
bool isDarkTunnelEnvelope(const std::vector<unsigned char>& source);
std::string decodeDarkTunnel(const std::vector<unsigned char>& source);
}
