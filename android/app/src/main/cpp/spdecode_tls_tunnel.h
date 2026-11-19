#pragma once
#include <string>
#include <vector>
namespace spdecode::offline {
// TLS Tunnel (com.tlsvpn.tlstunnel, 8.5.0 / 516): .tls file and tls://
// text decoder. Returns the decoded configuration as a JSON object,
// mirroring decoders/Python/TLS.py (_render_config output).
// Throws std::runtime_error with a TLS_* code on any failure; a failed
// GCM tag never yields plaintext.
std::string decodeTls(const std::vector<unsigned char>& raw);
}
