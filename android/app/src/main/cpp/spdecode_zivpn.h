#pragma once
#include <string>
#include <vector>
namespace spdecode::offline {
// ZIVPN Tunnel (com.zi.zivpn, 2.2.5 / 184): .ziv file decoder.
// Returns the decoded Properties entries as a flat JSON object.
std::string decodeZiv(const std::vector<unsigned char>& raw);
// zivpn:// text links. Returns the decoded JSON, the decoded Properties
// entries as a flat JSON object, or {"decodedText": ...} for other plaintext.
std::string decodeZivpnText(const std::vector<unsigned char>& raw);
}
