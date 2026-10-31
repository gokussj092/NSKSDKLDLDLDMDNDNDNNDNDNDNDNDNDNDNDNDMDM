#pragma once
#include <string>
#include <vector>

namespace spdecode {
using CatalogBytes=std::vector<unsigned char>;
// Verified server envelope: returns authenticated GZIP bytes, never unchecked JSON.
// Uses the existing P-256 ECDH / HKDF-SHA256 / AES-256-GCM catalog protocol.
CatalogBytes openCatalog(const CatalogBytes& recipientPkcs8,
                         const std::string& recipientSpki,
                         const std::string& purpose,
                         const std::string& senderSpki,
                         const std::string& salt,
                         const std::string& iv,
                         int plainBytes,
                         const std::string& data);
} // namespace spdecode
