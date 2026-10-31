#pragma once
#include <cstddef>
#include <cstdint>
#include <string>
namespace spdecode {
struct RequestProof {
    std::string timestamp;
    std::string nonce;
    std::string message;
};
std::string sha256Hex(const unsigned char* data, std::size_t size);
std::string formatProof(int operation, const std::string& version,
                        const unsigned char* data, std::size_t length,
                        const std::string& bearer,
                        const std::string& timestamp, const std::string& nonce);
RequestProof prepareProof(int operation, const std::string& version,
                          const unsigned char* data, std::size_t length,
                          const std::string& bearer);
// Client-side format and challenge policy only; backend checks tokens/attestation.
bool validClassicChallenge(const std::string& nonce, const std::string& challengeId,
                           const std::string& apiVersion);
bool validActionChallenge(const std::string& requestHash, const std::string& challengeId,
                          std::int64_t project);
bool validPlayNonce(const std::string& nonce);
std::string makeAliasSuffix();
std::string playNonce(const std::string& serverNonce,
                      const std::string& challengeId, const std::string& publicKey);
} // namespace spdecode
