# Maya investigation results

- **VERIFIED_LOCAL_VECTOR:** the supplied `maya://` sample authenticates with ChaCha20-Poly1305 and produces a 16-character opaque identifier. Altered tag, malformed Base64 and arbitrary path targets are rejected.
- **VERIFIED_SYNTHETIC:** a synthetic GitHub Contents JSON response containing a synthetic encrypted `.maya` file is structurally validated and passed unchanged to the existing file decoder. CBC PKCS#7 and AES-GCM inner fields decode correctly in a Python fixture.
- **NETWORK_AUTH_PENDING:** unauthenticated GitHub repository and file lookups returned HTTP 404. No live private token used, no successful real download; do not count synthetic checks as a production catalog.
- **SERVER_VPN_NOT_ENABLED:** reference-by-ID is not an application-wide catalog. No icon/provider/card or server count added to Server VPN.
- **SECRET_SAFETY:** a personal token appeared in the user input. It was not copied, queried, saved or reused. Rotate before enabling optional authorized access.

The method is code-complete for parsing references, accessing only the fixed upstream with authorized credentials and forwarding bytes to the original Maya file worker. Its production availability is gated by valid access to the upstream.
