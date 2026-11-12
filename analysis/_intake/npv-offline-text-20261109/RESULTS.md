# Results

- VERIFIED_SYNTHETIC: 85 native/Python cases passed, including signed v1/v5/v6,
  password, app-key, ECDH recipient identity, wrong/missing credentials,
  altered tags, historical whitebox CTR, modern URI aliases, DNS, standalone
  npvs1, nested fields, malformed Base64/UTF-8 and duplicate JSON members.
- Invalid nested encoded values now fail instead of returning partial JSON.
- No actual NPV text sample was supplied in this request. Synthetic parity
  does not certify unrelated ciphers or every exporter using an alias.
- Android installation, selection/scrolling and real-link QA remain device
  checks; Android build results are recorded separately.
