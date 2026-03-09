# SCB-VKA BB (BlackBox) Identity Stamp Protocol

**Status:** DEPRECATED — Removed from specification.

**Reason:** AEAD authentication + AAD context binding already provides integrity, authenticity, and type identification. BB stamp is redundant. The gap it addresses (type mismatch after successful decryption) is an implementation-level defensive programming concern, not an architectural requirement.

All type and version identification is handled by AAD fields (VID, object_type, purpose) which are already bound to every AEAD operation in SCB-VKA v2.

---

*This document is retained for historical reference only.*