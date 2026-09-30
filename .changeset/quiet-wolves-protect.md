---
"certkit": patch
---

Resolve Windows filesystem protection commands from SystemRoot so PATH collisions cannot select non-Windows tools.

Recognize normalized POSIX aliases of the manually managed system NSS database on Windows too.

Remove only the default SYSTEM and Administrators grants when protecting Windows CA directories, then verify the ACL remains self-only.

Validate malformed elevation arguments consistently before rejecting unsupported platforms.
