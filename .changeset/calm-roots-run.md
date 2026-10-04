---
'certkit': patch
---

Run Linux system trust commands directly when the CLI already has effective UID 0, so install and uninstall work without sudo in root containers. Preserve sudo elevation for non-root callers and report direct-command failures without sudo guidance.
