# Microsoft DBX

`dbx_microsoft_baseline.bin` retains the previously enrolled signed update
(SHA-256 `2089e3125e611376cb44326b5765674255443b2484f88de97251939d18055f68`).
`dbx_microsoft_update.bin` is the unmodified 20260707 update from MrChromebox
commit `af5e96c613f23bec0e50d79c641ed64fd36de622`
(SHA-256 `524c796ade42db0048b656f6cf3863832174ae7f58cad6986d1ccae1e3d3ecd1`).

Setup Mode enrollment writes the baseline, then appends the signed update.
Existing User Mode installations receive updates through the OS instead.

After replacing the update, run `python3 GenerateDbxAppend.py` in this directory
and commit the regenerated `dbx_microsoft_append.esl` alongside it. This unsigned
signature list is only for `dbxDefault`: it contains entries absent from the
baseline, matching AuthVariableLib's append filtering. It must not be used as an
authenticated OS update. Keep update order and signature owners intact: fwupd
identifies the DBX version using its last Microsoft entry.
