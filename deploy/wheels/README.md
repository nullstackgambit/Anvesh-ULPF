# deploy/wheels — wheels that PyPI does not publish

`make fetch` copies these into `runtime/wheelhouse` and lets pip use them
(`--find-links`) next to the wheels it downloads from PyPI. Every file is
pinned by SHA-256 in `requirements.lock`, so the hash-checked install
(`pip --require-hashes`) accepts exactly this file.

| File | Why it is here | Provenance |
|---|---|---|
| `drain3-0.9.11-py3-none-any.whl` (sha256 `01085bbeace1fec49ab7b53efa87eaf03092401c47a4e58783bf90592ee74167`) | drain3 0.9.11 is published on PyPI only as a source distribution; a wheel rebuilt elsewhere would not match the pinned hash | Built 2026-10-07 from the PyPI sdist `drain3-0.9.11.tar.gz`, sha256 `9ab4b1407fad74f56554ae371ef019c3c7985861631f4bab46a0e92585125f75` (equal to the digest PyPI publishes, checked 2026-10-10). Pure Python (`py3-none-any`). MIT licence, included in the wheel (`dist-info/licenses/LICENSE.txt`). See verification/DEPENDENCIES.md, note 1. |
