# deploy/keys — signing keys (generated, never committed)

Everything in this directory except this README is git-ignored and is never
included in an offline bundle. The installer generates the keys on the target.

| File | Created by | Purpose |
|---|---|---|
| `seal.key` (0600) | `ulpf keygen` | Ed25519 private key that signs raw-archive manifests (`ulpf seal`). Must stay on the collector host. |
| `seal.pub` | `ulpf keygen` | Public key for `ulpf verify --pubkey seal.pub`; give it to auditors. |
| `release.key` (0600) | `ulpf bundle build` (first run) | Ed25519 key that signs `BUNDLE.json` of offline bundles. Lives on the **build** host only. |
| `release.pub` | `ulpf bundle build` | Shipped inside the bundle. Its SHA-256 must be compared out of band before installing (README.md, Air-gapped deployment). |

Operational notes:

- `ulpf keygen` refuses to overwrite an existing key; `--force` replaces it.
  The manifests signed with the old key then no longer verify against the new
  `seal.pub`. Key rotation with several trusted keys is not implemented
  (README.md, Known limitations), so back up `seal.key` and `seal.pub` together with the
  archive and its manifests.
- The tamper evidence protects against changes made *without* `seal.key`.
  Anyone who can read `seal.key` can re-sign a modified archive. Keep the host
  and the key's permissions tight, and record the manifest head
  (`runtime/data/archive/manifests/HEAD`) outside the host
  (`ulpf verify --expect-head`).
