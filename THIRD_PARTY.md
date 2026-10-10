# Third-party components

ULPF itself is licensed under Apache-2.0 (`LICENSE`). It ships or installs the
following third-party components **unmodified**. Every license below was read
from the component itself (license file inside the release archive, or the
installed Python package's metadata) on 2026-10-07; nothing was filled in from
memory. Python package licenses: `importlib.metadata` of the exact wheels in
`requirements.lock`.

## Runtime binaries (installed from `runtime/dist`, SHA-256 pinned in `deploy/airgap/ARTIFACTS.json`)

| Component | Version | License | Evidence |
|---|---|---|---|
| Vector (static musl build) | 0.58.0 | MPL-2.0 | `LICENSE` in `vector-0.58.0-x86_64-unknown-linux-musl.tar.gz` |
| OpenSearch (min distribution) | 3.8.0 | Apache-2.0 | `LICENSE.txt` in `opensearch-min-3.8.0-linux-x64.tar.gz` |
| OpenSearch security plugin | 3.8.0.0 | Apache-2.0 | Maven Central artifact `org.opensearch.plugin:opensearch-security` |
| Eclipse Temurin JDK (bundled with OpenSearch) | 25.0.4+7 | GPL-2.0 with Classpath Exception | `jdk/legal/java.base/LICENSE`, `ASSEMBLY_EXCEPTION`, `jdk/release` |

## Data and specifications

| Item | License / terms | Evidence |
|---|---|---|
| OCSF schema 1.9.0 (vendored export + JSON Schemas, `schema/ocsf/1.9.0`) | Apache-2.0 | <https://github.com/ocsf/ocsf-schema>; per-file URLs and SHA-256 in `schema/ocsf/1.9.0/MANIFEST.json` |
| IANA Protocol Numbers registry (`schema/iana/protocol-numbers-1.csv`) | IANA registry data | source URL + SHA-256 in `schema/iana/SOURCE.json` |
| RFC 6962 Merkle test vectors | Apache-2.0 | transparency-dev/merkle `testonly/constants.go` @ `77f1b57d…` (re-typed into tests, attributed) |
| Vendor log-format facts (`verification/vendor_refs/`) | facts extracted from vendor documentation (field names/order/types) for interoperability; the documents themselves are not redistributed | URLs inside each file |

## Python packages (wheels in `wheelhouse/`, exact versions + SHA-256 in `requirements.lock`)

Optional-extra packages under copyleft licenses: **pySigma (LGPL-2.1-only)**
and **pySigma-backend-opensearch / -elasticsearch (LGPL-3.0-only)** are used
unmodified, imported dynamically, and only by `ulpf detect sigma`; the core
pipeline does not depend on them.

| Package | Version | License (from package metadata) |
|---|---|---|
| altair | 6.3.0 | BSD License |
| anyio | 4.15.1 | MIT |
| attrs | 26.1.0 | MIT |
| cachetools | 4.2.1 | MIT |
| certifi | 2026.7.22 | MPL-2.0 |
| cffi | 2.1.1 | MIT-0 |
| charset-normalizer | 3.5.2 | MIT |
| click | 8.5.0 | BSD-3-Clause |
| cloudpickle | 3.1.2 | BSD-3-Clause |
| cryptography | 50.0.2 | Apache-2.0 OR BSD-3-Clause |
| diskcache | 5.6.3 | Apache 2.0 |
| diskcache-stubs | 5.6.3.6.20240818 | Apache Software License |
| drain3 | 0.9.11 | MIT |
| h11 | 0.16.0 | MIT |
| httptools | 0.8.0 | MIT |
| idna | 3.20 | BSD-3-Clause |
| iniconfig | 2.3.1 | MIT |
| itsdangerous | 2.2.0 | BSD License |
| Jinja2 | 3.1.6 | BSD License |
| joblib | 1.6.0 | BSD-3-Clause |
| jq | 1.12.0 | BSD-2-Clause |
| jsonpickle | 1.5.1 | BSD License (classifier; License field "UNKNOWN") |
| jsonschema | 4.26.0 | MIT |
| jsonschema-specifications | 2025.9.1 | MIT |
| MarkupSafe | 3.0.4 | BSD-3-Clause |
| narwhals | 2.26.0 | MIT |
| numpy | 2.5.3 | BSD-3-Clause AND 0BSD AND MIT AND Zlib AND CC0-1.0 |
| packaging | 26.3 | Apache-2.0 OR BSD-2-Clause |
| pandas | 3.0.6 | BSD License |
| pillow | 12.3.0 | MIT-CMU |
| pip | 26.2.1 | MIT |
| pluggy | 1.6.0 | MIT |
| protobuf | 7.36.2 | 3-Clause BSD License |
| pyarrow | 25.0.1 | Apache-2.0 |
| pycparser | 3.0 | BSD-3-Clause |
| pydeck | 0.9.3 | Apache License 2.0 |
| Pygments | 2.21.0 | BSD-2-Clause |
| pyparsing | 3.3.3 | MIT |
| pySigma | 1.5.1 | LGPL-2.1-only |
| pySigma-backend-elasticsearch | 2.1.1 | LGPL-3.0-only |
| pySigma-backend-opensearch | 2.0.3 | LGPL-3.0-only |
| pytest | 9.1.1 | MIT |
| python-dateutil | 2.9.0.post0 | Dual License |
| python-multipart | 0.0.32 | Apache-2.0 |
| PyYAML | 6.0.3 | MIT |
| referencing | 0.37.0 | MIT |
| requests | 2.34.2 | Apache-2.0 |
| rpds-py | 2026.9.1 | MIT |
| scikit-learn | 1.9.1 | BSD-3-Clause |
| scipy | 1.18.1 | BSD License |
| six | 1.17.0 | MIT |
| starlette | 1.7.0 | BSD-3-Clause |
| streamlit | 1.65.0 | Apache-2.0 |
| threadpoolctl | 3.7.0 | BSD-3-Clause |
| toml | 0.10.2 | MIT |
| types-PyYAML | 6.0.12.20260906 | Apache-2.0 |
| typing_extensions | 4.16.0 | PSF-2.0 |
| urllib3 | 2.8.0 | MIT |
| uvicorn | 0.54.0 | BSD-3-Clause |
| watchdog | 6.0.0 | Apache-2.0 |
| websockets | 17.2 | BSD-3-Clause |
