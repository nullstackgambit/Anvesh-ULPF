# deploy/certs — deployment CA and TLS certificates (generated, never committed)

Everything in this directory except this README is git-ignored and is never
included in an offline bundle. `ulpf certs init` creates a private CA for this
deployment and issues the certificates with `cryptography`: RSA 3072 and
SHA-256, valid for 825 days by default (`--days`; the CA is valid twice as
long). No network access is needed. Private keys are written with mode 0600.

| File | Used by |
|---|---|
| `ulpf-ca.crt` / `ulpf-ca.key` | Deployment CA. Distribute the certificate to senders and clients. Move the key offline after issuing. |
| `ulpf-server.crt` / `.key` | Vector's TLS syslog listener (`listen.syslog_tls`, default 127.0.0.1:6514). The listener is enabled only when these files exist. SAN localhost / 127.0.0.1. |
| `opensearch-node.crt` / `.key` | OpenSearch HTTP and transport TLS (`ulpf os secure` copies them to `runtime/opensearch-config/certs`). |
| `opensearch-admin.crt` / `.key` | Client certificate of the OpenSearch security admin (initialising the security index). |
| `ulpf-client.crt` / `.key` | A sender client certificate (used by the TLS tests). |

`ulpf certs init` issues loopback names only (SAN localhost / 127.0.0.1). To
expose the listener or OpenSearch beyond loopback, you need server
certificates for the real host names, and `ulpf certs init` cannot issue those
yet. Put certificates from your own CA in place under the same file names
(README.md, Known limitations; docs/architecture.md, Security).
