> 状态: draft (草稿) · 归属: wave1 · 更新: 2026-11-25 · 里程碑: M5

# kore-plugin-ssl

This repository implements kore’s TLS certificate management plugin (id `ssl`). The certificate directory is fixed to `KORE_SSL_CERT_DIR` (default `/etc/kore/ssl`); RPC never accepts arbitrary paths. All operations read/write real files — no in-memory fake inventory. It uses only the Go standard library + pluginapi: no third-party ACME library, no bundled certbot/acme binary. `lifecycle=lazy`: renewal is triggered by a kernel event, no internal ticker. It never writes web server config: site binding and 80→443 redirect belong to the site plugin; this repo only registers ownership, suggests payloads and makes read-only judgments.

语言：[简体中文](DETAIL.md) · [English](DETAIL.en.md) · [Español](DETAIL.es.md) · [Français](DETAIL.fr.md) · [Deutsch](DETAIL.de.md) · [Русский](DETAIL.ru.md) · [Português](DETAIL.pt.md)

## What it does

- **Protocol**: `kore.plugin.v1`, `lifecycle=lazy`, `depth_level=production`.
- **Methods**: `ssl.list` / `import` / `selfsign` / `renew` / `verify` / `expiring` / `renew.set` / `acme.status` / `acme.issue`; `verify` performs a real TLS handshake probe.
- **Real files**: fixed certificate directory, no arbitrary RPC paths; each certificate is really parsed, no fake in-memory list.
- **Read-only boundary**: `site.bindSSL` / `unbindSSL` / `setRedirect` belong to the site plugin; this repo only registers ownership and suggests payloads, with `boundary_test.go` asserting against overreach.
- **Zero ticker**: renewal is triggered by the kernel via `event:cert.renew_due`; no residency, no plugin timer.
- **ACME**: built-in issuance, or `engine=external` for certbot/acme.sh; `acme.status` probes the local client read-only.

## Quick start

```bash
make check    # gofmt → vet → test
make build    # build the plugin binary
make dist     # produce the release tarball
```

The plugin is started on demand by the kore shell; `info.json` declares capabilities and `requires_kore`.

## Security and boundaries

Report vulnerabilities through [SECURITY.md](../SECURITY.md)

## Documentation map

[SECURITY.md](../SECURITY.md) — disclosure process.
[CONTRIBUTING.md](../CONTRIBUTING.md) — commit and release conventions.
[CHANGELOG.md](../CHANGELOG.md) — version history.
[info.json](../info.json) — capabilities and version declaration.

## FAQ

**Q: Do I need an account?**
No. There is no account, online verification or hidden telemetry; configuration is plain text.

**Q: Where do plugins live?**
Each plugin lives in its own `kore-plugin-<id>` repository, depending only on `kore/pkg/pluginapi`.

**Q: Where should I start?**
Read the protocol surface and method table in the README, then the capability declarations in `info.json`.
