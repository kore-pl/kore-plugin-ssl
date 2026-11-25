> 状态: Entwurf (草稿) · 归属: wave1 · 更新: 2026-11-25 · 里程碑: M5

# kore-plugin-ssl

Dieses Repository implementiert das TLS-Zertifikatsverwaltungs-Plugin für Kore (id `ssl`). Das Zertifikatsverzeichnis ist fest auf `KORE_SSL_CERT_DIR` (Standard `/etc/kore/ssl`); RPC akzeptiert keine beliebigen Pfade. Alle Operationen lesen/schreiben echte Dateien, kein gefälschtes In-Memory-Inventar. Nur Go-Standardbibliothek + pluginapi: keine Drittanbieter-ACME-Bibliothek, kein gebündeltes certbot/acme. `lifecycle=lazy`: der Kernel löst Verlängerungen aus, keine internen Timer. Das Plugin schreibt keine Webserver-Konfiguration: Bindung und 80→443-Redirect gehören zum site-Plugin; hier wird nur Zuordnung registriert und schreibgeschützt bewertet.

语言：[简体中文](DETAIL.md) · [English](DETAIL.en.md) · [Español](DETAIL.es.md) · [Français](DETAIL.fr.md) · [Deutsch](DETAIL.de.md) · [Русский](DETAIL.ru.md) · [Português](DETAIL.pt.md)

## Was es tut

- **Protokoll**: `kore.plugin.v1`, `lifecycle=lazy`, `depth_level=production`.
- **Methoden**: `ssl.list` / `import` / `selfsign` / `renew` / `verify` / `expiring` / `renew.set` / `acme.status` / `acme.issue`; `verify` prüft echten TLS-Handshake.
- **Echte Dateien**: festes Verzeichnis, keine beliebigen Pfade; jedes Zertifikat wird wirklich geparst.
- **Schreibgeschützte Grenze**: `site.bindSSL` / `unbindSSL` / `setRedirect` gehören zum site-Plugin; `boundary_test.go` verhindert Übergriffe.
- **Keine Timer**: Verlängerung durch `event:cert.renew_due` des Kernels; keine residenten Prozesse.
- **ACME**: integrierte Ausstellung oder `engine=external` für certbot/acme.sh; `acme.status` prüft den lokalen Client.

## Schnellstart

```bash
make check    # gofmt → vet → test
make build    # Plugin-Binary bauen
make dist     # Release-Tarball erzeugen
```

Das Plugin wird von der Kore-Shell bei Bedarf gestartet; `info.json` deklariert Capabilities und `requires_kore`.

## Sicherheit und Grenzen

Melde Schwachstellen über [SECURITY.md](../SECURITY.md)

## Dokumentationsübersicht

[SECURITY.md](../SECURITY.md) — Offenlegungsprozess.
[CONTRIBUTING.md](../CONTRIBUTING.md) — Commit- und Release-Konventionen.
[CHANGELOG.md](../CHANGELOG.md) — Versionshistorie.
[info.json](../info.json) — Capabilities und Version.

## Häufige Fragen

**F: Brauche ich ein Konto?**
Nein. Keine Konten, keine Online-Prüfung, keine Telemetrie; Konfiguration im Klartext.

**F: Wo liegen die Plugins?**
Jedes Plugin liegt in `kore-plugin-<id>` und hängt nur von `kore/pkg/pluginapi` ab.

**F: Wo anfangen?**
Lies Protokoll und Methodentabelle in der README, dann die Capabilities in `info.json`.
