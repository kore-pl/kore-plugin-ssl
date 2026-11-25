> 状态: borrador (草稿) · 归属: wave1 · 更新: 2026-11-25 · 里程碑: M5

# kore-plugin-ssl

Este repositorio implementa el plugin de gestión de certificados TLS de kore (id `ssl`). El directorio de certificados es fijo (`KORE_SSL_CERT_DIR`, por defecto `/etc/kore/ssl`); RPC no acepta rutas arbitrarias. Todas las operaciones leen/escriben archivos reales, sin inventarios falsos. Solo usa biblioteca estándar Go + pluginapi, sin bibliotecas ACME de terceros ni binarios certbot/acme. `lifecycle=lazy`: el núcleo dispara la renovación, sin temporizadores internos. No escribe configuración del servidor web: enlace y redirección 80→443 son del plugin site; aquí solo se registra la pertenencia y se emite un juicio de solo lectura.

语言：[简体中文](DETAIL.md) · [English](DETAIL.en.md) · [Español](DETAIL.es.md) · [Français](DETAIL.fr.md) · [Deutsch](DETAIL.de.md) · [Русский](DETAIL.ru.md) · [Português](DETAIL.pt.md)

## Qué hace

- **Protocolo**: `kore.plugin.v1`, `lifecycle=lazy`, `depth_level=production`.
- **Métodos**: `ssl.list` / `import` / `selfsign` / `renew` / `verify` / `expiring` / `renew.set` / `acme.status` / `acme.issue`; `verify` hace un handshake TLS real.
- **Archivos reales**: directorio fijo, sin rutas arbitrarias; cada certificado se analiza realmente.
- **Límite de solo lectura**: `site.bindSSL` / `unbindSSL` / `setRedirect` son del plugin site; `boundary_test.go` bloquea extralimitaciones.
- **Sin temporizadores**: renovación disparada por `event:cert.renew_due` del núcleo; sin procesos residentes.
- **ACME**: emisión integrada o `engine=external` para certbot/acme.sh; `acme.status` sondea el cliente local.

## Inicio rápido

```bash
make check    # gofmt → vet → test
make build    # compilar el binario
make dist     # generar el tarball
```

El plugin lo inicia el shell de kore bajo demanda; `info.json` declara capacidades y `requires_kore`.

## Seguridad y límites

Informa de vulnerabilidades por [SECURITY.md](../SECURITY.md)

## Mapa de documentación

[SECURITY.md](../SECURITY.md) — proceso de divulgación.
[CONTRIBUTING.md](../CONTRIBUTING.md) — convenciones de commit y versión.
[CHANGELOG.md](../CHANGELOG.md) — historial.
[info.json](../info.json) — capacidades y versión.

## Preguntas frecuentes

**P: ¿Necesito una cuenta?**
No. Sin cuentas, verificación en línea ni telemetría oculta; configuración en texto plano.

**P: ¿Dónde están los plugins?**
Cada plugin vive en su propio repositorio `kore-plugin-<id>` y solo depende de `kore/pkg/pluginapi`.

**P: ¿Por dónde empezar?**
Lee el protocolo y la tabla de métodos del README y luego las capacidades en `info.json`.
