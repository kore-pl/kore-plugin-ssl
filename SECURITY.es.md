# Divulgación de vulnerabilidades de seguridad

Este archivo es el proceso de divulgación, no el diseño de seguridad. El diseño del núcleo está en docs/SECURITY.md; el modelo de amenazas de kore está en el repositorio kore.

## Alcance

Covered: the TLS certificate management plugin (id `ssl`) implementation, `info.json` capability declarations, the `web/` frontend and `make dist` artifacts.

## Versiones compatibles

| Versión | Estado | Notas |
| --- | --- | --- |
| `0.8.0`（当前最新） | Sí — acepta y corrige | Instantánea de vista previa/desarrollo; actualiza. |
| 更早的 `0.x` 版本 | No — sin soporte | Instantánea de vista previa/desarrollo; actualiza. |

Durante la fase 0.x se usa una superficie mínima: solo se corrige el último parche de cada línea minor; los parches antiguos no se respaldan.

## Superficie de ataque en este repositorio

Las acciones remotas y las escrituras en el host se limitan a las capacidades declaradas; una evasión es una vulnerabilidad. Los sockets de los plugins los crea el shell con permisos restringidos; evadir permisos o leer datos de otro plugin es una vulnerabilidad.

## Informes

Preferido: GitHub Security Advisory en este repositorio («Informar de una vulnerabilidad», privado, sin issue público). Correo alternativo: pengtang1024@users.noreply.github.com con asunto `[kore security] <repo>`. No abras issues públicos ni publices detalles explotables en debates o PR.

Incluye: versión o commit afectado, pasos de reproducción o PoC, evaluación del impacto, si ya es público y tu preferencia de atribución.

## Plazos y divulgación

Confirmación en 72 horas con una primera valoración; los casos complejos reciben un plan de investigación. Divulgación coordinada con plazo por defecto de 90 días; contáctanos primero si hace falta anticiparla (p. ej. explotación activa). Registra las correcciones en CHANGELOG.md sin detalles de explotación y publica un aviso si procede.

## Agradecimientos

Con tu consentimiento agradecemos al informante en las notas de lanzamiento; anónimo si lo pides.
