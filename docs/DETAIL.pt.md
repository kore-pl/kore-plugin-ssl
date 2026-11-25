> 状态: rascunho (草稿) · 归属: wave1 · 更新: 2026-11-25 · 里程碑: M5

# kore-plugin-ssl

Este repositório implementa o plugin de gestão de certificados TLS do kore (id `ssl`). O diretório de certificados é fixo (`KORE_SSL_CERT_DIR`, padrão `/etc/kore/ssl`); RPC não aceita caminhos arbitrários. Todas as operações leem/escrevem arquivos reais, sem inventário falso em memória. Apenas biblioteca padrão Go + pluginapi, sem biblioteca ACME de terceiros nem certbot/acme embutido. `lifecycle=lazy`: o núcleo dispara a renovação, sem timers internos. O plugin não escreve configuração de servidor web: vinculação e redirecionamento 80→443 pertencem ao plugin site; aqui apenas se registra a pertença e se emite decisão somente leitura.

语言：[简体中文](DETAIL.md) · [English](DETAIL.en.md) · [Español](DETAIL.es.md) · [Français](DETAIL.fr.md) · [Deutsch](DETAIL.de.md) · [Русский](DETAIL.ru.md) · [Português](DETAIL.pt.md)

## O que faz

- **Protocolo**: `kore.plugin.v1`, `lifecycle=lazy`, `depth_level=production`.
- **Métodos**: `ssl.list` / `import` / `selfsign` / `renew` / `verify` / `expiring` / `renew.set` / `acme.status` / `acme.issue`; `verify` faz handshake TLS real.
- **Arquivos reais**: diretório fixo, sem caminhos arbitrários; cada certificado é analisado de verdade.
- **Fronteira somente leitura**: `site.bindSSL` / `unbindSSL` / `setRedirect` pertencem ao plugin site; `boundary_test.go` bloqueia excessos.
- **Zero timers**: renovação disparada por `event:cert.renew_due` do núcleo; sem processos residentes.
- **ACME**: emissão integrada ou `engine=external` para certbot/acme.sh; `acme.status` sonda o cliente local.

## Início rápido

```bash
make check    # gofmt → vet → test
make build    # compilar o binário
make dist     # gerar o tarball
```

O plugin é iniciado sob demanda pelo shell do kore; `info.json` declara capacidades e `requires_kore`.

## Segurança e limites

Relate vulnerabilidades por [SECURITY.md](../SECURITY.md)

## Mapa da documentação

[SECURITY.md](../SECURITY.md) — processo de divulgação.
[CONTRIBUTING.md](../CONTRIBUTING.md) — convenções de commit e versão.
[CHANGELOG.md](../CHANGELOG.md) — histórico.
[info.json](../info.json) — capacidades e versão.

## Perguntas frequentes

**P: Preciso de uma conta?**
Não. Sem contas, verificação online ou telemetria oculta; configuração em texto simples.

**P: Onde ficam os plugins?**
Cada plugin fica em `kore-plugin-<id>` e depende apenas de `kore/pkg/pluginapi`.

**P: Por onde começar?**
Leia o protocolo e a tabela de métodos no README e depois as capacidades em `info.json`.
