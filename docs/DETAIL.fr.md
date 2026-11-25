> 状态: brouillon (草稿) · 归属: wave1 · 更新: 2026-11-25 · 里程碑: M5

# kore-plugin-ssl

Ce dépôt implémente le plugin de gestion des certificats TLS de kore (id `ssl`). Le répertoire des certificats est fixe (`KORE_SSL_CERT_DIR`, par défaut `/etc/kore/ssl`) ; le RPC n’accepte aucun chemin arbitraire. Toutes les opérations lisent/écrivent de vrais fichiers, sans faux inventaire en mémoire. Uniquement la bibliothèque standard Go + pluginapi : aucune bibliothèque ACME tierce, aucun binaire certbot/acme embarqué. `lifecycle=lazy` : le noyau déclenche le renouvellement, aucun minuteur interne. Le plugin n’écrit pas la configuration du serveur web : liaison et redirection 80→443 appartiennent au plugin site ; ici on enregistre seulement l’appartenance et on porte un jugement en lecture seule.

语言：[简体中文](DETAIL.md) · [English](DETAIL.en.md) · [Español](DETAIL.es.md) · [Français](DETAIL.fr.md) · [Deutsch](DETAIL.de.md) · [Русский](DETAIL.ru.md) · [Português](DETAIL.pt.md)

## Ce que fait le projet

- **Protocole** : `kore.plugin.v1`, `lifecycle=lazy`, `depth_level=production`.
- **Méthodes** : `ssl.list` / `import` / `selfsign` / `renew` / `verify` / `expiring` / `renew.set` / `acme.status` / `acme.issue` ; `verify` effectue un vrai sonde de handshake TLS.
- **Vrais fichiers** : répertoire fixe, aucun chemin arbitraire ; chaque certificat est réellement analysé.
- **Frontière en lecture seule** : `site.bindSSL` / `unbindSSL` / `setRedirect` appartiennent au plugin site ; `boundary_test.go` bloque tout dépassement.
- **Zéro minuteur** : renouvellement déclenché par `event:cert.renew_due` du noyau ; aucune résidence.
- **ACME** : émission intégrée ou `engine=external` pour certbot/acme.sh ; `acme.status` sonde le client local.

## Démarrage rapide

```bash
make check    # gofmt → vet → test
make build    # compiler le binaire
make dist     # produire le tarball
```

Le plugin est lancé à la demande par le shell kore ; `info.json` déclare les capacités et `requires_kore`.

## Sécurité et limites

Signalez les vulnérabilités via [SECURITY.md](../SECURITY.md)

## Plan de la documentation

[SECURITY.md](../SECURITY.md) — procédure de divulgation.
[CONTRIBUTING.md](../CONTRIBUTING.md) — conventions de commit et version.
[CHANGELOG.md](../CHANGELOG.md) — historique.
[info.json](../info.json) — capacités et version.

## Questions fréquentes

**Q : Faut-il un compte ?**
Non. Pas de compte, de vérification en ligne ni de télémétrie cachée ; configuration en texte brut.

**Q : Où sont les plugins ?**
Chaque plugin a son propre dépôt `kore-plugin-<id>` et ne dépend que de `kore/pkg/pluginapi`.

**Q : Par où commencer ?**
Lisez le protocole et le tableau des méthodes du README, puis les capacités dans `info.json`.
