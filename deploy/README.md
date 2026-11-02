# Donnarieix Auth — deployment and HTTPS

**Current target:** Debian 13 unprivileged Proxmox CT at
`192.168.1.142`, served through existing Nginx on `infra-static`.

- Application CI/CD: `.github/workflows/ci.yml` (push to `main` once
  `AUTH_AUTO_DEPLOY=true` and secrets are configured).
- LXC bootstrap: `deploy/bootstrap-lxc.sh`.
- Root-owned restricted SSH installer: `deploy/install-staging.sh`.
- HTTPS edge: `deploy/install-nginx-edge.sh` on **infra-static**, never
  inside the CT. It reuses a suitable existing certificate or obtains an
  automated HTTP-01 certificate when public port 80 is available.
- Exact DNS, Nginx, firewall and administrator instructions:
  [Staging deployment guide](../docs/staging-deployment.md).

The older `deploy/Caddyfile` is a historical example, **not** the active
network architecture. SQLite and OIDC keys must stay on the CT, never in Git
or GitHub Actions artifacts. Keep this test issuer accessible only to the
authorized LAN/VPN clients until security acceptance is complete.

## Courriers de vérification (installation unique)

L'email transactionnel doit être activé sur le **conteneur Auth**,
pas sur le proxy Nginx `infra-static`.
Créer une boîte dédiée chez le fournisseur mail (par exemple
`auth@donnarieix.fr` si elle est hébergée chez o2switch), puis lancer
`bash deploy/configure-smtp.sh` depuis une console root interactive du CT,
avec une copie à jour de ce dépôt.

Le script écrit les paramètres SMTP dans le fichier persistant
`/etc/donnarieix-auth/auth.env` avec les permissions 0600,
sans afficher le mot de passe, et redémarre le service.
Les builds et livraisons GitHub ne modifient pas ce fichier.

o2switch recommande l'hôte serveur se terminant en `.o2switch.net`,
SMTP TLS sur port **465** et l'adresse mail complète comme identifiant.
Utiliser le nom réel indiqué dans l'espace client, pas une valeur fictive.
La prise en charge alternative STARTTLS obligatoire sur port **587** existe
pour d'autres prestataires.

Après installation, demander un nouveau code de vérification depuis
l'interface, contrôler sa réception et vérifier le compte. Tester également
la récupération de mot de passe. Ne considérer le mail opérationnel qu'après
ce test réel ; l'état système `active` et un HTTP 202 ne prouvent pas la
livraison. En cas d'erreur, consulter `journalctl -u donnarieix-auth -n 80`
(le code et le destinataire ne doivent pas être dans les logs).
