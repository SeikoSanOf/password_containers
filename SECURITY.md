# SECURITY

Ce document explique l'approche sécurité actuelle pour `password_containers`.

## État actuel
- Données sont chiffrées dans `vault.json` avec AES-256-GCM
- Clé dérivée du mot de passe maître via PBKDF2(HMAC-SHA256) avec 200000 itérations
- `vault.json` ne doit pas être commité (déjà dans `.gitignore`)
- Aucun mécanisme de gestion de mots de passe perdu ou de récupération

## Recommandations pour futures versions
1. passer de PBKDF2 à Argon2id pour meilleure résistance GPU.
2. implémenter verrouillage automatique et tentative limite après erreurs.
3. protéger la mémoire vive en utilisant `zeroize` plus systématique.
4. ne jamais logguer des secrets ou le mot de passe maître.
5. envisager l’utilisation de bibliothèques auditables (libsodium, age) et intégration OTP/MFA.
