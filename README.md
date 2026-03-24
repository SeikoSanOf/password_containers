# password_containers

Coffre-fort de mots de passe minimal en Rust.

## Fonctionnalités
- stocke les secrets (service/login/password) chiffrés dans `vault.json`
- chiffrement AES-256-GCM
- mot de passe maître demandé au démarrage
- persistance entre exécutions

## Dépendances
- rpassword
- serde + serde_json
- aes-gcm, aes
- pbkdf2 + sha2
- rand
- base64
- zeroize

## Usage
1. `cargo build`
2. `cargo run`
3. Saisir le mot de passe maître (création puis confirmation au premier lancement)
4. Ajouter, lister et afficher secret

## Sécurité
- `vault.json` est chiffré mais stocke le salt + nonce en clair (normal)
- `gitignore` contient `vault.json`, `secrets.json` etc
- pas encore testé en production
