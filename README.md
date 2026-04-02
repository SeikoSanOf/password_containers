# password_containers

Gestionnaire de mots de passe local en Rust, avec interface graphique (egui) et mode CLI optionnel.

## Fonctionnalites
- Ajout, modification et suppression d'entrees (service, identifiant, mot de passe)
- Generation de mots de passe forts
- Copie du mot de passe dans le presse-papiers
- Sauvegarde locale chiffree dans `vault.db`
- Export des donnees chiffrees vers un fichier externe (portabilite)
- Verification du mot de passe maitre au chargement
- Verrouillage temporaire apres plusieurs echecs (anti brute-force)
- Interface graphique native simple et moderne pour les utilisateurs

## Securite
- Derivation de cle via Argon2id
- Chiffrement des donnees au repos via AES-256-GCM
- Salt et nonce aleatoires par sauvegarde
- Effacement memoire du plaintext avec `zeroize`
- Option de suppression complete du coffre local (base RGPD: droit a l'effacement)

## Dependances principales
- `argon2`
- `aes-gcm`
- `bincode`
- `zeroize`
- `rpassword`
- `copypasta`
- `reqwest` (synchronisation API optionnelle)
- `eframe` / `egui` (interface graphique)

## Usage
1. `cargo build`
2. `cargo run` (ouvre la GUI)
3. Au premier lancement: creation du mot de passe maitre
4. Au lancement suivant: authentification sur le mot de passe maitre

### Mode CLI
1. `cargo run -- --cli`
2. Utiliser le menu:
   - `1` Ajouter
   - `2` Lister
   - `3` Copier
   - `4` Generer
   - `5` Supprimer
   - `6` Modifier
   - `7` Purger coffre
   - `8` Export chiffre
   - `9` Quitter

## Tests
- Les tests crypto sont actives via `src/crypto_tests.rs` et compiles avec le binaire.
- Lancement: `cargo test`

## Portabilite
- Cible principale: Windows, macOS, Linux (CLI)
- Android n'est pas encore pris en charge.

## Notes
- Le coffre est local par defaut.
- L'URL API est un placeholder (`API_URL`) et doit etre adaptee avant usage en production.
