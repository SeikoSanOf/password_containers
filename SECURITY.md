# SECURITY

Ce document decrit l'etat de securite actuel du projet `password_containers`.

## Etat actuel
- Donnees chiffrees au repos dans `vault.db` avec AES-256-GCM
- Cle derivee du mot de passe maitre via Argon2id
- Salt (16 octets) et nonce (12 octets) aleatoires a chaque sauvegarde
- Effacement du plaintext en memoire avec `zeroize`
- Export chiffré du coffre pour portabilite des donnees
- Politique d'authentification:
  - 3 tentatives maximum
  - delai exponentiel entre tentatives (2s, 4s, 8s)
  - verrouillage temporaire de 10 minutes (`.vault.lock`)
- Synchronisation API optionnelle (requiert configuration explicite)

## Tests
Les tests cryptographiques couvrent:
- Derivation de cle deterministe
- Variation de cle selon mot de passe/salt
- Chiffrement/dechiffrement roundtrip
- Nonces differents => ciphertexts differents
- Echec de dechiffrement avec mauvais mot de passe

Commande:

```bash
cargo test
```

## Durcissement applique
- Suppression du `unwrap` dans la derivation Argon2
- Propagation des erreurs crypto via `Result`
- Gestion explicite des erreurs de sauvegarde
- Verrouillage anti brute-force persistant (fichier de lock local)

## Base RGPD minimale
Mesures minimales actuellement implantees:
- Chiffrement des donnees sensibles au repos
- Stockage local par defaut (pas de transfert reseau obligatoire)
- Droit a l'effacement: option de purge complete du coffre local
- Droit a la portabilite (base technique): export chiffré du coffre

Mesures a completer pour conformite RGPD operationnelle:
- Registre des traitements et base legale
- Politique de retention explicite
- Mecanismes d'export structure des donnees (droit d'acces/portabilite)
- Journalisation de securite et gestion des incidents
- Informations utilisateurs (notice de confidentialite)

## Limites connues
- Pas de 2FA/TOTP
- Pas de rotation guidee du mot de passe maitre
- API distante non finalisee (placeholder)
- Pas de securisation materielle de la memoire (limite userspace)
