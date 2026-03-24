# SECURITY

Ce document explique l'approche sécurité actuelle pour `password_containers`.

## État actuel ✅
- Données chiffrées dans `vault.json` avec AES-256-GCM
- Clé dérivée du mot de passe maître via PBKDF2(HMAC-SHA256) avec 200000 itérations
- `vault.json` ne doit pas être commité (dans `.gitignore`)
- Aucun mécanisme de gestion de mots de passe perdu ou de récupération
- Tests unitaires pour crypto (dérivation de clé, chiffrement/déchiffrement, gestion d'erreurs)

## Tests disponibles 🧪

```bash
cargo test
```

Couvre :
- Dérivation de clé déterministe
- Différenciation par mot de passe
- Différenciation par salt
- Chiffrement/déchiffrement complet
- Nonces uniques = ciphertexts différents
- Erreur si mot de passe décryption incorrect

## Recommandations pour futures versions 🚀

### 1. **Argon2id** (au lieu de PBKDF2)
- Résistance GPU/ASIC bien meilleure
- Configuration : paramètres d'espace/temps adaptés (CPU + mémoire)
- Impact : ~5x plus lent mais 1000x plus dur à brute-force

```rust
// Futur pseudocode
use argon2::{Argon2, ParamsBuilder};
let argon2 = Argon2::new(...);
argon2.hash_password(password, salt)?;
```

### 2. **Lock automatique** après N tentatives échouées
- 3 tentatives maximum de saisie du mot de passe maître
- Délai exponentiel entre tentatives (2s, 4s, 8s)
- Fichier de log ou fichier `.locked` pour état persistant
- Déblocage manuel ou délai (ex: 10 minutes)

```rust
// Futur
let failed_attempts = load_failed_attempts();
if failed_attempts >= 3 {
    sleep(exponential_backoff(failed_attempts));
}
```

### 3. **OTP / 2FA** (Time-based One-Time Password)
- Ajouter support TOTP (Google Authenticator, Authy) via `totp-lite` ou `totp-rs`
- Deuxième facteur : code 6 chiffres toutes les 30 secondes
- Stockage sécurisé du secret TOTP dans `vault.json` aussi chiffré

```rust
// Futur
use totp_lite::Sha1;
let totp = Sha1::generate_token(&seed);
if user_code == totp { allow_unlock() }
```

### 4. **Gestion de la rotation de mot de passe maître**
- Option pour changer le mot de passe maître
- Re-chiffrer tous les secrets avec nouvelle clé + nouveau salt
- Backup préalable du `vault.json` (versionnage ou sauvegarde)

### 5. **Audit & Logging sécurisé**
- Tous les accès/ajouts loggés en hash (sans mots de passe)
- Fichier `.audit.log` horodaté
- Détection d'accès suspects

### 6. **Zeroize amélioré**
- Zeroize tout plaintext après décryption et copy
- Utiliser `volatile` pour éviter les optimisations du compilateur
- Protéger la mémoire stack (difficile en userspace)

### 7. **Libsodium / Age intégration** (optionnel)
- Considérer `age` pour chiffrement plus simple et auditée
- Ou `libsodium` (libsodium.rs) pour des primitives éprouvées + modernes

### 8. **Tests de performance & fuzzing**
- Ajouter benchmarks : `criterion` pour mesurer overhead crypto
- Fuzzing sur déchiffrement (inputs invalides, corrupted data)
- Tests de résistance timing-attacks

## Actions immédates ⚡

- [ ] Ajouter tests de stress / benchmark
- [ ] Ajouter `#[repr(sensitive)]` ou pattern pour zeroize automatique
- [ ] CI/CD via GitHub Actions pour tests et builds
- [ ] Audit externe si déploiement production

## Respect des normes 🛡️

- OWASP : chiffrement au repos ✅, gestion de clé ⚠ (à améliorer)
- NIST : SHA-256 ✅, AES-256 ✅, PBKDF2 ⚠ (Argon2id pour demain)
- CWE : pas d'injection ✅, pas de hardcoded secrets ✅
