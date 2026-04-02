use aes_gcm::aead::{Aead, KeyInit};
use aes_gcm::{Aes256Gcm, Nonce};
use argon2::{Argon2, Algorithm, Version, Params};
use chrono::{DateTime, Local, Utc};
use eframe::egui;
use keyring::Entry;
use rand::distr::{Alphanumeric, SampleString};
use rand::Rng;
use serde::{Deserialize, Serialize};
use std::error::Error;
use std::fmt;
use std::fs;
use std::io::{self, Write};
use std::path::Path;
use std::sync::mpsc::{self, Receiver, Sender};
use std::thread;
use std::time::{Duration, SystemTime, UNIX_EPOCH};
use zeroize::{Zeroize, Zeroizing};
use copypasta::{ClipboardContext, ClipboardProvider};

#[cfg(test)]
mod crypto_tests;

// --- CONFIGURATION ---
const VAULT_PATH: &str = "vault.db";
const LOCK_PATH: &str = ".vault.lock";
const USER_SETTINGS_PATH: &str = ".user-settings.json";
const API_URL: &str = "https://api.seikodev.fr/sync";
const KEYRING_SERVICE: &str = "password_containers";
const KEYRING_ACCOUNT_SYNC_API_KEY: &str = "sync_api_key";
const MAX_AUTH_ATTEMPTS: u32 = 3;
const AUTH_BASE_DELAY_SECS: u64 = 2;
const LOCKOUT_SECS: u64 = 600;

// --- MODÈLES DE DONNÉES ---

#[derive(Serialize, Deserialize, Debug, Clone, Zeroize)]
#[zeroize(drop)]
struct Secret {
    service: String,
    identifiant: String,
    mot_de_passe: String,
    #[serde(default)]
    created_at: u64,
    #[serde(default)]
    updated_at: u64,
}

#[derive(Serialize, Deserialize)]
struct VaultFile {
    salt: [u8; 16],
    nonce: [u8; 12],
    ciphertext: Vec<u8>,
}

#[derive(Serialize, Deserialize, Clone)]
struct AppSettings {
    appearance_glass: bool,
    appearance_dense_mode: bool,
    sync_enabled: bool,
    sync_url: String,
    #[serde(skip_serializing, default)]
    sync_api_key: String,
    other_remember_section: bool,
}

impl Default for AppSettings {
    fn default() -> Self {
        Self {
            appearance_glass: true,
            appearance_dense_mode: false,
            sync_enabled: false,
            sync_url: API_URL.to_string(),
            sync_api_key: String::new(),
            other_remember_section: true,
        }
    }
}

fn load_user_settings() -> AppSettings {
    if !Path::new(USER_SETTINGS_PATH).exists() {
        let mut cfg = AppSettings::default();
        cfg.sync_api_key = load_sync_api_key_secure().unwrap_or_default();
        return cfg;
    }

    match fs::read_to_string(USER_SETTINGS_PATH)
        .ok()
        .and_then(|s| serde_json::from_str::<AppSettings>(&s).ok())
    {
        Some(mut cfg) => {
            if cfg.sync_url.trim().is_empty() || cfg.sync_url.contains("api.seikodev.fr/vault") {
                cfg.sync_url = API_URL.to_string();
            }

            // Migrate legacy plaintext key from JSON into OS secure storage.
            if !cfg.sync_api_key.trim().is_empty() {
                let _ = save_sync_api_key_secure(&cfg.sync_api_key);
                let _ = write_user_settings_file(&cfg);
            }

            if let Some(secure_key) = load_sync_api_key_secure() {
                cfg.sync_api_key = secure_key;
            }
            cfg
        }
        None => {
            let mut cfg = AppSettings::default();
            cfg.sync_api_key = load_sync_api_key_secure().unwrap_or_default();
            cfg
        }
    }
}

fn save_user_settings(settings: &AppSettings) -> Result<(), AppError> {
    save_sync_api_key_secure(&settings.sync_api_key)?;
    write_user_settings_file(settings)
}

fn write_user_settings_file(settings: &AppSettings) -> Result<(), AppError> {
    let data = serde_json::to_vec_pretty(settings).map_err(|_| AppError::Serialization)?;
    fs::write(USER_SETTINGS_PATH, data).map_err(AppError::Io)
}

fn load_sync_api_key_secure() -> Option<String> {
    let entry = Entry::new(KEYRING_SERVICE, KEYRING_ACCOUNT_SYNC_API_KEY).ok()?;
    match entry.get_password() {
        Ok(value) if !value.trim().is_empty() => Some(value),
        _ => None,
    }
}

fn save_sync_api_key_secure(api_key: &str) -> Result<(), AppError> {
    let entry = Entry::new(KEYRING_SERVICE, KEYRING_ACCOUNT_SYNC_API_KEY)
        .map_err(|e| AppError::Settings(format!("Impossible d'ouvrir le coffre systeme: {}", e)))?;
    entry
        .set_password(api_key)
        .map_err(|e| AppError::Settings(format!("Impossible de stocker la cle API: {}", e)))
}

#[derive(Debug)]
enum AppError {
    Io(io::Error),
    Crypto,
    Serialization,
    AuthFailed,
    AuthLocked(u64),
    Network(String),
    Settings(String),
}

impl fmt::Display for AppError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            AppError::Io(err) => write!(f, "Erreur I/O: {}", err),
            AppError::Crypto => write!(f, "Erreur cryptographique"),
            AppError::Serialization => write!(f, "Erreur de serialisation"),
            AppError::AuthFailed => write!(f, "Mot de passe maitre invalide"),
            AppError::AuthLocked(remaining) => {
                write!(f, "Acces verrouille pendant encore {} seconde(s)", remaining)
            }
            AppError::Network(msg) => write!(f, "Erreur reseau: {}", msg),
            AppError::Settings(msg) => write!(f, "Erreur parametres: {}", msg),
        }
    }
}

impl Error for AppError {}

// --- LOGIQUE CRYPTOGRAPHIQUE ---

fn derive_key(password: &str, salt: &[u8]) -> Result<[u8; 32], AppError> {
    let mut output_key = [0u8; 32];
    // Argon2id avec paramètres recommandés par l'OWASP
    let params = Params::new(65536, 3, 4, Some(32)).map_err(|_| AppError::Crypto)?;
    let argon2 = Argon2::new(Algorithm::Argon2id, Version::V0x13, params);

    argon2
        .hash_password_into(password.as_bytes(), salt, &mut output_key)
        .map_err(|_| AppError::Crypto)?;

    Ok(output_key)
}

fn generate_password(len: usize) -> String {
    Alphanumeric.sample_string(&mut rand::rng(), len)
}

// --- GESTION DU COFFRE (LOCAL & API) ---

fn sauvegarder(
    password: &str,
    secrets: &[Secret],
    sync_cfg: Option<(&str, &str)>,
) -> Result<(), AppError> {
    let mut salt = [0u8; 16];
    let mut nonce_bytes = [0u8; 12];
    let mut rng = rand::rng();
    rng.fill_bytes(&mut salt);
    rng.fill_bytes(&mut nonce_bytes);

    let key = derive_key(password, &salt)?;
    let cipher = Aes256Gcm::new_from_slice(&key).map_err(|_| AppError::Crypto)?;
    let nonce = Nonce::from_slice(&nonce_bytes);

    // Sérialisation binaire avec Zeroize sur le plaintext temporaire
    let mut plaintext = bincode::serialize(secrets).map_err(|_| AppError::Serialization)?;
    let ciphertext = cipher.encrypt(nonce, plaintext.as_ref()).map_err(|_| AppError::Crypto)?;
    plaintext.zeroize(); // Effacement immédiat du clair en RAM

    let vault = VaultFile { salt, nonce: nonce_bytes, ciphertext };
    let binary_data = bincode::serialize(&vault).map_err(|_| AppError::Serialization)?;

    // Sauvegarde locale
    fs::write(VAULT_PATH, &binary_data).map_err(AppError::Io)?;

    // Optionnel : Upload API
    if let Some((key, api_url)) = sync_cfg {
        let target_url = if api_url.trim().is_empty() {
            API_URL
        } else {
            api_url
        };
        envoyer_vault_distance(key, target_url, binary_data)?;
    }

    Ok(())
}

fn envoyer_vault_distance(api_key: &str, sync_url: &str, binary_data: Vec<u8>) -> Result<(), AppError> {
    let client = reqwest::blocking::Client::new();
    let part = reqwest::blocking::multipart::Part::bytes(binary_data)
        .file_name("vault.db")
        .mime_str("application/octet-stream")
        .map_err(|e| AppError::Network(e.to_string()))?;
    let form = reqwest::blocking::multipart::Form::new().part("file", part);

    let resp = client
        .post(sync_url)
        .header("X-API-KEY", api_key)
        .multipart(form)
        .send()
        .map_err(|e| AppError::Network(e.to_string()))?;

    if !resp.status().is_success() {
        return Err(AppError::Network(format!("Echec sync API ({})", resp.status())));
    }

    Ok(())
}

fn synchroniser_vault_fichier(api_key: &str, sync_url: &str) -> Result<(), AppError> {
    let payload = fs::read(VAULT_PATH).map_err(AppError::Io)?;
    envoyer_vault_distance(api_key, sync_url, payload)
}

fn probe_sync_connection(api_key: String, sync_url: String) -> Result<(), String> {
    let download_url = if let Some(base) = sync_url.strip_suffix("/sync") {
        format!("{}/download", base)
    } else {
        format!("{}/download", sync_url.trim_end_matches('/'))
    };

    let client = reqwest::blocking::Client::builder()
        .timeout(Duration::from_secs(8))
        .build()
        .map_err(|e| format!("Echec creation client HTTP: {}", e))?;

    let resp = client
        .get(download_url)
        .header("X-API-KEY", api_key)
        .send()
        .map_err(|e| format!("Erreur reseau Sync: {}", e))?;

    if !resp.status().is_success() {
        let status = resp.status();
        if status.as_u16() == 401 || status.as_u16() == 403 || status.as_u16() == 404 {
            return Err(format!(
                "Connexion Sync KO ({}). Cle API invalide/non autorisee ou endpoint inadapté pour cette cle.",
                status
            ));
        }
        return Err(format!("Connexion Sync KO ({}).", status));
    }

    Ok(())
}

fn recuperer_vault_distante(api_key: &str, sync_url: &str) -> Result<bool, AppError> {
    let target_url = if sync_url.trim().is_empty() {
        API_URL
    } else {
        sync_url
    };

    let download_url = if let Some(base) = target_url.strip_suffix("/sync") {
        format!("{}/download", base)
    } else {
        format!("{}/download", target_url.trim_end_matches('/'))
    };

    let client = reqwest::blocking::Client::builder()
        .timeout(Duration::from_secs(10))
        .build()
        .map_err(|e| AppError::Network(e.to_string()))?;

    let resp = client
        .get(download_url)
        .header("X-API-KEY", api_key)
        .send()
        .map_err(|e| AppError::Network(e.to_string()))?;

    if !resp.status().is_success() {
        return Err(AppError::Network(format!(
            "Echec download serveur ({})",
            resp.status()
        )));
    }

    let remote_bytes = resp
        .bytes()
        .map_err(|e| AppError::Network(e.to_string()))?
        .to_vec();

    // Verifie que le contenu ressemble bien au format attendu du coffre
    let _: VaultFile =
        bincode::deserialize(&remote_bytes).map_err(|_| AppError::Serialization)?;

    if let Ok(local_bytes) = fs::read(VAULT_PATH) {
        if local_bytes == remote_bytes {
            return Ok(false);
        }
    }

    fs::write(VAULT_PATH, remote_bytes).map_err(AppError::Io)?;
    Ok(true)
}

fn charger(password: &str) -> Result<Vec<Secret>, AppError> {
    let data = fs::read(VAULT_PATH).map_err(AppError::Io)?;
    let vault: VaultFile = bincode::deserialize(&data).map_err(|_| AppError::Serialization)?;

    let key = derive_key(password, &vault.salt)?;
    let cipher = Aes256Gcm::new_from_slice(&key).map_err(|_| AppError::Crypto)?;
    let nonce = Nonce::from_slice(&vault.nonce);

    let mut plaintext = cipher.decrypt(nonce, vault.ciphertext.as_ref()).map_err(|_| AppError::AuthFailed)?;
    let secrets: Vec<Secret> = bincode::deserialize(&plaintext).map_err(|_| AppError::Serialization)?;
    plaintext.zeroize();

    Ok(secrets)
}

fn now_unix_secs() -> u64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap_or_else(|_| Duration::from_secs(0))
        .as_secs()
}

fn unlock_task(
    master_pwd: String,
    sync_enabled: bool,
    sync_api_key: String,
    sync_url: String,
    failed_attempts: u32,
) -> UnlockTaskResult {
    let mut attempt_count = failed_attempts;
    let mut sync_note = String::new();

    if sync_enabled && !sync_api_key.trim().is_empty() && !Path::new(VAULT_PATH).exists() {
        match recuperer_vault_distante(sync_api_key.as_str(), sync_url.as_str()) {
            Ok(true) => {
                sync_note = "Coffre recupere depuis le serveur. ".to_string();
            }
            Ok(false) => {}
            Err(e) => {
                sync_note = format!(
                    "Aucun coffre distant recupere ({}). ",
                    e
                );
            }
        }
    }

    if !Path::new(VAULT_PATH).exists() {
        return UnlockTaskResult {
            unlocked: false,
            secrets: Vec::new(),
            failed_attempts: attempt_count,
            status: format!(
                "{}Confirmez le mot de passe pour creer le coffre.",
                sync_note
            ),
        };
    }

    if let Err(e) = enforce_lock_policy() {
        return UnlockTaskResult {
            unlocked: false,
            secrets: Vec::new(),
            failed_attempts: attempt_count,
            status: e.to_string(),
        };
    }

    if sync_enabled && !sync_api_key.trim().is_empty() {
        match recuperer_vault_distante(sync_api_key.as_str(), sync_url.as_str()) {
            Ok(true) => {
                sync_note = "Coffre local mis a jour depuis le serveur. ".to_string();
            }
            Ok(false) => {}
            Err(e) => {
                sync_note = format!(
                    "Sync distante indisponible, ouverture locale maintenue ({}). ",
                    e
                );
            }
        }
    }

    match charger(master_pwd.as_str()) {
        Ok(secrets) => {
            let _ = clear_lock_file();
            UnlockTaskResult {
                unlocked: true,
                secrets,
                failed_attempts: 0,
                status: format!("{}Coffre deverrouille.", sync_note),
            }
        }
        Err(AppError::AuthFailed) => {
            attempt_count += 1;
            if attempt_count >= MAX_AUTH_ATTEMPTS {
                let until = now_unix_secs() + LOCKOUT_SECS;
                let status = if write_lock_until(until).is_ok() {
                    format!(
                        "Trop d'echecs. Verrouillage actif pendant {} secondes.",
                        LOCKOUT_SECS
                    )
                } else {
                    "Echec auth et erreur lors du verrouillage.".to_string()
                };
                return UnlockTaskResult {
                    unlocked: false,
                    secrets: Vec::new(),
                    failed_attempts: attempt_count,
                    status,
                };
            }

            let delay_secs = AUTH_BASE_DELAY_SECS.saturating_mul(1u64 << (attempt_count - 1));
            thread::sleep(Duration::from_secs(delay_secs));
            UnlockTaskResult {
                unlocked: false,
                secrets: Vec::new(),
                failed_attempts: attempt_count,
                status: format!(
                    "Mot de passe invalide. Nouvelle tentative dans {} seconde(s).",
                    delay_secs
                ),
            }
        }
        Err(e) => UnlockTaskResult {
            unlocked: false,
            secrets: Vec::new(),
            failed_attempts: attempt_count,
            status: format!("Erreur ouverture coffre: {}", e),
        },
    }
}

fn read_lock_until() -> Option<u64> {
    fs::read_to_string(LOCK_PATH)
        .ok()
        .and_then(|s| s.trim().parse::<u64>().ok())
}

fn write_lock_until(until: u64) -> Result<(), AppError> {
    fs::write(LOCK_PATH, until.to_string()).map_err(AppError::Io)
}

fn clear_lock_file() -> Result<(), AppError> {
    if Path::new(LOCK_PATH).exists() {
        fs::remove_file(LOCK_PATH).map_err(AppError::Io)?;
    }
    Ok(())
}

fn enforce_lock_policy() -> Result<(), AppError> {
    if let Some(until) = read_lock_until() {
        let now = now_unix_secs();
        if until > now {
            return Err(AppError::AuthLocked(until - now));
        }
        clear_lock_file()?;
    }
    Ok(())
}

fn open_existing_vault_with_retry() -> Result<(Zeroizing<String>, Vec<Secret>), AppError> {
    enforce_lock_policy()?;

    let mut attempts = 0u32;
    loop {
        let pwd = demander_mot_de_passe("Mot de passe maître : ");
        match charger(&pwd) {
            Ok(secrets) => {
                clear_lock_file()?;
                return Ok((pwd, secrets));
            }
            Err(AppError::AuthFailed) => {
                attempts += 1;
                if attempts >= MAX_AUTH_ATTEMPTS {
                    let until = now_unix_secs() + LOCKOUT_SECS;
                    write_lock_until(until)?;
                    return Err(AppError::AuthLocked(LOCKOUT_SECS));
                }

                let delay_secs = AUTH_BASE_DELAY_SECS.saturating_mul(1u64 << (attempts - 1));
                eprintln!(
                    "Mot de passe incorrect. Nouvelle tentative dans {} seconde(s).",
                    delay_secs
                );
                thread::sleep(Duration::from_secs(delay_secs));
            }
            Err(e) => return Err(e),
        }
    }
}

    fn exporter_coffre_chiffre(destination: &str) -> Result<u64, AppError> {
        if !Path::new(VAULT_PATH).exists() {
            return Err(AppError::Io(io::Error::new(
                io::ErrorKind::NotFound,
                "Aucun coffre local a exporter",
            )));
        }

        fs::copy(VAULT_PATH, destination).map_err(AppError::Io)
    }

// --- INTERFACE ---

fn run_cli() {
    println!("--- PassSecure Pro v2.0 (Argon2id + Bincode) ---");

    let (master_pwd, mut coffre) = if !Path::new(VAULT_PATH).exists() {
        println!("[!] Création d'un nouveau coffre.");
        let master_pwd = demander_mot_de_passe("Mot de passe maître : ");
        let confirm = demander_mot_de_passe("Confirmez le mot de passe : ");
        if *master_pwd != *confirm {
            eprintln!("Les mots de passe ne correspondent pas.");
            return;
        }
        (master_pwd, Vec::new())
    } else {
        match open_existing_vault_with_retry() {
            Ok(v) => v,
            Err(AppError::AuthLocked(remaining)) => {
                eprintln!(
                    "Accès verrouillé. Réessayez dans environ {} seconde(s).",
                    remaining
                );
                return;
            }
            Err(e) => {
                eprintln!("Erreur : {}", e);
                return;
            }
        }
    };

    loop {
        println!(
            "\n1. Ajouter | 2. Liste | 3. Copier | 4. Générer PWD | 5. Supprimer | 6. Modifier | 7. Purger coffre | 8. Export chiffré | 9. Quitter"
        );
        print!("Choix : ");
        io::stdout().flush().unwrap();

        let mut input = String::new();
        io::stdin().read_line(&mut input).unwrap();

        match input.trim() {
            "1" => {
                let service = saisir("Service : ");
                let login = saisir("Identifiant : ");
                let mdp = rpassword::prompt_password("Mot de passe (laisser vide pour générer) : ").unwrap();
                
                let mot_de_passe = if mdp.is_empty() {
                    let g = generate_password(24);
                    println!("Généré : {}", g);
                    g
                } else { mdp };

                let ts = now_unix_secs();
                coffre.push(Secret {
                    service,
                    identifiant: login,
                    mot_de_passe,
                    created_at: ts,
                    updated_at: ts,
                });
                if let Err(e) = sauvegarder(&master_pwd, &coffre, None) {
                    eprintln!("Erreur de sauvegarde : {}", e);
                }
            }
            "2" => {
                for (i, s) in coffre.iter().enumerate() {
                    println!("{}. {} [{}]", i + 1, s.service, s.identifiant);
                }
            }
            "3" => {
                print!("Numéro : ");
                io::stdout().flush().unwrap();
                let mut n = String::new();
                io::stdin().read_line(&mut n).unwrap();
                if let Ok(idx) = n.trim().parse::<usize>() {
                    if idx > 0 && idx <= coffre.len() {
                        let mdp = coffre[idx-1].mot_de_passe.clone();
                        if let Ok(mut ctx) = ClipboardContext::new() {
                            ctx.set_contents(mdp).unwrap();
                            println!("[✓] Copié dans le presse-papier.");
                        }
                    }
                }
            }
            "5" => {
                print!("Numéro à supprimer : ");
                io::stdout().flush().unwrap();
                let mut n = String::new();
                io::stdin().read_line(&mut n).unwrap();
                if let Ok(idx) = n.trim().parse::<usize>() {
                    if idx > 0 && idx <= coffre.len() {
                        coffre.remove(idx - 1);
                        if let Err(e) = sauvegarder(&master_pwd, &coffre, None) {
                            eprintln!("Erreur de sauvegarde : {}", e);
                        }
                        println!("Supprimé.");
                    }
                }
            }
            "6" => {
                print!("Numéro à modifier : ");
                io::stdout().flush().unwrap();
                let mut n = String::new();
                io::stdin().read_line(&mut n).unwrap();

                if let Ok(idx) = n.trim().parse::<usize>() {
                    if idx > 0 && idx <= coffre.len() {
                        let item = &mut coffre[idx - 1];
                        println!("Laisser vide pour conserver la valeur actuelle.");

                        let nouveau_service = saisir("Nouveau service : ");
                        if !nouveau_service.is_empty() {
                            item.service = nouveau_service;
                        }

                        let nouvel_identifiant = saisir("Nouvel identifiant : ");
                        if !nouvel_identifiant.is_empty() {
                            item.identifiant = nouvel_identifiant;
                        }

                        let nouveau_mdp = rpassword::prompt_password(
                            "Nouveau mot de passe (vide = conserver, 'gen' = générer) : ",
                        )
                        .unwrap_or_default();

                        if nouveau_mdp == "gen" {
                            let g = generate_password(24);
                            println!("Nouveau mot de passe généré : {}", g);
                            item.mot_de_passe = g;
                        } else if !nouveau_mdp.is_empty() {
                            item.mot_de_passe = nouveau_mdp;
                        }

                        item.updated_at = now_unix_secs();

                        if let Err(e) = sauvegarder(&master_pwd, &coffre, None) {
                            eprintln!("Erreur de sauvegarde : {}", e);
                        } else {
                            println!("Entrée modifiée.");
                        }
                    }
                }
            }
            "7" => {
                println!("Cette action supprime le coffre local (base RGPD: droit à l'effacement).");
                let confirmation = saisir("Tapez SUPPRIMER pour confirmer : ");
                if confirmation == "SUPPRIMER" {
                    coffre.clear();
                    if Path::new(VAULT_PATH).exists() {
                        if let Err(e) = fs::remove_file(VAULT_PATH) {
                            eprintln!("Impossible de supprimer le coffre : {}", e);
                        }
                    }
                    let _ = clear_lock_file();
                    println!("Coffre local supprimé.");
                    break;
                }
                println!("Annulé.");
            }
            "8" => {
                let destination = saisir("Chemin du fichier export (ex: backup.vault.db) : ");
                if destination.is_empty() {
                    println!("Chemin vide, export annulé.");
                    continue;
                }

                match exporter_coffre_chiffre(&destination) {
                    Ok(bytes) => println!("Export chiffré réussi ({} octets).", bytes),
                    Err(e) => eprintln!("Erreur d'export : {}", e),
                }
            }
            "9" => break,
            _ => println!("Option invalide."),
        }
    }
}

struct VaultGuiApp {
    master_pwd: String,
    confirm_pwd: String,
    unlocked: bool,
    secrets: Vec<Secret>,
    selected: Option<usize>,
    service_input: String,
    identifiant_input: String,
    password_input: String,
    export_path: String,
    search_query: String,
    show_password: bool,
    reveal_detail_password: bool,
    show_delete_modal: bool,
    show_purge_modal: bool,
    show_entry_modal: bool,
    modal_edit_index: Option<usize>,
    show_sync_api_key: bool,
    sort_mode: SortMode,
    active_section: UiSection,
    settings_category: SettingsCategory,
    settings: AppSettings,
    sync_probe_state: SyncProbeState,
    sync_probe_in_flight: bool,
    save_local_in_flight: bool,
    save_local_pending: bool,
    sync_upload_in_flight: bool,
    sync_upload_pending: bool,
    unlock_in_flight: bool,
    bg_tx: Sender<BackgroundEvent>,
    bg_rx: Receiver<BackgroundEvent>,
    status: String,
    failed_attempts: u32,
}

#[derive(Clone, Copy, PartialEq, Eq)]
enum SortMode {
    ServiceAsc,
    UpdatedDesc,
    CreatedDesc,
}

#[derive(Clone, Copy, PartialEq, Eq)]
enum UiSection {
    Vault,
    Transfer,
    Settings,
}

#[derive(Clone, Copy, PartialEq, Eq)]
enum SettingsCategory {
    Appearance,
    Sync,
    Other,
}

#[derive(Clone, Copy, PartialEq, Eq)]
enum SyncProbeState {
    Unknown,
    Online,
    Offline,
}

enum BackgroundEvent {
    SaveLocalDone(Result<(), String>),
    SyncUploadDone(Result<(), String>),
    SyncProbeDone(Result<(), String>),
    UnlockDone(UnlockTaskResult),
}

struct UnlockTaskResult {
    unlocked: bool,
    secrets: Vec<Secret>,
    failed_attempts: u32,
    status: String,
}

impl Default for VaultGuiApp {
    fn default() -> Self {
        let (bg_tx, bg_rx) = mpsc::channel();
        Self {
            master_pwd: String::new(),
            confirm_pwd: String::new(),
            unlocked: false,
            secrets: Vec::new(),
            selected: None,
            service_input: String::new(),
            identifiant_input: String::new(),
            password_input: String::new(),
            export_path: String::from("backup.vault.db"),
            search_query: String::new(),
            show_password: false,
            reveal_detail_password: false,
            show_delete_modal: false,
            show_purge_modal: false,
            show_entry_modal: false,
            modal_edit_index: None,
            show_sync_api_key: false,
            sort_mode: SortMode::UpdatedDesc,
            active_section: UiSection::Vault,
            settings_category: SettingsCategory::Appearance,
            settings: load_user_settings(),
            sync_probe_state: SyncProbeState::Unknown,
            sync_probe_in_flight: false,
            save_local_in_flight: false,
            save_local_pending: false,
            sync_upload_in_flight: false,
            sync_upload_pending: false,
            unlock_in_flight: false,
            bg_tx,
            bg_rx,
            status: String::from("Entrez votre mot de passe maitre pour ouvrir ou creer le coffre."),
            failed_attempts: 0,
        }
    }
}

impl VaultGuiApp {
    fn apply_custom_style(&self, ctx: &egui::Context) {
        let mut style = (*ctx.style()).clone();
        style.visuals = egui::Visuals::dark();
        style.spacing.item_spacing = if self.settings.appearance_dense_mode {
            egui::vec2(8.0, 8.0)
        } else {
            egui::vec2(10.0, 10.0)
        };
        style.spacing.button_padding = if self.settings.appearance_dense_mode {
            egui::vec2(10.0, 6.0)
        } else {
            egui::vec2(14.0, 8.0)
        };
        style.visuals.window_fill = egui::Color32::from_rgb(12, 14, 22);
        style.visuals.panel_fill = egui::Color32::from_rgb(16, 18, 28);
        style.visuals.faint_bg_color = egui::Color32::from_rgb(21, 24, 36);
        style.visuals.widgets.inactive.bg_fill = egui::Color32::from_rgb(31, 35, 52);
        style.visuals.widgets.hovered.bg_fill = egui::Color32::from_rgb(54, 59, 86);
        style.visuals.widgets.active.bg_fill = egui::Color32::from_rgb(168, 85, 247);
        style.visuals.selection.bg_fill = egui::Color32::from_rgb(147, 51, 234);
        style.visuals.override_text_color = Some(egui::Color32::from_rgb(231, 235, 246));
        ctx.set_style(style);
    }

    fn glass_frame(&self) -> egui::Frame {
        let alpha = if self.settings.appearance_glass { 180 } else { 255 };
        egui::Frame::new()
            .fill(egui::Color32::from_rgba_unmultiplied(34, 39, 59, alpha))
            .stroke(egui::Stroke::new(
                1.0,
                egui::Color32::from_rgba_unmultiplied(153, 171, 218, 110),
            ))
            .corner_radius(egui::CornerRadius::same(12))
            .inner_margin(egui::Margin::same(12))
    }

    fn section_items() -> [(UiSection, &'static str, &'static str); 3] {
        [
            (UiSection::Vault, "DB", "Coffre"),
            (UiSection::Transfer, "EX", "Export"),
            (UiSection::Settings, "ST", "Parametres"),
        ]
    }

    fn settings_category_items() -> [(SettingsCategory, &'static str); 3] {
        [
            (SettingsCategory::Appearance, "Apparence"),
            (SettingsCategory::Sync, "Sync"),
            (SettingsCategory::Other, "Autres"),
        ]
    }

    fn sync_badge(&self) -> (&'static str, egui::Color32, &'static str) {
        if !self.settings.sync_enabled {
            return ("OFF", egui::Color32::from_rgb(148, 163, 184), "Sync desactivee");
        }
        if self.settings.sync_api_key.trim().is_empty() {
            return (
                "OFF",
                egui::Color32::from_rgb(148, 163, 184),
                "Cle API manquante",
            );
        }
        if self.sync_probe_in_flight || self.sync_upload_in_flight {
            return (
                "TEST",
                egui::Color32::from_rgb(251, 191, 36),
                "Operation reseau en cours",
            );
        }

        match self.sync_probe_state {
            SyncProbeState::Online => (
                "ON",
                egui::Color32::from_rgb(74, 222, 128),
                "Connexion API valide",
            ),
            SyncProbeState::Offline => (
                "OFF",
                egui::Color32::from_rgb(248, 113, 113),
                "Connexion API invalide",
            ),
            SyncProbeState::Unknown => (
                "TEST",
                egui::Color32::from_rgb(251, 191, 36),
                "Connexion non testee",
            ),
        }
    }

    fn test_sync_connection(&mut self) {
        if !self.settings.sync_enabled {
            self.sync_probe_state = SyncProbeState::Unknown;
            self.status = "Sync desactivee par utilisateur.".to_string();
            return;
        }
        if self.settings.sync_api_key.trim().is_empty() {
            self.sync_probe_state = SyncProbeState::Unknown;
            self.status = "Renseignez la cle API pour tester la connexion.".to_string();
            return;
        }
        if self.sync_probe_in_flight {
            return;
        }

        self.sync_probe_in_flight = true;
        self.status = "Test de connexion sync en cours...".to_string();

        let api_key = self.settings.sync_api_key.clone();
        let sync_url = if self.settings.sync_url.trim().is_empty() {
            API_URL.to_string()
        } else {
            self.settings.sync_url.trim().to_string()
        };
        let tx = self.bg_tx.clone();
        thread::spawn(move || {
            let result = probe_sync_connection(api_key, sync_url);
            let _ = tx.send(BackgroundEvent::SyncProbeDone(result));
        });
    }

    fn process_background_events(&mut self) {
        while let Ok(event) = self.bg_rx.try_recv() {
            match event {
                BackgroundEvent::SaveLocalDone(Ok(())) => {
                    self.save_local_in_flight = false;
                    self.status = "Coffre sauvegarde localement.".to_string();
                    self.start_sync_upload();
                    if self.save_local_pending {
                        self.save_local_pending = false;
                        self.start_local_save();
                    }
                }
                BackgroundEvent::SaveLocalDone(Err(err)) => {
                    self.save_local_in_flight = false;
                    self.status = format!("Erreur sauvegarde locale: {}", err);
                    if self.save_local_pending {
                        self.save_local_pending = false;
                        self.start_local_save();
                    }
                }
                BackgroundEvent::SyncUploadDone(Ok(())) => {
                    self.sync_upload_in_flight = false;
                    self.sync_probe_state = SyncProbeState::Online;
                    self.status = "Coffre sauvegarde et sync distante terminee.".to_string();
                    if self.sync_upload_pending {
                        self.sync_upload_pending = false;
                        self.start_sync_upload();
                    }
                }
                BackgroundEvent::SyncUploadDone(Err(err)) => {
                    self.sync_upload_in_flight = false;
                    self.sync_probe_state = SyncProbeState::Offline;
                    self.status = format!(
                        "Sauvegarde locale OK, mais sync distante en echec: {}",
                        err
                    );
                    if self.sync_upload_pending {
                        self.sync_upload_pending = false;
                        self.start_sync_upload();
                    }
                }
                BackgroundEvent::SyncProbeDone(Ok(())) => {
                    self.sync_probe_in_flight = false;
                    self.sync_probe_state = SyncProbeState::Online;
                    self.status = "Connexion Sync OK.".to_string();
                }
                BackgroundEvent::SyncProbeDone(Err(err)) => {
                    self.sync_probe_in_flight = false;
                    self.sync_probe_state = SyncProbeState::Offline;
                    self.status = err;
                }
                BackgroundEvent::UnlockDone(result) => {
                    self.unlock_in_flight = false;
                    self.failed_attempts = result.failed_attempts;
                    self.status = result.status;
                    if result.unlocked {
                        self.unlocked = true;
                        self.secrets = result.secrets;
                    }
                }
            }
        }
    }

    fn start_sync_upload(&mut self) {
        if !self.settings.sync_enabled || self.settings.sync_api_key.trim().is_empty() {
            return;
        }
        if self.sync_upload_in_flight {
            self.sync_upload_pending = true;
            return;
        }

        self.sync_upload_in_flight = true;
        self.status = "Coffre sauvegarde localement. Sync distante en cours...".to_string();

        let api_key = self.settings.sync_api_key.clone();
        let sync_url = if self.settings.sync_url.trim().is_empty() {
            API_URL.to_string()
        } else {
            self.settings.sync_url.trim().to_string()
        };
        let tx = self.bg_tx.clone();
        thread::spawn(move || {
            let result = synchroniser_vault_fichier(api_key.as_str(), sync_url.as_str())
                .map_err(|e| e.to_string());
            let _ = tx.send(BackgroundEvent::SyncUploadDone(result));
        });
    }

    fn start_local_save(&mut self) {
        if self.master_pwd.is_empty() {
            self.status = "Mot de passe maitre manquant: sauvegarde impossible.".to_string();
            return;
        }
        if self.save_local_in_flight {
            self.save_local_pending = true;
            return;
        }

        self.save_local_in_flight = true;
        self.status = "Sauvegarde locale en cours...".to_string();

        let master_pwd = self.master_pwd.clone();
        let secrets = self.secrets.clone();
        let tx = self.bg_tx.clone();
        thread::spawn(move || {
            let result = sauvegarder(&master_pwd, &secrets, None).map_err(|e| e.to_string());
            let _ = tx.send(BackgroundEvent::SaveLocalDone(result));
        });
    }

    fn start_unlock_async(&mut self) {
        if self.unlock_in_flight {
            return;
        }

        self.unlock_in_flight = true;
        self.status = "Chargement du coffre...".to_string();

        let master_pwd = self.master_pwd.clone();
        let sync_enabled = self.settings.sync_enabled;
        let sync_api_key = self.settings.sync_api_key.clone();
        let sync_url = if self.settings.sync_url.trim().is_empty() {
            API_URL.to_string()
        } else {
            self.settings.sync_url.trim().to_string()
        };
        let failed_attempts = self.failed_attempts;
        let tx = self.bg_tx.clone();

        thread::spawn(move || {
            let result = unlock_task(master_pwd, sync_enabled, sync_api_key, sync_url, failed_attempts);
            let _ = tx.send(BackgroundEvent::UnlockDone(result));
        });
    }

    fn can_probe_sync(&self) -> bool {
        self.settings.sync_enabled && !self.settings.sync_api_key.trim().is_empty()
    }

    fn filtered_indices(&self) -> Vec<usize> {
        let mut indices: Vec<usize> = if self.search_query.trim().is_empty() {
            (0..self.secrets.len()).collect()
        } else {
            let needle = self.search_query.to_lowercase();
            self.secrets
            .iter()
            .enumerate()
            .filter_map(|(idx, s)| {
                let service = s.service.to_lowercase();
                let identifiant = s.identifiant.to_lowercase();
                if service.contains(&needle) || identifiant.contains(&needle) {
                    Some(idx)
                } else {
                    None
                }
            })
            .collect()
        };

        match self.sort_mode {
            SortMode::ServiceAsc => indices.sort_by_key(|i| self.secrets[*i].service.to_lowercase()),
            SortMode::UpdatedDesc => {
                indices.sort_by_key(|i| std::cmp::Reverse(self.secrets[*i].updated_at))
            }
            SortMode::CreatedDesc => {
                indices.sort_by_key(|i| std::cmp::Reverse(self.secrets[*i].created_at))
            }
        }

        indices
    }

    fn sort_mode_label(&self) -> &'static str {
        match self.sort_mode {
            SortMode::ServiceAsc => "Service (A-Z)",
            SortMode::UpdatedDesc => "Date maj (recent d'abord)",
            SortMode::CreatedDesc => "Date creation (recent d'abord)",
        }
    }

    fn password_strength(password: &str) -> (&'static str, egui::Color32) {
        let len = password.chars().count();
        let has_lower = password.chars().any(|c| c.is_ascii_lowercase());
        let has_upper = password.chars().any(|c| c.is_ascii_uppercase());
        let has_digit = password.chars().any(|c| c.is_ascii_digit());
        let has_symbol = password.chars().any(|c| !c.is_ascii_alphanumeric());
        let classes = [has_lower, has_upper, has_digit, has_symbol]
            .iter()
            .filter(|v| **v)
            .count();

        if len >= 16 && classes >= 3 {
            ("Fort", egui::Color32::from_rgb(74, 222, 128))
        } else if len >= 12 && classes >= 2 {
            ("Moyen", egui::Color32::from_rgb(251, 191, 36))
        } else {
            ("Faible", egui::Color32::from_rgb(248, 113, 113))
        }
    }

    fn ts_label(ts: u64) -> String {
        if ts == 0 {
            "N/A".to_string()
        } else {
            match DateTime::<Utc>::from_timestamp(ts as i64, 0) {
                Some(dt) => dt
                    .with_timezone(&Local)
                    .format("%d/%m/%Y %H:%M")
                    .to_string(),
                None => "N/A".to_string(),
            }
        }
    }

    fn masked_password(password: &str) -> String {
        "*".repeat(password.chars().count().max(8))
    }

    fn load_selected_into_form(&mut self) {
        if let Some(i) = self.selected {
            if let Some(secret) = self.secrets.get(i) {
                self.service_input = secret.service.clone();
                self.identifiant_input = secret.identifiant.clone();
                self.password_input = secret.mot_de_passe.clone();
            }
        }
    }

    fn open_new_entry_modal(&mut self) {
        self.modal_edit_index = None;
        self.selected = None;
        self.service_input.clear();
        self.identifiant_input.clear();
        self.password_input.clear();
        self.show_entry_modal = true;
    }

    fn open_edit_entry_modal(&mut self, idx: usize) {
        if idx < self.secrets.len() {
            self.selected = Some(idx);
            self.modal_edit_index = Some(idx);
            self.load_selected_into_form();
            self.show_entry_modal = true;
        }
    }

    fn save_entry_modal(&mut self) {
        if let Some(i) = self.modal_edit_index {
            self.selected = Some(i);
            self.update_selected_entry();
        } else {
            self.add_new_entry();
        }
        self.show_entry_modal = false;
    }

    fn persist(&mut self) {
        self.start_local_save();
    }

    fn unlock_or_create(&mut self) {
        if self.master_pwd.is_empty() {
            self.status = String::from("Le mot de passe maitre est requis.");
            return;
        }

        if !Path::new(VAULT_PATH).exists() {
            // Sans sync distante, creation locale immediate.
            if self.settings.sync_enabled && !self.settings.sync_api_key.trim().is_empty() {
                self.start_unlock_async();
                return;
            }

            if self.confirm_pwd.is_empty() {
                self.status = String::from("Confirmez le mot de passe pour creer le coffre.");
                return;
            }
            if self.confirm_pwd != self.master_pwd {
                self.status = String::from("Confirmation invalide.");
                return;
            }
            self.unlocked = true;
            self.secrets.clear();
            self.status = String::from("Nouveau coffre cree. Ajoutez une premiere entree.");
            return;
        }

        self.start_unlock_async();
    }

    fn add_new_entry(&mut self) {
        if self.service_input.trim().is_empty() || self.identifiant_input.trim().is_empty() {
            self.status = String::from("Service et identifiant sont obligatoires.");
            return;
        }

        if self.password_input.trim().is_empty() {
            self.password_input = generate_password(24);
        }

        let now = now_unix_secs();
        let next = Secret {
            service: self.service_input.trim().to_string(),
            identifiant: self.identifiant_input.trim().to_string(),
            mot_de_passe: self.password_input.clone(),
            created_at: now,
            updated_at: now,
        };

        self.secrets.push(next);
        self.selected = None;
        self.status = String::from("Nouvelle entree ajoutee.");
        self.persist();
    }

    fn update_selected_entry(&mut self) {
        if self.service_input.trim().is_empty() || self.identifiant_input.trim().is_empty() {
            self.status = String::from("Service et identifiant sont obligatoires.");
            return;
        }

        let Some(i) = self.selected else {
            self.status = "Selectionnez d'abord une entree a mettre a jour.".to_string();
            return;
        };

        if i >= self.secrets.len() {
            self.status = "Selection invalide pour la mise a jour.".to_string();
            return;
        }

        if self.password_input.trim().is_empty() {
            self.password_input = generate_password(24);
        }

        let now = now_unix_secs();
        let created = self.secrets[i].created_at;
        self.secrets[i] = Secret {
            service: self.service_input.trim().to_string(),
            identifiant: self.identifiant_input.trim().to_string(),
            mot_de_passe: self.password_input.clone(),
            created_at: if created == 0 { now } else { created },
            updated_at: now,
        };

        self.status = String::from("Entree mise a jour.");

        self.persist();
    }

    fn delete_selected(&mut self) {
        if let Some(i) = self.selected {
            if i < self.secrets.len() {
                self.secrets.remove(i);
                self.selected = None;
                self.service_input.clear();
                self.identifiant_input.clear();
                self.password_input.clear();
                self.status = String::from("Entree supprimee.");
                self.persist();
            }
        }
    }

    fn copy_password(&mut self) {
        if let Some(i) = self.selected {
            if i < self.secrets.len() {
                if let Ok(mut ctx) = ClipboardContext::new() {
                    if ctx
                        .set_contents(self.secrets[i].mot_de_passe.clone())
                        .is_ok()
                    {
                        self.status = String::from("Mot de passe copie dans le presse-papiers.");
                    }
                }
            }
        }
    }

    fn purge_vault(&mut self) {
        self.secrets.clear();
        self.selected = None;
        self.service_input.clear();
        self.identifiant_input.clear();
        self.password_input.clear();
        if Path::new(VAULT_PATH).exists() {
            match fs::remove_file(VAULT_PATH) {
                Ok(_) => self.status = String::from("Coffre local supprime."),
                Err(e) => self.status = format!("Echec purge: {}", e),
            }
        }
        let _ = clear_lock_file();
    }
}

impl eframe::App for VaultGuiApp {
    fn update(&mut self, ctx: &egui::Context, _frame: &mut eframe::Frame) {
        self.process_background_events();
        if self.sync_probe_in_flight || self.sync_upload_in_flight || self.unlock_in_flight {
            ctx.request_repaint_after(Duration::from_millis(100));
        }
        self.apply_custom_style(ctx);

        egui::TopBottomPanel::top("top").show(ctx, |ui| {
            ui.horizontal_wrapped(|ui| {
                ui.heading(egui::RichText::new("PassSecure Workspace").strong().size(20.0));
                ui.separator();
                ui.label("Interface securisee locale");
                ui.separator();
                ui.label(egui::RichText::new(format!("{} entree(s)", self.secrets.len())).strong());
                if self.unlocked {
                    ui.colored_label(egui::Color32::from_rgb(74, 222, 128), "SESSION OUVERTE");
                } else {
                    ui.colored_label(egui::Color32::from_rgb(251, 191, 36), "SESSION VERROUILLEE");
                }
                let (sync_state, sync_color, sync_help) = self.sync_badge();
                ui.separator();
                ui.colored_label(sync_color, "●");
                ui.label(format!("SYNC {}", sync_state)).on_hover_text(sync_help);
            });
        });

        if !self.unlocked {
            egui::CentralPanel::default().show(ctx, |ui| {
                ui.vertical_centered(|ui| {
                    ui.add_space(40.0);
                    self.glass_frame()
                        .show(ui, |ui| {
                            ui.set_max_width(520.0);
                            ui.heading("Bienvenue dans PassSecure");
                            ui.label("Deverrouillez votre coffre ou creez un nouvel espace securise.");
                            ui.add_space(10.0);
                            ui.add_enabled_ui(!self.unlock_in_flight, |ui| {
                                ui.add(
                                    egui::TextEdit::singleline(&mut self.master_pwd)
                                        .hint_text("Mot de passe maitre")
                                        .password(true),
                                );

                                if !Path::new(VAULT_PATH).exists() {
                                    ui.add(
                                        egui::TextEdit::singleline(&mut self.confirm_pwd)
                                            .hint_text("Confirmation")
                                            .password(true),
                                    );
                                }

                                ui.add_space(8.0);
                                if ui
                                    .add_sized([200.0, 32.0], egui::Button::new("Ouvrir le coffre"))
                                    .clicked()
                                {
                                    self.unlock_or_create();
                                }
                            });

                            if self.unlock_in_flight {
                                ui.add_space(10.0);
                                ui.horizontal(|ui| {
                                    ui.add(egui::Spinner::new());
                                    ui.label("Chargement...");
                                });
                            }
                        });
                    ui.add_space(10.0);
                    ui.label(&self.status);
                });
            });
            return;
        }

        egui::SidePanel::left("nav_rail")
            .resizable(false)
            .exact_width(86.0)
            .show(ctx, |ui| {
                ui.add_space(6.0);
                self.glass_frame().show(ui, |ui| {
                    ui.vertical_centered(|ui| {
                        ui.heading("PS");
                    });
                });
                ui.add_space(8.0);

                for (section, icon, label) in Self::section_items() {
                    let selected = self.active_section == section;
                    let text = if selected {
                        egui::RichText::new(icon).strong().color(egui::Color32::WHITE)
                    } else {
                        egui::RichText::new(icon)
                    };

                    let button = egui::Button::new(text)
                        .min_size(egui::vec2(52.0, 44.0))
                        .fill(if selected {
                            egui::Color32::from_rgb(147, 51, 234)
                        } else {
                            egui::Color32::from_rgba_unmultiplied(49, 57, 84, 160)
                        });

                    if ui.add(button).on_hover_text(label).clicked() {
                        self.active_section = section;
                    }
                    ui.add_space(6.0);
                }
            });

        egui::SidePanel::left("context_drawer")
            .resizable(true)
            .default_width(320.0)
            .show(ctx, |ui| {
                match self.active_section {
                    UiSection::Vault => {
                        ui.heading("Coffre");
                        ui.add(
                            egui::TextEdit::singleline(&mut self.search_query)
                                .hint_text("Rechercher un service"),
                        );
                        egui::ComboBox::from_label("Tri")
                            .selected_text(self.sort_mode_label())
                            .show_ui(ui, |ui| {
                                ui.selectable_value(&mut self.sort_mode, SortMode::UpdatedDesc, "Date maj (recent d'abord)");
                                ui.selectable_value(&mut self.sort_mode, SortMode::CreatedDesc, "Date creation (recent d'abord)");
                                ui.selectable_value(&mut self.sort_mode, SortMode::ServiceAsc, "Service (A-Z)");
                            });
                        let filtered = self.filtered_indices();
                        ui.label(format!("{} resultat(s)", filtered.len()));
                        ui.separator();
                        egui::ScrollArea::vertical().show(ui, |ui| {
                            for idx in filtered {
                                let is_selected = self.selected == Some(idx);
                                let service = self.secrets[idx].service.clone();
                                let identifiant = self.secrets[idx].identifiant.clone();
                                let (level, color) = Self::password_strength(&self.secrets[idx].mot_de_passe);

                                self.glass_frame().show(ui, |ui| {
                                    ui.horizontal(|ui| {
                                        if ui
                                            .selectable_label(
                                                is_selected,
                                                egui::RichText::new(service).strong().size(15.0),
                                            )
                                            .clicked()
                                        {
                                            self.selected = Some(idx);
                                            self.load_selected_into_form();
                                        }
                                        ui.colored_label(color, level);
                                    });
                                    ui.label(egui::RichText::new(identifiant).small());
                                });
                            }
                        });
                    }
                    UiSection::Transfer => {
                        ui.heading("Export et maintenance");
                        self.glass_frame().show(ui, |ui| {
                            ui.label("Exportez ou purgez le coffre local en securite.");
                        });
                    }
                    UiSection::Settings => {
                        ui.heading("Parametres");
                        self.glass_frame().show(ui, |ui| {
                            for (cat, label) in Self::settings_category_items() {
                                if ui.selectable_label(self.settings_category == cat, label).clicked() {
                                    self.settings_category = cat;
                                }
                            }
                        });
                    }
                }
            });

        egui::SidePanel::right("summary")
            .resizable(true)
            .default_width(280.0)
            .show(ctx, |ui| {
                ui.heading("Apercu");
                self.glass_frame().show(ui, |ui| {
                    if let Some(i) = self.selected {
                        if i < self.secrets.len() {
                            let s = &self.secrets[i];
                            let (level, color) = Self::password_strength(&s.mot_de_passe);
                            ui.label(egui::RichText::new(&s.service).strong().size(18.0));
                            ui.label(format!("Identifiant: {}", s.identifiant));
                            ui.label(format!("Cree le: {}", Self::ts_label(s.created_at)));
                            ui.label(format!("Mis a jour: {}", Self::ts_label(s.updated_at)));
                            ui.colored_label(color, format!("Robustesse: {}", level));
                            ui.checkbox(&mut self.reveal_detail_password, "Afficher le mot de passe");
                            let displayed = if self.reveal_detail_password {
                                s.mot_de_passe.clone()
                            } else {
                                Self::masked_password(&s.mot_de_passe)
                            };
                            ui.monospace(displayed);
                            if ui.button("Copier le mot de passe").clicked() {
                                self.copy_password();
                            }
                        }
                    } else {
                        ui.label("Selectionnez une entree pour charger le detail.");
                    }
                });

                ui.add_space(10.0);
                self.glass_frame().show(ui, |ui| {
                    ui.label(egui::RichText::new("Etat").strong());
                    ui.label(&self.status);
                });
            });

        egui::CentralPanel::default().show(ctx, |ui| {
            match self.active_section {
                UiSection::Vault => {
                    ui.heading("Vue table");
                    ui.separator();
                    ui.horizontal(|ui| {
                        if ui.button("+ Nouveau mot de passe").clicked() {
                            self.open_new_entry_modal();
                        }
                    });
                    self.glass_frame().show(ui, |ui| {
                        egui::Grid::new("vault_table")
                            .striped(true)
                            .num_columns(5)
                            .show(ui, |ui| {
                                ui.strong("Service");
                                ui.strong("Identifiant");
                                ui.strong("Maj");
                                ui.strong("Score");
                                ui.strong("Actions");
                                ui.end_row();

                                for idx in self.filtered_indices() {
                                    let service = self.secrets[idx].service.clone();
                                    let identifiant = self.secrets[idx].identifiant.clone();
                                    let updated_at = self.secrets[idx].updated_at;
                                    let (level, color) =
                                        Self::password_strength(&self.secrets[idx].mot_de_passe);
                                    if ui.selectable_label(self.selected == Some(idx), service).clicked() {
                                        self.selected = Some(idx);
                                        self.load_selected_into_form();
                                    }
                                    ui.label(identifiant);
                                    ui.label(Self::ts_label(updated_at));
                                    ui.colored_label(color, level);
                                    ui.horizontal(|ui| {
                                        if ui.button("Edit").clicked() {
                                            self.open_edit_entry_modal(idx);
                                        }
                                        if ui.button("Suppr").clicked() {
                                            self.selected = Some(idx);
                                            self.show_delete_modal = true;
                                        }
                                    });
                                    ui.end_row();
                                }
                            });
                    });
                }
                UiSection::Transfer => {
                    ui.heading("Export et maintenance");
                    ui.separator();
                    self.glass_frame().show(ui, |ui| {
                        ui.label("Export chiffre (portabilite RGPD)");
                        ui.add(egui::TextEdit::singleline(&mut self.export_path).hint_text("backup.vault.db"));
                        if ui.button("Exporter une copie chiffree").clicked() {
                            match exporter_coffre_chiffre(self.export_path.trim()) {
                                Ok(bytes) => self.status = format!("Export reussi ({} octets).", bytes),
                                Err(e) => self.status = format!("Export en erreur: {}", e),
                            }
                        }

                        ui.add_space(12.0);
                        if ui
                            .add_sized([240.0, 32.0], egui::Button::new("Purger le coffre local"))
                            .clicked()
                        {
                            self.show_purge_modal = true;
                        }
                    });
                }
                UiSection::Settings => {
                    ui.heading("Parametres utilisateur");
                    ui.separator();
                    self.glass_frame().show(ui, |ui| match self.settings_category {
                        SettingsCategory::Appearance => {
                            ui.label("Personnalisez l'interface locale.");
                            ui.checkbox(&mut self.settings.appearance_glass, "Activer glassmorphism sombre");
                            ui.checkbox(&mut self.settings.appearance_dense_mode, "Mode compact");
                        }
                        SettingsCategory::Sync => {
                            ui.label("Synchronisation API optionnelle.");
                            if ui
                                .checkbox(
                                    &mut self.settings.sync_enabled,
                                    "Activer la synchronisation distante",
                                )
                                .changed()
                            {
                                self.sync_probe_state = SyncProbeState::Unknown;
                                if self.can_probe_sync() {
                                    self.test_sync_connection();
                                }
                            }
                            ui.horizontal(|ui| {
                                let key_changed = ui
                                    .add(
                                    egui::TextEdit::singleline(&mut self.settings.sync_api_key)
                                        .hint_text("Cle API")
                                        .password(!self.show_sync_api_key),
                                )
                                .changed();
                                ui.checkbox(&mut self.show_sync_api_key, "Afficher");
                                if key_changed {
                                    self.sync_probe_state = SyncProbeState::Unknown;
                                }
                            });
                            let (sync_state, sync_color, sync_help) = self.sync_badge();
                            ui.horizontal(|ui| {
                                ui.colored_label(sync_color, "●");
                                ui.label(format!("Etat Sync: {}", sync_state))
                                    .on_hover_text(sync_help);
                            });
                            if self.can_probe_sync() && self.sync_probe_state == SyncProbeState::Unknown {
                                self.test_sync_connection();
                            }
                            ui.small("La cle API est stockee dans le coffre systeme (Credential Manager) et n'est pas conservee en clair dans .user-settings.json.");
                        }
                        SettingsCategory::Other => {
                            ui.label("Comportements generaux.");
                            ui.checkbox(
                                &mut self.settings.other_remember_section,
                                "Conserver la section active",
                            );
                            ui.small("Option reservee aux preferences locales utilisateur.");
                        }
                    });

                    ui.add_space(8.0);
                    if ui.button("Enregistrer les parametres").clicked() {
                        match save_user_settings(&self.settings) {
                            Ok(_) => {
                                self.status = "Parametres sauvegardes localement.".to_string();
                                if self.can_probe_sync() {
                                    self.test_sync_connection();
                                }
                            }
                            Err(e) => self.status = format!("Echec sauvegarde parametres: {}", e),
                        }
                    }
                }
            }
        });

        if self.show_delete_modal {
            egui::Window::new("Confirmer la suppression")
                .collapsible(false)
                .resizable(false)
                .anchor(egui::Align2::CENTER_CENTER, egui::vec2(0.0, 0.0))
                .show(ctx, |ui| {
                    ui.label("Supprimer definitivement l'entree selectionnee ?");
                    ui.horizontal(|ui| {
                        if ui.button("Annuler").clicked() {
                            self.show_delete_modal = false;
                        }
                        if ui.button("Supprimer").clicked() {
                            self.delete_selected();
                            self.show_delete_modal = false;
                        }
                    });
                });
        }

        if self.show_entry_modal {
            let title = if self.modal_edit_index.is_some() {
                "Modifier l'entree"
            } else {
                "Nouvelle entree"
            };
            egui::Window::new(title)
                .collapsible(false)
                .resizable(false)
                .anchor(egui::Align2::CENTER_CENTER, egui::vec2(0.0, 0.0))
                .show(ctx, |ui| {
                    ui.add(
                        egui::TextEdit::singleline(&mut self.service_input)
                            .hint_text("Service"),
                    );
                    ui.add(
                        egui::TextEdit::singleline(&mut self.identifiant_input)
                            .hint_text("Identifiant"),
                    );
                    ui.add(
                        egui::TextEdit::singleline(&mut self.password_input)
                            .hint_text("Mot de passe")
                            .password(!self.show_password),
                    );
                    ui.checkbox(&mut self.show_password, "Afficher le mot de passe");
                    ui.horizontal(|ui| {
                        if ui.button("Generer").clicked() {
                            self.password_input = generate_password(24);
                        }
                        if ui.button("Annuler").clicked() {
                            self.show_entry_modal = false;
                        }
                        if ui.button("Enregistrer").clicked() {
                            self.save_entry_modal();
                        }
                    });
                });
        }

        if self.show_purge_modal {
            egui::Window::new("Confirmer la purge")
                .collapsible(false)
                .resizable(false)
                .anchor(egui::Align2::CENTER_CENTER, egui::vec2(0.0, 0.0))
                .show(ctx, |ui| {
                    ui.label("Cette action supprime tout le coffre local. Continuer ?");
                    ui.horizontal(|ui| {
                        if ui.button("Annuler").clicked() {
                            self.show_purge_modal = false;
                        }
                        if ui.button("Purger").clicked() {
                            self.purge_vault();
                            self.show_purge_modal = false;
                        }
                    });
                });
        }
    }
}

fn run_gui() -> Result<(), eframe::Error> {
    let options = eframe::NativeOptions {
        viewport: egui::ViewportBuilder::default()
            .with_title("PassSecure")
            .with_inner_size([1024.0, 680.0])
            .with_min_inner_size([860.0, 560.0]),
        ..Default::default()
    };

    eframe::run_native(
        "PassSecure",
        options,
        Box::new(|_cc| Ok(Box::new(VaultGuiApp::default()))),
    )
}

fn main() {
    let use_cli = std::env::args().any(|arg| arg == "--cli");
    if use_cli {
        run_cli();
        return;
    }

    if let Err(err) = run_gui() {
        eprintln!("Erreur GUI: {}", err);
    }
}

fn demander_mot_de_passe(p: &str) -> Zeroizing<String> {
    print!("{}", p);
    io::stdout().flush().unwrap();
    Zeroizing::new(rpassword::read_password().unwrap())
}

fn saisir(p: &str) -> String {
    print!("{}", p);
    io::stdout().flush().unwrap();
    let mut s = String::new();
    io::stdin().read_line(&mut s).unwrap();
    s.trim().to_string()
}