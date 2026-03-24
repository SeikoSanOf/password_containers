use aes_gcm::aead::{Aead, KeyInit, OsRng};
use aes_gcm::aead::rand_core::RngCore;
use aes_gcm::{Aes256Gcm, Nonce};
use base64::{engine::general_purpose, Engine as _};
use pbkdf2::pbkdf2_hmac;
use rpassword::read_password;
use serde::{Deserialize, Serialize};
use sha2::Sha256;
use std::fs;
use std::io::{self, Write};
use zeroize::Zeroize;

mod crypto_tests;

#[derive(Serialize, Deserialize, Debug)]
struct Secret {
    service: String,
    identifiant: String,
    mot_de_passe: String,
}

#[derive(Serialize, Deserialize)]
struct VaultFile {
    salt: String,
    nonce: String,
    ciphertext: String,
}

const VAULT_PATH: &str = "vault.json";
const PBKDF2_ITERS: u32 = 200_000;

fn derive_key(master_password: &str, salt: &[u8]) -> [u8; 32] {
    let mut key = [0u8; 32];
    pbkdf2_hmac::<Sha256>(master_password.as_bytes(), salt, PBKDF2_ITERS, &mut key);
    key
}

fn demander_mot_de_passe_maitre() -> String {
    loop {
        print!("Mot de passe maître : ");
        io::stdout().flush().unwrap();
        let pwd1 = read_password().expect("Erreur lecture mot de passe maître");

        if pwd1.trim().is_empty() {
            println!("Mot de passe maître ne peut pas être vide.");
            continue;
        }

        if !std::path::Path::new(VAULT_PATH).exists() {
            print!("Confirmer le mot de passe maître : ");
            io::stdout().flush().unwrap();
            let pwd2 = read_password().expect("Erreur lecture confirmation");

            if pwd1 != pwd2 {
                println!("Les mots de passe ne correspondent pas, recommencez.");
                continue;
            }
        }

        return pwd1;
    }
}

fn charger_coffre(master_password: &str) -> Vec<Secret> {
    let data = match fs::read_to_string(VAULT_PATH) {
        Ok(v) => v,
        Err(_) => return Vec::new(),
    };

    let vault: VaultFile = match serde_json::from_str(&data) {
        Ok(v) => v,
        Err(e) => {
            eprintln!("Impossible de lire le coffre : {}", e);
            return Vec::new();
        }
    };

    let salt = match general_purpose::STANDARD.decode(vault.salt) {
        Ok(s) => s,
        Err(e) => {
            eprintln!("Erreur salt : {}", e);
            return Vec::new();
        }
    };

    let nonce_bytes = match general_purpose::STANDARD.decode(vault.nonce) {
        Ok(n) => n,
        Err(e) => {
            eprintln!("Erreur nonce : {}", e);
            return Vec::new();
        }
    };

    let key = derive_key(master_password, &salt);
    let cipher = Aes256Gcm::new(&key.into());
    let nonce = Nonce::from_slice(&nonce_bytes);

    let ciphertext = match general_purpose::STANDARD.decode(vault.ciphertext) {
        Ok(c) => c,
        Err(e) => {
            eprintln!("Erreur ciphertext : {}", e);
            return Vec::new();
        }
    };

    let plaintext = match cipher.decrypt(nonce, ciphertext.as_ref()) {
        Ok(p) => p,
        Err(_) => {
            eprintln!("Échec du déchiffrement - vérifiez votre mot de passe maître.");
            std::process::exit(1);
        }
    };

    let secrets: Vec<Secret> = match serde_json::from_slice(&plaintext) {
        Ok(s) => s,
        Err(e) => {
            eprintln!("Impossible de parser le coffre décrypté : {}", e);
            Vec::new()
        }
    };

    let mut key_zero = key;
    key_zero.zeroize();

    secrets
}

fn sauvegarder_coffre(master_password: &str, coffre: &[Secret]) {
    let mut salt = [0u8; 16];
    OsRng.fill_bytes(&mut salt);

    let key = derive_key(master_password, &salt);
    let cipher = Aes256Gcm::new(&key.into());

    let mut nonce_bytes = [0u8; 12];
    OsRng.fill_bytes(&mut nonce_bytes);

    let plaintext = serde_json::to_vec(coffre).expect("Erreur sérialisation coffre");
    let ciphertext = cipher
        .encrypt(Nonce::from_slice(&nonce_bytes), plaintext.as_ref())
        .expect("Erreur chiffrement");

    let vault = VaultFile {
        salt: general_purpose::STANDARD.encode(salt),
        nonce: general_purpose::STANDARD.encode(nonce_bytes),
        ciphertext: general_purpose::STANDARD.encode(ciphertext),
    };

    let json = serde_json::to_string_pretty(&vault).expect("Erreur sérialisation vault");
    if let Err(e) = fs::write(VAULT_PATH, json) {
        eprintln!("Erreur écriture de {}: {}", VAULT_PATH, e);
    }

    let mut key_zero = key;
    key_zero.zeroize();
}

fn main() {
    println!("--- PassSecure-rs : Coffre-fort ultra-sécurisé (AES-256-GCM) ---");

    let master_password = demander_mot_de_passe_maitre();
    let mut coffre = charger_coffre(&master_password);

    if fs::metadata("secrets.json").is_ok() {
        if let Ok(plaintext) = fs::read_to_string("secrets.json") {
            if let Ok(old_data) = serde_json::from_str::<Vec<Secret>>(&plaintext) {
                if !old_data.is_empty() {
                    println!("Migration des secrets depuis secrets.json vers vault.json en cours...");
                    coffre.extend(old_data);
                    sauvegarder_coffre(&master_password, &coffre);
                }
            }
        }
        let _ = fs::remove_file("secrets.json");
    }

    loop {
        println!("\n1. Ajouter un mot de passe");
        println!("2. Afficher les secrets");
        println!("3. Quitter");
        print!("Choix : ");
        io::stdout().flush().unwrap();

        let mut choix = String::new();
        io::stdin().read_line(&mut choix).expect("Erreur de lecture");

        match choix.trim() {
            "1" => {
                let nouveau_secret = ajouter_secret();
                println!("\n[OK] Secret pour {} ajouté.", nouveau_secret.service);
                coffre.push(nouveau_secret);
                sauvegarder_coffre(&master_password, &coffre);
            }
            "2" => {
                if coffre.is_empty() {
                    println!("\nLe coffre est vide.");
                } else {
                    println!("\n--- Liste de vos secrets ---");
                    for (i, s) in coffre.iter().enumerate() {
                        println!("{}. Service: {} | Login: {}", i + 1, s.service, s.identifiant);
                    }
                    print!("Choisissez un numéro pour voir le mot de passe : ");
                    io::stdout().flush().unwrap();
                    let mut num = String::new();
                    io::stdin().read_line(&mut num).expect("Erreur de lecture");
                    if let Ok(index) = num.trim().parse::<usize>() {
                        if index > 0 && index <= coffre.len() {
                            println!("Mot de passe pour {} : {}", coffre[index - 1].service, coffre[index - 1].mot_de_passe);
                        } else {
                            println!("Numéro invalide.");
                        }
                    } else {
                        println!("Entrée invalide.");
                    }
                }
            }
            "3" => {
                println!("Fermeture sécurisée...");
                sauvegarder_coffre(&master_password, &coffre);
                break;
            }
            _ => println!("Choix invalide, réessaye."),
        }
    }
}

fn ajouter_secret() -> Secret {
    let service = saisir_donnee("Nom du service (ex: Github) : ");
    let login = saisir_donnee("Identifiant : ");

    print!("Mot de passe : ");
    io::stdout().flush().unwrap();
    let mdp = read_password().expect("Erreur de lecture du MDP");

    Secret {
        service,
        identifiant: login,
        mot_de_passe: mdp,
    }
}

fn saisir_donnee(prompt: &str) -> String {
    print!("{}", prompt);
    io::stdout().flush().unwrap();

    let mut input = String::new();
    io::stdin().read_line(&mut input).expect("Échec de la lecture");
    input.trim().to_string()
}