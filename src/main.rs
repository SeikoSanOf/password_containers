use std::fs;
use std::io::{self, Write};
use rpassword::read_password;
use serde::{Deserialize, Serialize};

// On définit la structure pour stocker un secret
#[derive(Serialize, Deserialize, Debug)]
struct Secret {
    service: String,
    identifiant: String,
    mot_de_passe: String,
}

fn main() {
    let path = "secrets.json";
    let mut coffre = charger_coffre(path);

    println!("--- PassSecure-rs : Coffre-fort ultra-sécurisé ---");

    loop {
        println!("\n1. Ajouter un mot de passe");
        println!("2. Afficher les secrets");
        println!("3. Quitter");
        print!("Choix : ");
        
        io::stdout().flush().unwrap();

        let mut choix = String::new();
        io::stdin()
            .read_line(&mut choix)
            .expect("Erreur de lecture");

        match choix.trim() {
            "1" => {
                let nouveau_secret = ajouter_secret();
                println!("\n[OK] Secret pour {} ajouté.", nouveau_secret.service);
                coffre.push(nouveau_secret);
                sauvegarder_coffre(path, &coffre);
            }
            "2" => {
                if coffre.is_empty() {
                    println!("\nLe coffre est vide.");
                } else {
                    println!("\n--- Liste de vos secrets ---");
                    for (i, s) in coffre.iter().enumerate() {
                        println!("{}. Service: {} | Login: {}", i+1, s.service, s.identifiant);
                    }
                    print!("Choisissez un numéro pour voir le mot de passe : ");
                    io::stdout().flush().unwrap();
                    let mut num = String::new();
                    io::stdin().read_line(&mut num).expect("Erreur de lecture");
                    if let Ok(index) = num.trim().parse::<usize>() {
                        if index > 0 && index <= coffre.len() {
                            println!("Mot de passe pour {} : {}", coffre[index-1].service, coffre[index-1].mot_de_passe);
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
                sauvegarder_coffre(path, &coffre);
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
    // read_password() masque la saisie dans le terminal
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
    io::stdin()
        .read_line(&mut input)
        .expect("Échec de la lecture");
    
    input.trim().to_string()
}

fn charger_coffre(path: &str) -> Vec<Secret> {
    match fs::read_to_string(path) {
        Ok(data) => serde_json::from_str(&data).unwrap_or_else(|e| {
            eprintln!("Impossible de parser {} : {}. Coffre vide.", path, e);
            Vec::new()
        }),
        Err(_) => Vec::new(),
    }
}

fn sauvegarder_coffre(path: &str, coffre: &[Secret]) {
    match serde_json::to_string_pretty(coffre) {
        Ok(json) => {
            if let Err(e) = fs::write(path, json) {
                eprintln!("Erreur d'écriture du fichier {}: {}", path, e);
            }
        }
        Err(e) => eprintln!("Erreur de sérialisation : {}", e),
    }
}