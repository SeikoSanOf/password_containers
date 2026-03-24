use serde::{Serialize, Deserialize};

#[derive(Serialize, Deserialize, Debug)]
pub struct Secret {
    pub service: String,
    pub identifiant: String,
    pub mot_de_passe: String,
}