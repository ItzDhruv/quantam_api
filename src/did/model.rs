use serde::{Serialize, Deserialize};

#[derive(Serialize, Deserialize)]
pub struct DidDocument {
    pub id: String,
    pub controller: String,
    pub verificationMethod: Vec<VerificationMethod>,
    pub keyAgreement: Vec<KeyAgreement>,
}

#[derive(Serialize, Deserialize)]
pub struct VerificationMethod {
    pub id: String,
    pub r#type: String,
    pub controller: String,
    pub publicKeyHex: String,
}

#[derive(Serialize, Deserialize)]
pub struct KeyAgreement {
    pub id: String,
    pub r#type: String,
    pub controller: String,
    pub publicKeyHex: String,
}
