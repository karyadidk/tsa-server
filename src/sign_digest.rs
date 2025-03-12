
use openssl::{pkey::PKey, rsa::Rsa, sign::Signer, hash::MessageDigest};
use std::{fs::File, io::Read};
use base64::{engine::general_purpose::STANDARD, Engine};


/// Load private key from PEM file
pub fn load_private_key(path: &str) -> Result<PKey<openssl::pkey::Private>, String> {
    let mut file = File::open(path).map_err(|_| "Failed to open private key file")?;
    let mut key_data = Vec::new();
    file.read_to_end(&mut key_data).map_err(|_| "Failed to read private key file")?;
    
    let rsa = Rsa::private_key_from_pem(&key_data).map_err(|_| "Invalid private key format")?;
    let pkey = PKey::from_rsa(rsa).map_err(|_| "Failed to load private key")?;
    Ok(pkey)
}

/// Sign a digest using the private key
pub fn sign_digest(digest: &[u8], private_key: &PKey<openssl::pkey::Private>) -> Result<String, String> {
    let mut signer = Signer::new(MessageDigest::sha256(), private_key).map_err(|_| "Failed to create signer")?;
    signer.update(digest).map_err(|_| "Failed to update digest")?;
    let signature = signer.sign_to_vec().map_err(|_| "Failed to sign digest")?;
    Ok(STANDARD.encode(&signature)) // Return base64-encoded signature
}