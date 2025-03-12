use openssl::x509::X509;
use openssl::hash::{Hasher, MessageDigest};

/// Computes the SHA-256 digest of the given X.509 certificate and returns it as a Vec<u8>.
pub fn get_sha256_digest(cert: &X509) -> Vec<u8> {
    let mut hasher = Hasher::new(MessageDigest::sha256()).expect("Failed to create hasher");
    hasher.update(&cert.to_der().expect("Failed to convert cert to DER")).expect("Failed to hash data");
    hasher.finish().expect("Failed to finalize hash").to_vec()
}

/// Extracts the serial number of the given X.509 certificate as a String.
pub fn get_serial_number(cert: &X509) -> String {
    cert.serial_number().to_bn().unwrap().to_dec_str().unwrap().to_string()
}

/// Extracts the issuer details (Country Name, Organization Name, Common Name) from the X.509 certificate.
pub fn get_issuer_details(cert: &X509) -> (String, String, String) {
    let issuer = cert.issuer_name();

    let country_name = issuer.entries_by_nid(openssl::nid::Nid::COUNTRYNAME)
        .next()
        .map(|entry| entry.data().as_utf8().unwrap().to_string())
        .unwrap_or("Unknown".to_string());

    let organization_name = issuer.entries_by_nid(openssl::nid::Nid::ORGANIZATIONNAME)
        .next()
        .map(|entry| entry.data().as_utf8().unwrap().to_string())
        .unwrap_or("Unknown".to_string());

    let common_name = issuer.entries_by_nid(openssl::nid::Nid::COMMONNAME)
        .next()
        .map(|entry| entry.data().as_utf8().unwrap().to_string())
        .unwrap_or("Unknown".to_string());

    (country_name, organization_name, common_name)
}
