use std::fs;
use openssl::x509::X509;
use base64::{engine::general_purpose::STANDARD, Engine};


pub fn add_certificate_chain(list_certificate: Vec<String>) -> String {

    let der_encoded = yasna::construct_der(|writer| {
        writer.write_set(|writer| {
    
            // Print the received strings
            for (_i, s) in list_certificate.iter().enumerate() {
                // println!("String {}: {}", i, s);
        
                // Read the certificate
                let cert_data = fs::read(s).expect("Failed to read certificate file");
                let cert = X509::from_pem(&cert_data).expect("Failed to parse certificate");
                let user_cert_der = cert.to_der().expect("Failed to convert to DER");

                writer.next().write_der(&user_cert_der);
            }
        });
    });

    STANDARD.encode(&der_encoded)

}