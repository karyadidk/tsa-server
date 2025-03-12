use yasna::parse_der;
use base64::{engine::general_purpose::STANDARD, Engine};
use yasna::models::ObjectIdentifier;
use time::OffsetDateTime;
use yasna::models::GeneralizedTime;

pub fn process_tsq(tsq: &str) -> Vec<u8> {
    let der_data = STANDARD.decode(tsq).expect("Invalid Base64 input"); // Decode Base64 to DER

    let mut digest_algorithm = String::new();
    let mut digest_data = Vec::new();

    // Parse ASN.1 structure
    parse_der(&der_data, |reader| {
        reader.read_sequence(|reader| {
            // Read version (INTEGER)
            let _version = reader.next().read_i64().expect("Failed to read version");

            // Read MessageImprint (SEQUENCE)
            reader.next().read_sequence(|reader| {
                // Read AlgorithmIdentifier (SEQUENCE)
                reader.next().read_sequence(|reader| {
                    let oid = reader.next().read_oid().expect("Failed to read digest algorithm");
                    digest_algorithm = oid.to_string();

                    // Check if there's a NULL, handle it gracefully
                    if let Ok(_) = reader.next().read_null() {
                        // NULL field is present, safely ignored
                    }

                    Ok(())
                })?;

                // Read Digest Data (OCTET STRING)
                digest_data = reader.next().read_bytes().expect("Failed to read digest data");
                // digest_data = STANDARD.encode(&octet_string); // Convert to Base64

                Ok(())
            })?;

            // Handle optional boolean (certReq BOOLEAN TRUE)
            if let Ok(_cert_req) = reader.next().read_bool() {
                // println!("CertReq: {}", cert_req);
            }

            // Handle optional fields here (e.g., Extensions)
            while let Ok(_) = reader.next().read_der() {
                // Skipping extra fields
            }

            Ok(())
        })
    }).expect("Failed to parse DER");



    // Encode ASN.1 structure TST Info
    let der_encoded = yasna::construct_der(|writer| {
        writer.write_sequence(|writer| {
            writer.next().write_u8(1); // version
            writer.next().write_oid(&ObjectIdentifier::from_slice(&[1, 3, 6, 1, 4, 1, 22408, 1, 2, 3, 45])); // Policy
            writer.next().write_sequence(|writer| {
                writer.next().write_sequence(|writer| {
                    writer.next().write_oid(&ObjectIdentifier::from_slice(&[2, 16, 840, 1, 101, 3, 4, 2, 1])); // SHA-256 OID
                });
                writer.next().write_bytes(&digest_data);
            });

            writer.next().write_i64(OffsetDateTime::now_utc().unix_timestamp());

            let datetime = OffsetDateTime::now_utc();
            let datetime = OffsetDateTime::from_unix_timestamp(datetime.unix_timestamp()).unwrap(); // Remove nanoseconds
            let utc_time = GeneralizedTime::from_datetime(datetime);
            writer.next().write_generalized_time(&utc_time);
        
        });
    });

    der_encoded
}
