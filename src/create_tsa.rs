use crate::get_user_cert_data;
use std::fs;
use yasna::Tag;
use yasna::models::ObjectIdentifier;
use base64::Engine;
use base64::engine::general_purpose::STANDARD;
use openssl::x509::X509;
use num_bigint::BigInt;

/// OID for messageDigest: 1.2.840.113549.1.9.4
const DATA_OID: &[u64] = &[1, 2, 840, 113549, 1, 7, 1];
const MESSAGE_DIGEST_OID: &[u64] = &[1, 2, 840, 113549, 1, 9, 4];

const OID_COUNTRY_NAME: &[u64] = &[2, 5, 4, 6];
const OID_ORGANIZATION_NAME: &[u64] = &[2, 5, 4, 10];
const OID_COMMON_NAME: &[u64] = &[2, 5, 4, 3];

pub fn create_tsa(signed_attributes: &mut String, user_cert_path: String, der_tsa: Vec<u8>, certificate_chain: &mut String, signature: String) -> String {

    signed_attributes.replace_range(0..2, "oI");
    let signed_attributes_der_asn1 = STANDARD.decode(signed_attributes).expect("Invalid Base64 input"); // Decode Base64 to DER

    certificate_chain.replace_range(0..2, "oI");
    let certificate_chain_der_asn1 = STANDARD.decode(certificate_chain).expect("Invalid Base64 input"); // Decode Base64 to DER

    let signature_der_data = STANDARD.decode(signature).expect("Invalid Base64 input"); // Decode Base64 to DER
    

    // Read the certificate
    let cert_data = fs::read(user_cert_path).expect("Failed to read certificate file");
    let cert = X509::from_pem(&cert_data).expect("Failed to parse certificate");
    // Get Serial Number
    let serial_number = get_user_cert_data::get_serial_number(&cert);
    // Get Issuer Details
    let (country_name, organization_name, common_name) = get_user_cert_data::get_issuer_details(&cert);

    let oid_country = ObjectIdentifier::from_slice(OID_COUNTRY_NAME);
    let oid_org = ObjectIdentifier::from_slice(OID_ORGANIZATION_NAME);
    let oid_common = ObjectIdentifier::from_slice(OID_COMMON_NAME);

    // Convert OID array into ObjectIdentifier
    let _data_oid = ObjectIdentifier::from_slice(DATA_OID);
    let _message_digest_oid = ObjectIdentifier::from_slice(MESSAGE_DIGEST_OID);

    // Convert Serial Number to BigInt
    let integer_value_sn = BigInt::parse_bytes(serial_number.as_bytes(), 10).unwrap();

    let der_encoded = yasna::construct_der(|writer| {
        writer.write_sequence(|writer| {
            // Begining
            writer.next().write_sequence(|writer| {
                writer.next().write_i8(0);
                writer.next().write_sequence(|writer| {
                    writer.next().write_utf8string("TimeStamp by DKPKI");
                });
            });

            // TimeStamp
            writer.next().write_sequence(|writer| {

                writer.next().write_oid(&ObjectIdentifier::from_slice(&[1, 2, 840, 113549, 1, 7, 2])); // PKCS#7 SignedData OID
                
                writer.next().write_tagged(Tag::context(0), |writer| {
                    writer.write_sequence(|writer| {
                        writer.next().write_i8(3); // version

                        // DigestAlgorithms ::= SET OF AlgorithmIdentifier
                        writer.next().write_set(|writer| {
                            writer.next().write_sequence(|writer| {
                                writer.next().write_oid(&ObjectIdentifier::from_slice(&[2, 16, 840, 1, 101, 3, 4, 2, 1])); // SHA-256 OID
                                // writer.next().write_null();
                            });
                        });

                        // EncapsulatedContentInfo ::= SEQUENCE
                        writer.next().write_sequence(|writer| {
                            writer.next().write_oid(&ObjectIdentifier::from_slice(&[1, 2, 840, 113549, 1, 9, 16, 1, 4])); // PKCS#7 TST_INFO OID
                            writer.next().write_tagged(Tag::context(0), |writer| {
                                writer.write_bytes(&der_tsa); // TST Request Der
                            });
                        });

                        // Certificates (OPTIONAL)
                        writer.next().write_der(&certificate_chain_der_asn1);

                        // SignerInfos ::= SET OF SignerInfo
                        writer.next().write_set(|writer| {
                            writer.next().write_sequence(|writer| {
                                writer.next().write_i8(1); // version
                                writer.next().write_sequence(|writer| {
                                    writer.next().write_sequence(|writer| {
                                        writer.next().write_set(|writer| {
                                            writer.next().write_sequence(|writer| {
                                                writer.next().write_oid(&oid_country);
                                                writer.next().write_printable_string(&country_name);
                                            });
                                        });
                                        writer.next().write_set(|writer| {
                                            writer.next().write_sequence(|writer| {
                                                writer.next().write_oid(&oid_org);
                                                writer.next().write_utf8_string(&organization_name);
                                            });
                                        });
                                        writer.next().write_set(|writer| {
                                            writer.next().write_sequence(|writer| {
                                                writer.next().write_oid(&oid_common);
                                                writer.next().write_utf8_string(&common_name);
                                            });
                                        });
                                    });
                                    writer.next().write_bigint_bytes(&integer_value_sn.to_signed_bytes_be(), integer_value_sn.sign() == num_bigint::Sign::Plus);
                                });
                                
                                // DigestAlgorithm Identifier
                                writer.next().write_sequence(|writer| {
                                    writer.next().write_oid(&ObjectIdentifier::from_slice(&[2, 16, 840, 1, 101, 3, 4, 2, 1])); // SHA-256 OID
                                    writer.next().write_null();
                                });

                                // SignedAttributes
                                writer.next().write_der(&signed_attributes_der_asn1);

                                // Signature Algorithm
                                writer.next().write_sequence(|writer| {
                                    writer.next().write_oid(&ObjectIdentifier::from_slice(&[1, 2, 840, 113549, 1, 1, 11])); // sha1WithRSAEncryption
                                    writer.next().write_null();
                                });

                                // Signature
                                writer.next().write_bytes(&signature_der_data); // Fake signature

                            });
                        });
                    });
                });
            });
        });
    });

    STANDARD.encode(&der_encoded)
}
