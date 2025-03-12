use crate::get_user_cert_data;
use yasna::{Tag, models::ObjectIdentifier};
use num_bigint::BigInt;
use std::fs;
use openssl::x509::X509;
use base64::engine::general_purpose::STANDARD;
use base64::Engine;
use yasna::models::UTCTime;
use time::OffsetDateTime;

/// OID for messageDigest: 1.2.840.113549.1.9.4
const CONTENT_TYPE_OID: &[u64] = &[1, 2, 840, 113549, 1, 9, 3];
const TST_INFO_OID: &[u64] = &[1, 2, 840, 113549, 1, 9, 16, 1, 4];
const MESSAGE_DIGEST_OID: &[u64] = &[1, 2, 840, 113549, 1, 9, 4];
const SIGNING_TIME_OID: &[u64] = &[1, 2, 840, 113549, 1, 9, 5];

const OID_ROOT: &[u64] = &[1, 2, 840, 113549, 1, 9, 16, 2, 47];
const OID_COUNTRY_NAME: &[u64] = &[2, 5, 4, 6];
const OID_ORGANIZATION_NAME: &[u64] = &[2, 5, 4, 10];
const OID_COMMON_NAME: &[u64] = &[2, 5, 4, 3];

pub fn encode_asn1(cert_path: &str, digest_base64: &str) -> Vec<u8> {
    let digest_value = STANDARD.decode(digest_base64).expect("Failed to decode Base64");
    // let ocsp_value = STANDARD.decode(ocsp_response).expect("Failed to decode Base64");
    // let crl_value = STANDARD.decode(crl_response).expect("Failed to decode Base64");

    // Read the certificate
    let cert_data = fs::read(cert_path).expect("Failed to read certificate file");
    let cert = X509::from_pem(&cert_data).expect("Failed to parse certificate");

    // Get SHA-256 Digest
    let digest_cert = get_user_cert_data::get_sha256_digest(&cert);

    // Get Serial Number
    let serial_number = get_user_cert_data::get_serial_number(&cert);

    // Get Issuer Details
    let (country_name, organization_name, common_name) = get_user_cert_data::get_issuer_details(&cert);

    // Convert OID array into ObjectIdentifier
    let content_type_oid = ObjectIdentifier::from_slice(CONTENT_TYPE_OID);
    let tst_info_oid = ObjectIdentifier::from_slice(TST_INFO_OID);
    let message_digest_oid = ObjectIdentifier::from_slice(MESSAGE_DIGEST_OID);
    let signing_time_oid = ObjectIdentifier::from_slice(SIGNING_TIME_OID);

    let oid_root = ObjectIdentifier::from_slice(OID_ROOT);
    let oid_country = ObjectIdentifier::from_slice(OID_COUNTRY_NAME);
    let oid_org = ObjectIdentifier::from_slice(OID_ORGANIZATION_NAME);
    let oid_common = ObjectIdentifier::from_slice(OID_COMMON_NAME);

    // Convert Serial Number to BigInt
    let integer_value_sn = BigInt::parse_bytes(serial_number.as_bytes(), 10).unwrap();

    // Encode ASN.1 structure wrapped in SET
    let der_encoded = yasna::construct_der(|writer| {
        writer.write_set(|writer| {
            writer.next().write_sequence(|writer| {
                writer.next().write_oid(&content_type_oid);
                writer.next().write_set(|writer| {
                    writer.next().write_oid(&tst_info_oid);
                });
            });
            writer.next().write_sequence(|writer| {
                writer.next().write_oid(&message_digest_oid);
                writer.next().write_set(|writer| {
                    writer.next().write_bytes(&digest_value);
                });
            });
            writer.next().write_sequence(|writer| {
                writer.next().write_oid(&signing_time_oid);
                writer.next().write_set(|writer| {
                    let datetime = OffsetDateTime::now_utc();
                    let datetime = OffsetDateTime::from_unix_timestamp(datetime.unix_timestamp()).unwrap(); // Remove nanoseconds
                    let utc_time = UTCTime::from_datetime(datetime);
                    writer.next().write_utctime(&utc_time);
                });
            });
            writer.next().write_sequence(|writer| {
                writer.next().write_oid(&oid_root);
                writer.next().write_set(|writer| {
                    writer.next().write_sequence(|writer| {
                        writer.next().write_sequence(|writer| {
                            writer.next().write_sequence(|writer| {
                                writer.next().write_bytes(&digest_cert);
                                writer.next().write_sequence(|writer| {
                                    writer.next().write_sequence(|writer| {
                                        writer.next().write_tagged(Tag::context(4), |writer| {
                                            writer.write_sequence(|writer| {
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
                                        });
                                    });
                                    writer.next().write_bigint_bytes(&integer_value_sn.to_signed_bytes_be(), integer_value_sn.sign() == num_bigint::Sign::Plus);
                                });
                            });
                        });
                    });
                });
            });
        });
    });

    // Convert DER to Base64 (standard base64 encoding)
    der_encoded
    // STANDARD.encode(&der_encoded)
}