mod process_tsq;
mod get_user_cert_data;
mod prerequest;
mod create_tsa;
mod sign_digest;
mod add_certificate_chain;
use base64::{engine::general_purpose::STANDARD, Engine};
use hyper::StatusCode;
use sha2::{Sha256, Digest};



use axum::{routing::post, Router, body::{Body, to_bytes}, http::header, extract::Request, response::{IntoResponse, Response}};
use tokio::net::TcpListener;
use std::{fs, net::SocketAddr};


fn generate(tsq: &str) -> String {

    let user_cert_path = "/app/certificates/tsa_cert.pem";
    let private_key_path = "/app/key/tsa.key";

    let folder_path = "/app/certificates";
    let list_certificate: Vec<String> = fs::read_dir(folder_path)
        .expect("Failed to read directory")
        .filter_map(|entry| {
            entry.ok().and_then(|e| {
                e.path().to_str().map(|s| s.to_string())
            })
        })
        .collect();

    let der_tst = process_tsq::process_tsq(tsq);

    let mut hasher_tst = Sha256::new();
    hasher_tst.update(&der_tst);
    let result_tst = hasher_tst.finalize();
    let digest_data = STANDARD.encode(&result_tst);


    
    let der_encoded = prerequest::encode_asn1(&user_cert_path, &digest_data);
    let mut base64_encoded = STANDARD.encode(&der_encoded);


    let certificate_chain = add_certificate_chain::add_certificate_chain(list_certificate);

    // Load private key
    let private_key = match sign_digest::load_private_key(private_key_path) {
        Ok(key) => key,
        Err(err) => {
            eprintln!("Error loading private key: {}", err);
            return "".to_string();
        }
    };

    // Sign the digest
    let signature = match sign_digest::sign_digest(&der_encoded, &private_key) {
        Ok(sig) => sig,
        Err(err) => {
            eprintln!("Error signing digest: {}", err);
            return "".to_string();
        }
    };

    let cms = create_tsa::create_tsa(&mut base64_encoded, user_cert_path.to_string(), der_tst, &mut certificate_chain.clone(), signature);

    cms
}


async fn stream_handler(req: Request) -> impl IntoResponse {
    let content_type = req.headers().get(header::CONTENT_TYPE);
    if content_type != Some(&header::HeaderValue::from_static("application/timestamp-query")) {
        return Response::builder()
            .status(StatusCode::BAD_REQUEST)
            .body(Body::from("Invalid Content-Type"))
            .unwrap();
    }
    
    let body = req.into_body();

    // Convert the stream into bytes
    let bytes = to_bytes(body, 1024 * 1024).await.unwrap_or_default(); // Limit: 1MB

    // Convert bytes to Base64
    let base64_string = STANDARD.encode(&bytes);

    // Generate binary response (for example, decoding Base64 back to raw bytes)
    let binary_data_base64 = generate(&base64_string); // Replace with actual function

    // Decode Base64 back to raw bytes
    let binary_data = match STANDARD.decode(&binary_data_base64) {
        Ok(data) => data,
        Err(_) => {
            return Response::builder()
                .status(500)
                .body(Body::from("Failed to decode base64"))
                .unwrap();
        }
    };
    // Create a binary response
    Response::builder()
        .status(StatusCode::OK)
        .header(header::CONTENT_TYPE, "application/timestamp-reply")
        .body(Body::from(binary_data))
        .unwrap()

}

#[tokio::main]
async fn main() {
    let app = Router::new().route("/", post(stream_handler));

    let addr = SocketAddr::from(([0, 0, 0, 0], 2580));
    let listener = TcpListener::bind(addr).await.unwrap();

    println!("Server running on http://{}", addr);
    axum::serve(listener, app).await.unwrap();
}

// curl -H "Content-Type: application/timestamp-query" --data-binary '@request.tsq' http://127.0.0.1:2580 | base64