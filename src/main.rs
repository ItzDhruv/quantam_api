use axum::{routing::get, routing::post,  Router, Json}; 
use pqcrypto_traits::sign::SignedMessage;
mod hybrid;
// mod hybrid_wallet;
use hybrid::{HybridPublicKeyJson, SignResponse, SignRequest};
// mod hybrid_enc;
// use hybrid_enc::{HybridEncPublicKeyJson, HybridEncSecretKeyJson, HybridEncryptRequest, HybridEncryptResponse, HybridDecryptRequest, HybridDecryptResponse, hybrid_encrypt, hybrid_decrypt}; 

mod sr25519;
#[tokio::main]
async fn main() {
    println!("Server runs on  http://localhost:3000/");

    let app = Router::new()
                                        .route("/", get(|| async { "Scanbo key genration" }))
                                        .route("/hybrid_key", get(hybrid_key))
                                               .route("/sr25519", get(sr25519::generate_sr25519_wallet));
                                        // .route("/hybrid_sign", post(hybrid_sign));
    // run our app with hyper, listening globally on port 3000
    let listener = tokio::net::TcpListener::bind("0.0.0.0:3000").await.unwrap();
    axum::serve(listener, app).await.unwrap();
    
}



async fn hybrid_key() -> Json<HybridPublicKeyJson> {
    
    let (pk_json, _sk) = hybrid::get_hybrid_keypair_json();
  
    Json(pk_json)
 
}   





async fn hybrid_sign(Json(req): Json<SignRequest>) -> Json<SignResponse> {
    // Decode message (hex → bytes)
    let hex_msg = hex::encode(req.message_hex);
    println!("Message hash : {}", hex_msg);
    let msg = hex::decode(hex_msg).expect("invalid message hex");

    // Decode secret key parts
    let sk = hybrid::decode_secret_key(
        &req.secret_dilithium_hex,
        &req.secret_ed25519_hex,
    );

    // Generate signature
    let sig = hybrid::hybrid_sign(&msg, &sk);

    // Convert signature to JSON hex format
    Json(SignResponse {
        dilithium_signature: hex::encode(sig.dilithium_sm.as_bytes()),
        ed25519_signature: hex::encode(sig.ed25519_sig.to_bytes()),
    })
}







async fn hybrid_sign_handler(Json(req): Json<SignRequest>) -> Json<SignResponse> {
    // message_hex is already hex string -> decode once
    let msg = hex::decode(&req.message_hex).expect("invalid message hex");

    let sk = hybrid::decode_secret_key(
        &req.secret_dilithium_hex,
        &req.secret_ed25519_hex,
    );

    let sig = hybrid::hybrid_sign(&msg, &sk);

    Json(SignResponse {
        dilithium_signature: hex::encode(sig.dilithium_sm.as_bytes()),
        ed25519_signature: hex::encode(sig.ed25519_sig.to_bytes()),
    })
}


// async fn hybridVerify(Json(req): Json<VerifyRequest>) -> bool {
    
//     let dil_sig_bytes = hex::decode(&req.dilithium_signature).unwrap();
//     let ed_sig_bytes = hex::decode(&req.ed25519_signature).unwrap();
//     let message = hex::decode(&req.message_hex).unwrap();
//     let compressed_key_bytes = hex::decode(&req.compressed_key_hex).unwrap();
//     let dil_pk_bytes = hex::decode(&req.dilithium_pk_hex).unwrap();
//     let ed_pk_bytes = hex::decode(&req.ed25519_pk_hex).unwrap();

//     let recover = hybrid_verify(message, sig, pk);
//     recover
// }
