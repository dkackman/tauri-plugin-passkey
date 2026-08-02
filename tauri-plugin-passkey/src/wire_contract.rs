//! Pins the JSON wire format between the webview and the Rust commands.
//! The shapes here are what guest-js/index.ts sends (standard WebAuthn JSON,
//! base64url-encoded binary fields). If a webauthn-rs-proto upgrade breaks
//! these tests, the JS<->Rust contract broke: audit before bumping.
#![cfg(test)]

use webauthn_rs_proto::{PublicKeyCredentialCreationOptions, PublicKeyCredentialRequestOptions};

#[test]
fn creation_options_deserialize_from_standard_webauthn_json() {
    let json = r#"{
        "rp": { "id": "example.com", "name": "Example" },
        "user": { "id": "dXNlci1pZA", "name": "alice", "displayName": "Alice" },
        "challenge": "Y2hhbGxlbmdlLWJ5dGVz",
        "pubKeyCredParams": [{ "type": "public-key", "alg": -7 }],
        "timeout": 60000,
        "attestation": "none"
    }"#;
    let options: PublicKeyCredentialCreationOptions =
        serde_json::from_str(json).expect("standard creation options JSON must deserialize");
    assert_eq!(options.rp.id, "example.com");
    assert_eq!(options.user.name, "alice");
    assert_eq!(options.pub_key_cred_params.len(), 1);
    assert_eq!(options.pub_key_cred_params[0].alg, -7);
}

#[test]
fn request_options_deserialize_from_standard_webauthn_json() {
    let json = r#"{
        "challenge": "Y2hhbGxlbmdlLWJ5dGVz",
        "rpId": "example.com",
        "timeout": 60000,
        "userVerification": "preferred",
        "allowCredentials": [
            { "type": "public-key", "id": "Y3JlZC1pZA" }
        ]
    }"#;
    let options: PublicKeyCredentialRequestOptions =
        serde_json::from_str(json).expect("standard request options JSON must deserialize");
    assert_eq!(options.rp_id, "example.com");
    assert_eq!(options.allow_credentials.len(), 1);
}
