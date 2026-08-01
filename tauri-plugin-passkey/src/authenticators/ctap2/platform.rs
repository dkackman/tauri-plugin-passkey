use std::{
    sync::{
        mpsc::{channel, Sender},
        Mutex,
    },
    thread,
};

use authenticator::{
    authenticatorservice::{AuthenticatorService, RegisterArgs, SignArgs},
    crypto::COSEAlgorithm,
    ctap2::server::{
        AuthenticationExtensionsClientInputs, AuthenticationExtensionsClientOutputs,
        CredentialProtectionPolicy, HMACGetSecretInput, PublicKeyCredentialDescriptor,
        PublicKeyCredentialParameters, PublicKeyCredentialUserEntity, RelyingParty,
        ResidentKeyRequirement, Transport, UserVerificationRequirement,
    },
    statecallback::StateCallback,
    Pin, StatusPinUv, StatusUpdate,
};
use base64::{prelude::BASE64_URL_SAFE_NO_PAD, Engine};
use base64urlsafedata::Base64UrlSafeData;
use openssl::sha::Sha256;
use tauri::{async_runtime::block_on, AppHandle, Emitter, Runtime, Url};
use tokio::sync::mpsc;
use webauthn_rs_proto::{
    AuthenticatorTransport, PublicKeyCredential, PublicKeyCredentialCreationOptions,
    PublicKeyCredentialRequestOptions, RegisterPublicKeyCredential,
    RegistrationExtensionsClientOutputs, RequestAuthenticationExtensions,
    RequestRegistrationExtensions,
};

use crate::authenticators::ctap2::event::WebauthnEvent;

use super::EVENT_NAME;

pub fn init_manager() -> crate::Result<AuthenticatorService> {
    let mut manager = AuthenticatorService::new()?;
    manager.add_u2f_usb_hid_platform_transports();
    Ok(manager)
}

pub fn perform_register(
    manager: &Mutex<AuthenticatorService>,
    status_tx: Sender<StatusUpdate>,
    url: Url,
    options: PublicKeyCredentialCreationOptions,
    timeout: u64,
) -> crate::Result<RegisterPublicKeyCredential> {
    let client_data =
        crate::validation::build_client_data("webauthn.create", &options.challenge, &url)?;

    let mut hasher = Sha256::new();
    hasher.update(&client_data);
    let client_data_hash = hasher.finish();

    let user_verification_req = options
        .authenticator_selection
        .as_ref()
        .map(|s| convert_user_verification(s.user_verification))
        .unwrap_or(UserVerificationRequirement::Preferred);
    let resident_key_req = convert_resident_key(options.authenticator_selection.as_ref());
    let exclude_list = convert_exclude_list(options.exclude_credentials);

    let args = RegisterArgs {
        pin: None,
        client_data_hash,
        origin: url.to_string(),
        user_verification_req,
        use_ctap1_fallback: false,
        relying_party: RelyingParty {
            id: options.rp.id,
            name: Some(options.rp.name),
        },
        user: PublicKeyCredentialUserEntity {
            id: options.user.id.to_vec(),
            name: Some(options.user.name),
            display_name: Some(options.user.display_name),
        },
        exclude_list,
        resident_key_req,
        extensions: convert_request_registration_extensions(options.extensions),
        pub_cred_params: convert_algorithms(options.pub_key_cred_params),
    };

    let (register_tx, register_rx) = channel();
    let callback = StateCallback::new(Box::new(move |rv| {
        let _ = register_tx.send(rv);
    }));

    // `args` carries the hmac-secret/PRF inputs, which are key-derivation
    // secrets — log only non-sensitive shape, never the struct itself.
    #[cfg(feature = "log")]
    log::debug!(
        "Registering with rp_id={}, {} pub_cred_params",
        args.relying_party.id,
        args.pub_cred_params.len()
    );

    // Hold the manager lock only for this dispatch: `register` hands the work
    // to transport threads and returns. The blocking wait below must run
    // WITHOUT the lock so that `cancel()` can acquire it mid-operation.
    manager
        .lock()
        .unwrap()
        .register(timeout, args, status_tx, callback)?;

    let result = register_rx.recv().map_err(|_| {
        crate::Error::Authenticator("Registration ended without a result".to_string())
    })??;

    #[cfg(feature = "log")]
    log::debug!("Register succeeded");

    let raw_id = result
        .att_obj
        .auth_data
        .credential_data
        .as_ref()
        .map(|c| c.credential_id.clone())
        .ok_or_else(|| {
            crate::Error::Authenticator("attestation object is missing credential data".to_string())
        })?;

    Ok(webauthn_rs_proto::RegisterPublicKeyCredential {
        extensions: convert_response_registration_extensions(result.extensions),
        response: webauthn_rs_proto::AuthenticatorAttestationResponseRaw {
            attestation_object: serde_cbor_2::to_vec(&result.att_obj)?.into(),
            client_data_json: Base64UrlSafeData::from(client_data),
            transports: Some(vec![
                AuthenticatorTransport::Usb,
                AuthenticatorTransport::Nfc,
                AuthenticatorTransport::Internal,
                AuthenticatorTransport::Ble,
            ]),
        },
        id: BASE64_URL_SAFE_NO_PAD.encode(&raw_id),
        raw_id: raw_id.into(),
        type_: "public-key".to_string(),
    })
}

pub fn perform_authentication(
    manager: &Mutex<AuthenticatorService>,
    status_tx: Sender<StatusUpdate>,
    url: Url,
    options: PublicKeyCredentialRequestOptions,
    timeout: u64,
) -> crate::Result<PublicKeyCredential> {
    let client_data =
        crate::validation::build_client_data("webauthn.get", &options.challenge, &url)?;

    let mut hasher = Sha256::new();
    hasher.update(&client_data);
    let client_data_hash = hasher.finish();

    // Keep the allow-list ids: CTAP2.0 authenticators may omit `credentials`
    // from the assertion, and a single-entry allow list is then the only way
    // to recover which credential signed.
    let allowed_ids: Vec<Vec<u8>> = options
        .allow_credentials
        .iter()
        .map(|c| c.id.to_vec())
        .collect();

    let args = SignArgs {
        pin: None,
        relying_party_id: options.rp_id.clone(),
        client_data_hash,
        origin: url.to_string(),
        user_presence_req: true,
        user_verification_req: convert_user_verification(options.user_verification),
        use_ctap1_fallback: false,
        allow_list: convert_allow_list(options.allow_credentials),
        extensions: convert_request_authentication_extensions(options.extensions)?,
    };

    let (sign_tx, sign_rx) = channel();
    let callback = StateCallback::new(Box::new(move |rv| {
        let _ = sign_tx.send(rv);
    }));

    // `args.extensions` carries the PRF salts — see perform_register.
    #[cfg(feature = "log")]
    log::debug!("Signing with rp_id={}", args.relying_party_id);

    // Hold the manager lock only for this dispatch: `sign` hands the work
    // to transport threads and returns. The blocking wait below must run
    // WITHOUT the lock so that `cancel()` can acquire it mid-operation.
    manager
        .lock()
        .unwrap()
        .sign(timeout, args, status_tx, callback)?;

    let result = sign_rx.recv().map_err(|_| {
        crate::Error::Authenticator("Authentication ended without a result".to_string())
    })??;

    // The sign result contains the PRF outputs — do not log it.
    #[cfg(feature = "log")]
    log::debug!("Sign succeeded");

    // `credentials` was optional in CTAP2.0: authenticators may omit it when
    // the client already knows which credential signed. A single-entry allow
    // list identifies that credential; otherwise (discoverable-credential
    // flow) there is nothing to fall back on and an empty id would only fail
    // later at the relying party, so surface a protocol error here instead.
    let raw_id = match result.assertion.credentials {
        Some(c) => c.id,
        None => match allowed_ids.as_slice() {
            [only] => only.clone(),
            _ => {
                return Err(crate::Error::Authenticator(
                    "authenticator did not return a credential id".to_string(),
                ))
            }
        },
    };
    let auth_data = result.assertion.auth_data.to_vec();

    Ok(PublicKeyCredential {
        id: BASE64_URL_SAFE_NO_PAD.encode(&raw_id),
        raw_id: raw_id.into(),
        type_: "public-key".to_string(),
        response: webauthn_rs_proto::AuthenticatorAssertionResponseRaw {
            client_data_json: Base64UrlSafeData::from(client_data),
            authenticator_data: auth_data.into(),
            signature: result.assertion.signature.into(),
            user_handle: result.assertion.user.map(|h| h.id.into()),
        },
        extensions: convert_response_authentication_extensions(result.extensions),
    })
}

pub fn status<R: Runtime>(
    app_handle: AppHandle<R>,
    pin_sender: mpsc::Sender<Sender<Pin>>,
    select_sender: mpsc::Sender<Sender<Option<usize>>>,
) -> Sender<StatusUpdate> {
    let (status_tx, status_rx) = channel::<StatusUpdate>();
    thread::spawn(move || loop {
        let Ok(status) = status_rx.recv() else {
            return;
        };

        #[cfg(feature = "log")]
        log::debug!("Status: {status:?}");

        match &status {
            StatusUpdate::PinUvError(StatusPinUv::PinRequired(sender))
            | StatusUpdate::PinUvError(StatusPinUv::InvalidPin(sender, ..)) => {
                block_on(async {
                    let _ = pin_sender.send(sender.clone()).await;
                });
            }
            StatusUpdate::SelectResultNotice(sender, ..) => {
                block_on(async {
                    let _ = select_sender.send(sender.clone()).await;
                });
            }
            _ => (),
        }

        if let Some(event) = WebauthnEvent::from_status(status) {
            let _ = app_handle.emit(EVENT_NAME, event);
        }
    });
    status_tx
}

fn convert_response_authentication_extensions(
    extensions: AuthenticationExtensionsClientOutputs,
) -> webauthn_rs_proto::AuthenticationExtensionsClientOutputs {
    webauthn_rs_proto::AuthenticationExtensionsClientOutputs {
        appid: extensions.app_id,
        hmac_get_secret: extensions.hmac_get_secret.map(|h| {
            webauthn_rs_proto::HmacGetSecretOutput {
                output1: h.output1.to_vec().into(),
                output2: h.output2.map(|s| s.to_vec().into()),
            }
        }),
    }
}

/// PRF salts are supplied by the webview and must be exactly 32 bytes;
/// anything else is a caller error rather than a reason to panic.
fn convert_salt(salt: Vec<u8>) -> crate::Result<[u8; 32]> {
    let len = salt.len();
    salt.try_into()
        .map_err(|_| crate::Error::Authenticator(format!("PRF salt must be 32 bytes, got {len}")))
}

fn convert_request_authentication_extensions(
    extensions: Option<RequestAuthenticationExtensions>,
) -> crate::Result<AuthenticationExtensionsClientInputs> {
    let Some(e) = extensions else {
        return Ok(AuthenticationExtensionsClientInputs::default());
    };

    let hmac_get_secret = match e.hmac_get_secret {
        Some(h) => Some(HMACGetSecretInput {
            salt1: convert_salt(h.output1.to_vec())?,
            salt2: h.output2.map(|s| convert_salt(s.to_vec())).transpose()?,
        }),
        None => None,
    };

    Ok(AuthenticationExtensionsClientInputs {
        app_id: e.appid,
        hmac_get_secret,
        ..Default::default()
    })
}

fn convert_request_registration_extensions(
    extensions: Option<RequestRegistrationExtensions>,
) -> AuthenticationExtensionsClientInputs {
    extensions
        .map(|e| AuthenticationExtensionsClientInputs {
            cred_props: e.cred_props,
            min_pin_length: e.min_pin_length,
            hmac_create_secret: e.hmac_create_secret,
            credential_protection_policy: e
                .cred_protect
                .clone()
                .map(|c| convert_credential_protection_policy(c.credential_protection_policy)),
            enforce_credential_protection_policy: e
                .cred_protect
                .and_then(|c| c.enforce_credential_protection_policy),
            ..Default::default()
        })
        .unwrap_or_default()
}

fn convert_response_registration_extensions(
    extensions: AuthenticationExtensionsClientOutputs,
) -> RegistrationExtensionsClientOutputs {
    RegistrationExtensionsClientOutputs {
        appid: extensions.app_id,
        hmac_secret: extensions.hmac_create_secret,
        cred_props: extensions
            .cred_props
            .map(|c| webauthn_rs_proto::CredProps { rk: Some(c.rk) }),
        ..Default::default()
    }
}

fn convert_credential_protection_policy(
    cred_protect: webauthn_rs_proto::CredentialProtectionPolicy,
) -> CredentialProtectionPolicy {
    match cred_protect {
    webauthn_rs_proto::CredentialProtectionPolicy::UserVerificationOptional => {
      CredentialProtectionPolicy::UserVerificationOptional
    }
    webauthn_rs_proto::CredentialProtectionPolicy::UserVerificationOptionalWithCredentialIDList => {
      CredentialProtectionPolicy::UserVerificationOptionalWithCredentialIDList
    }
    webauthn_rs_proto::CredentialProtectionPolicy::UserVerificationRequired => {
      CredentialProtectionPolicy::UserVerificationRequired
    }
  }
}

fn convert_algorithms(
    algorithms: Vec<webauthn_rs_proto::PubKeyCredParams>,
) -> Vec<PublicKeyCredentialParameters> {
    algorithms
        .into_iter()
        .filter_map(|a| {
            Some(PublicKeyCredentialParameters {
                alg: COSEAlgorithm::try_from(a.alg).ok()?,
            })
        })
        .collect()
}

fn convert_transports(
    transports: Vec<webauthn_rs_proto::AuthenticatorTransport>,
) -> Vec<Transport> {
    transports
        .into_iter()
        .filter_map(|t| match t {
            webauthn_rs_proto::AuthenticatorTransport::Usb => Some(Transport::USB),
            webauthn_rs_proto::AuthenticatorTransport::Nfc => Some(Transport::NFC),
            webauthn_rs_proto::AuthenticatorTransport::Ble => Some(Transport::BLE),
            webauthn_rs_proto::AuthenticatorTransport::Internal => Some(Transport::Internal),
            _ => None, // Hybrid etc. have no CTAP2-crate equivalent
        })
        .collect()
}

fn convert_exclude_list(
    list: Option<Vec<webauthn_rs_proto::PublicKeyCredentialDescriptor>>,
) -> Vec<PublicKeyCredentialDescriptor> {
    list.unwrap_or_default()
        .into_iter()
        .map(|d| PublicKeyCredentialDescriptor {
            id: d.id.into(),
            transports: d.transports.map(convert_transports).unwrap_or_default(),
        })
        .collect()
}

fn convert_allow_list(
    list: Vec<webauthn_rs_proto::AllowCredentials>,
) -> Vec<PublicKeyCredentialDescriptor> {
    list.into_iter()
        .map(|c| PublicKeyCredentialDescriptor {
            id: c.id.into(),
            transports: c.transports.map(convert_transports).unwrap_or_default(),
        })
        .collect()
}

fn convert_user_verification(
    policy: webauthn_rs_proto::UserVerificationPolicy,
) -> UserVerificationRequirement {
    match policy {
        webauthn_rs_proto::UserVerificationPolicy::Required => {
            UserVerificationRequirement::Required
        }
        webauthn_rs_proto::UserVerificationPolicy::Preferred => {
            UserVerificationRequirement::Preferred
        }
        webauthn_rs_proto::UserVerificationPolicy::Discouraged_DO_NOT_USE => {
            UserVerificationRequirement::Discouraged
        }
    }
}

fn convert_resident_key(
    selection: Option<&webauthn_rs_proto::AuthenticatorSelectionCriteria>,
) -> ResidentKeyRequirement {
    match selection.and_then(|s| s.resident_key) {
        Some(webauthn_rs_proto::ResidentKeyRequirement::Required) => {
            ResidentKeyRequirement::Required
        }
        Some(webauthn_rs_proto::ResidentKeyRequirement::Preferred) => {
            ResidentKeyRequirement::Preferred
        }
        Some(webauthn_rs_proto::ResidentKeyRequirement::Discouraged) => {
            ResidentKeyRequirement::Discouraged
        }
        // WebAuthn Level 1 compatibility: the boolean is authoritative when the
        // enum is absent.
        None if selection.map(|s| s.require_resident_key).unwrap_or(false) => {
            ResidentKeyRequirement::Required
        }
        None => ResidentKeyRequirement::Preferred,
    }
}
