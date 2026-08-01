use std::{collections::HashMap, env, fmt::Debug, path::PathBuf};

use chrono::Local;
use serde::{Deserialize, Serialize};
use tauri::{async_runtime::Mutex, AppHandle, Manager, State, Url};

/// Logs an error and converts it to a String for returning to the frontend.
trait LogErr<T> {
  fn log_err(self, msg: &str) -> Result<T, String>;
}

impl<T, E: Debug> LogErr<T> for Result<T, E> {
  fn log_err(self, msg: &str) -> Result<T, String> {
    self.map_err(|e| {
      let err = format!("{msg}: {e:?}");
      log::error!("{err}");
      err
    })
  }
}

trait LogNone<T> {
  fn log_none(self, msg: &str) -> Result<T, String>;
}

impl<T> LogNone<T> for Option<T> {
  fn log_none(self, msg: &str) -> Result<T, String> {
    self.ok_or_else(|| {
      log::error!("{msg}");
      msg.to_string()
    })
  }
}

const DEFAULT_RP_ID: &str = "webauthn.dkackman.com";
const DEFAULT_RP_ORIGIN: &str = "https://webauthn.dkackman.com/";

fn rp_id() -> String {
  env::var("WEBAUTHN_RP_ID").unwrap_or_else(|_| DEFAULT_RP_ID.to_string())
}

fn rp_origin() -> String {
  env::var("WEBAUTHN_RP_ORIGIN").unwrap_or_else(|_| DEFAULT_RP_ORIGIN.to_string())
}

#[derive(Clone, Serialize, Deserialize)]
struct RpConfig {
  rp_id: String,
  rp_origin: String,
}

/// The persisted RP-side state for one RP ID: registered users and their
/// passkeys (public keys + counters only — nothing secret).
#[derive(Default, Serialize, Deserialize)]
struct RpStore {
  users: HashMap<String, Uuid>,
  passkeys: HashMap<Uuid, Vec<Passkey>>,
}

const STORE_FILE: &str = "passkey-store.json";

fn store_path(app: &AppHandle) -> Result<PathBuf, String> {
  let dir = app
    .path()
    .app_data_dir()
    .log_err("Failed to resolve app data dir")?;
  std::fs::create_dir_all(&dir).log_err("Failed to create app data dir")?;
  Ok(dir.join(STORE_FILE))
}

/// Passkeys are scoped to an RP, and the app can switch RP config at runtime,
/// so the file holds a store per RP ID.
fn read_all_stores(app: &AppHandle) -> HashMap<String, RpStore> {
  store_path(app)
    .ok()
    .and_then(|path| std::fs::read_to_string(path).ok())
    .and_then(|json| serde_json::from_str(&json).ok())
    .unwrap_or_default()
}

fn load_rp_store(app: &AppHandle, rp_id: &str) -> RpStore {
  read_all_stores(app).remove(rp_id).unwrap_or_default()
}

fn save_rp_store(
  app: &AppHandle,
  rp_id: &str,
  users: &HashMap<String, Uuid>,
  passkeys: &HashMap<Uuid, Vec<Passkey>>,
) -> Result<(), String> {
  let mut all = read_all_stores(app);
  all.insert(
    rp_id.to_string(),
    RpStore {
      users: users.clone(),
      passkeys: passkeys.clone(),
    },
  );
  let json = serde_json::to_string_pretty(&all).log_err("Failed to serialize passkey store")?;
  std::fs::write(store_path(app)?, json).log_err("Failed to write passkey store")
}

fn build_webauthn(rp_id: &str, rp_origin: &str) -> Result<Webauthn, String> {
  let url = Url::parse(rp_origin).log_err("Invalid RP origin URL")?;
  let mut builder =
    WebauthnBuilder::new(rp_id, &url).log_err("Failed to create WebauthnBuilder")?;
  let android_origin = format!("android:apk-key-hash:W8LAR3CdJ3CAVCTuv3_J5fF2iKYGYQhYfKq9ANbOzjI");
  builder = builder.append_allowed_origin(
    &Url::parse(&android_origin).log_err("Invalid Android APK key hash URL")?,
  );

  builder.build().log_err("Failed to build Webauthn")
}

use base64::{engine::general_purpose::URL_SAFE_NO_PAD, Engine};
use tauri_plugin_log::{RotationStrategy, Target, TargetKind, TimezoneStrategy};
use webauthn_rs::{
  prelude::{
    Base64UrlSafeData, DiscoverableAuthentication, Passkey, PasskeyAuthentication,
    PasskeyRegistration, Uuid,
  },
  Webauthn, WebauthnBuilder,
};
use webauthn_rs_proto::{
  PublicKeyCredential, PublicKeyCredentialCreationOptions, PublicKeyCredentialRequestOptions,
  RegisterPublicKeyCredential,
};

#[tauri::command]
async fn reg_start(
  state: State<'_, Mutex<Option<(PasskeyRegistration, Uuid)>>>,
  passkeys: State<'_, Mutex<HashMap<Uuid, Vec<Passkey>>>>,
  webauthn: State<'_, Mutex<Webauthn>>,
  users: State<'_, Mutex<HashMap<String, Uuid>>>,
  name: &str,
  enable_prf: bool,
) -> Result<PublicKeyCredentialCreationOptions, String> {
  let uuid = *users
    .lock()
    .await
    .entry(name.to_string())
    .or_insert(Uuid::new_v4());

  let existing_creds = passkeys
    .lock()
    .await
    .get(&uuid)
    .map(|p| p.iter().map(|p| p.cred_id().clone()).collect());

  let (challenge, state_val) = webauthn
    .lock()
    .await
    .start_passkey_registration(uuid, name, name, existing_creds)
    .log_err("Failed to start registration")?;

  state.lock().await.replace((state_val, uuid));

  let mut public_key = challenge.public_key;
  if enable_prf {
    public_key.extensions = Some(webauthn_rs_proto::RequestRegistrationExtensions {
      hmac_create_secret: Some(true),
      ..Default::default()
    });
  }

  Ok(public_key)
}

#[tauri::command]
async fn reg_finish(
  app: AppHandle,
  state: State<'_, Mutex<Option<(PasskeyRegistration, Uuid)>>>,
  passkeys: State<'_, Mutex<HashMap<Uuid, Vec<Passkey>>>>,
  users: State<'_, Mutex<HashMap<String, Uuid>>>,
  webauthn: State<'_, Mutex<Webauthn>>,
  config: State<'_, Mutex<RpConfig>>,
  response: RegisterPublicKeyCredential,
) -> Result<(), String> {
  let (passkey_reg, uuid) = state
    .lock()
    .await
    .take()
    .log_none("No pending registration. Did you call register first?")?;

  let passkey = webauthn
    .lock()
    .await
    .finish_passkey_registration(&response, &passkey_reg)
    .log_err("Failed to verify registration")?;

  let mut passkeys = passkeys.lock().await;
  passkeys.entry(uuid).or_default().push(passkey);

  let rp_id = config.lock().await.rp_id.clone();
  save_rp_store(&app, &rp_id, &*users.lock().await, &passkeys)?;

  Ok(())
}

#[tauri::command]
async fn auth_start(
  webauthn: State<'_, Mutex<Webauthn>>,
  state: State<'_, Mutex<Option<DiscoverableAuthentication>>>,
  salt1: Option<String>,
  salt2: Option<String>,
) -> Result<PublicKeyCredentialRequestOptions, String> {
  let (challenge, state_val) = webauthn
    .lock()
    .await
    .start_discoverable_authentication()
    .log_err("Failed to start authentication")?;

  state.lock().await.replace(state_val);

  let mut public_key = challenge.public_key;
  if let Some(s1) = salt1 {
    let salts = if let Some(s2) = salt2 {
      vec![s1, s2]
    } else {
      vec![s1]
    };
    let decode_salt = |s: &str| -> Result<Base64UrlSafeData, String> {
      let bytes = URL_SAFE_NO_PAD.decode(s).log_err("Invalid salt encoding")?;
      if bytes.len() != 32 {
        return Err(format!(
          "PRF salt must be exactly 32 bytes, got {}",
          bytes.len()
        ));
      }
      Ok(Base64UrlSafeData::from(bytes))
    };
    public_key.extensions = Some(webauthn_rs_proto::RequestAuthenticationExtensions {
      hmac_get_secret: Some(webauthn_rs_proto::HmacGetSecretInput {
        output1: decode_salt(&salts[0])?,
        output2: salts.get(1).map(|s| decode_salt(s)).transpose()?,
      }),
      appid: None,
      uvm: None,
    });
  }

  Ok(public_key)
}

#[tauri::command]
async fn auth_start_non_discoverable(
  webauthn: State<'_, Mutex<Webauthn>>,
  users: State<'_, Mutex<HashMap<String, Uuid>>>,
  state: State<'_, Mutex<Option<PasskeyAuthentication>>>,
  passkeys: State<'_, Mutex<HashMap<Uuid, Vec<Passkey>>>>,
  name: &str,
  salt1: Option<String>,
  salt2: Option<String>,
) -> Result<PublicKeyCredentialRequestOptions, String> {
  let uuid = *users
    .lock()
    .await
    .get(name)
    .log_none(&format!("User \"{name}\" not found. Register first."))?;

  let user_passkeys = passkeys
    .lock()
    .await
    .get(&uuid)
    .log_none("No passkey found for this user. Register first.")?
    .clone();

  let (challenge, state_val) = webauthn
    .lock()
    .await
    .start_passkey_authentication(&user_passkeys)
    .log_err("Failed to start authentication")?;

  state.lock().await.replace(state_val);

  let mut public_key = challenge.public_key;
  if let Some(s1) = salt1 {
    let salts = if let Some(s2) = salt2 {
      vec![s1, s2]
    } else {
      vec![s1]
    };
    let decode_salt = |s: &str| -> Result<Base64UrlSafeData, String> {
      let bytes = URL_SAFE_NO_PAD.decode(s).log_err("Invalid salt encoding")?;
      if bytes.len() != 32 {
        return Err(format!(
          "PRF salt must be exactly 32 bytes, got {}",
          bytes.len()
        ));
      }
      Ok(Base64UrlSafeData::from(bytes))
    };
    public_key.extensions = Some(webauthn_rs_proto::RequestAuthenticationExtensions {
      hmac_get_secret: Some(webauthn_rs_proto::HmacGetSecretInput {
        output1: decode_salt(&salts[0])?,
        output2: salts.get(1).map(|s| decode_salt(s)).transpose()?,
      }),
      appid: None,
      uvm: None,
    });
  }

  Ok(public_key)
}

#[derive(Serialize, Deserialize)]
struct PrfResults {
  first: String,
  second: Option<String>,
}

#[tauri::command]
async fn auth_finish(
  app: AppHandle,
  webauthn: State<'_, Mutex<Webauthn>>,
  state: State<'_, Mutex<Option<DiscoverableAuthentication>>>,
  passkeys: State<'_, Mutex<HashMap<Uuid, Vec<Passkey>>>>,
  users: State<'_, Mutex<HashMap<String, Uuid>>>,
  config: State<'_, Mutex<RpConfig>>,
  response: PublicKeyCredential,
) -> Result<Option<PrfResults>, String> {
  let (user, cred_id) = webauthn
    .lock()
    .await
    .identify_discoverable_authentication(&response)
    .log_err("Failed to identify credential")?;

  let passkey = passkeys
    .lock()
    .await
    .get(&user)
    .and_then(|p| p.iter().find(|p| p.cred_id() == cred_id))
    .log_none("Passkey not found. You may need to register again.")?
    .clone();

  let passkey_auth = state
    .lock()
    .await
    .take()
    .log_none("No pending authentication. Did you call authenticate first?")?;

  let auth_result = webauthn
    .lock()
    .await
    .finish_discoverable_authentication(&response, passkey_auth, &[(&passkey).into()])
    .log_err("Failed to verify authentication")?;

  {
    let mut passkeys = passkeys.lock().await;
    if let Some(user_passkeys) = passkeys.get_mut(&user) {
      for passkey in user_passkeys.iter_mut() {
        passkey.update_credential(&auth_result);
      }
    }
    let rp_id = config.lock().await.rp_id.clone();
    save_rp_store(&app, &rp_id, &*users.lock().await, &passkeys)?;
  }

  // Extract PRF results from clientExtensionResults. Note: this field is NOT
  // covered by the authenticator's signature per the WebAuthn spec. On macOS/iOS
  // the native bridge constructs this from the platform-verified PRF output,
  // so it is trustworthy in practice. A tampered Tauri frontend could inject
  // arbitrary values here.
  let prf_results = response
    .extensions
    .hmac_get_secret
    .as_ref()
    .map(|hmac| PrfResults {
      first: URL_SAFE_NO_PAD.encode(hmac.output1.as_ref()),
      second: hmac
        .output2
        .as_ref()
        .map(|s| URL_SAFE_NO_PAD.encode(s.as_ref())),
    });

  Ok(prf_results)
}

#[tauri::command]
async fn auth_finish_non_discoverable(
  app: AppHandle,
  webauthn: State<'_, Mutex<Webauthn>>,
  state: State<'_, Mutex<Option<PasskeyAuthentication>>>,
  passkeys: State<'_, Mutex<HashMap<Uuid, Vec<Passkey>>>>,
  users: State<'_, Mutex<HashMap<String, Uuid>>>,
  config: State<'_, Mutex<RpConfig>>,
  response: PublicKeyCredential,
) -> Result<Option<PrfResults>, String> {
  let passkey_auth = state
    .lock()
    .await
    .take()
    .log_none("No pending authentication. Did you call authenticate first?")?;
  let auth_result = webauthn
    .lock()
    .await
    .finish_passkey_authentication(&response, &passkey_auth)
    .log_err("Failed to verify authentication")?;

  {
    let mut passkeys = passkeys.lock().await;
    for user_passkeys in passkeys.values_mut() {
      for passkey in user_passkeys.iter_mut() {
        passkey.update_credential(&auth_result);
      }
    }
    let rp_id = config.lock().await.rp_id.clone();
    save_rp_store(&app, &rp_id, &*users.lock().await, &passkeys)?;
  }

  // Extract PRF results from clientExtensionResults. Note: this field is NOT
  // covered by the authenticator's signature per the WebAuthn spec. On macOS/iOS
  // the native bridge constructs this from the platform-verified PRF output,
  // so it is trustworthy in practice. A tampered Tauri frontend could inject
  // arbitrary values here.
  let prf_results = response
    .extensions
    .hmac_get_secret
    .as_ref()
    .map(|hmac| PrfResults {
      first: URL_SAFE_NO_PAD.encode(hmac.output1.as_ref()),
      second: hmac
        .output2
        .as_ref()
        .map(|s| URL_SAFE_NO_PAD.encode(s.as_ref())),
    });

  Ok(prf_results)
}

#[tauri::command]
async fn get_rp_config(config: State<'_, Mutex<RpConfig>>) -> Result<RpConfig, String> {
  Ok(config.lock().await.clone())
}

#[tauri::command]
async fn set_rp_config(
  app: AppHandle,
  webauthn: State<'_, Mutex<Webauthn>>,
  config: State<'_, Mutex<RpConfig>>,
  passkeys: State<'_, Mutex<HashMap<Uuid, Vec<Passkey>>>>,
  users: State<'_, Mutex<HashMap<String, Uuid>>>,
  rp_id: String,
  rp_origin: String,
) -> Result<(), String> {
  let new_webauthn = build_webauthn(&rp_id, &rp_origin)?;
  *webauthn.lock().await = new_webauthn;

  // The store on disk is written after every mutation, so on an RP switch we
  // only need to swap in the persisted state for the new RP ID.
  let store = load_rp_store(&app, &rp_id);
  *users.lock().await = store.users;
  *passkeys.lock().await = store.passkeys;

  *config.lock().await = RpConfig { rp_id, rp_origin };
  Ok(())
}

#[cfg_attr(mobile, tauri::mobile_entry_point)]
pub fn run() {
  // Load .env from the example root (parent of src-tauri)
  let _ = dotenvy::from_filename("../.env");
  let rp_id = rp_id();
  let rp_origin = rp_origin();
  log::info!("Using RP ID: {rp_id}, Origin: {rp_origin}");

  let webauthn = build_webauthn(&rp_id, &rp_origin).expect("Failed to build Webauthn");

  let initial_rp_id = rp_id.clone();
  tauri::Builder::default()
    .manage(Mutex::new(webauthn))
    .manage(Mutex::new(RpConfig { rp_id, rp_origin }))
    .manage(Mutex::new(Option::<DiscoverableAuthentication>::None))
    .manage(Mutex::new(Option::<PasskeyAuthentication>::None))
    .manage(Mutex::new(Option::<(PasskeyRegistration, Uuid)>::None))
    .setup(move |app| {
      let store = load_rp_store(app.handle(), &initial_rp_id);
      app.manage(Mutex::new(store.passkeys));
      app.manage(Mutex::new(store.users));
      Ok(())
    })
    .plugin(
      tauri_plugin_log::Builder::new()
        .clear_targets()
        .target(Target::new(TargetKind::Stdout))
        .target(Target::new(TargetKind::LogDir {
          file_name: Some(Local::now().to_rfc3339().replace(":", "-")),
        }))
        .rotation_strategy(RotationStrategy::KeepAll)
        .timezone_strategy(TimezoneStrategy::UseLocal)
        .build(),
    )
    .plugin(tauri_plugin_opener::init())
    .plugin(tauri_plugin_passkey::init())
    .invoke_handler(tauri::generate_handler![
      reg_start,
      reg_finish,
      auth_start,
      auth_finish,
      auth_start_non_discoverable,
      auth_finish_non_discoverable,
      get_rp_config,
      set_rp_config,
    ])
    .run(tauri::generate_context!())
    .expect("error while running tauri application");
}
