use std::{
  sync::mpsc::{channel, Sender},
  thread,
};

use authenticator::{
  authenticatorservice::{AuthenticatorService, RegisterArgs, SignArgs},
  crypto::COSEAlgorithm,
  ctap2::server::{
    AuthenticationExtensionsClientInputs, AuthenticationExtensionsClientOutputs,
    CredentialProtectionPolicy, HMACGetSecretInput, PublicKeyCredentialParameters,
    PublicKeyCredentialUserEntity, RelyingParty, ResidentKeyRequirement,
    UserVerificationRequirement,
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
  AuthenticatorTransport, CollectedClientData, PublicKeyCredential,
  PublicKeyCredentialCreationOptions, PublicKeyCredentialRequestOptions,
  RegisterPublicKeyCredential, RegistrationExtensionsClientOutputs,
  RequestAuthenticationExtensions, RequestRegistrationExtensions,
};

use crate::authenticators::ctap2::event::WebauthnEvent;

use super::EVENT_NAME;

pub fn init_manager() -> crate::Result<AuthenticatorService> {
  let mut manager = AuthenticatorService::new()?;
  manager.add_u2f_usb_hid_platform_transports();
  Ok(manager)
}

pub trait AuthenticatorExt {
  fn perform_register(
    &mut self,
    status_tx: Sender<StatusUpdate>,
    url: Url,
    options: PublicKeyCredentialCreationOptions,
    timeout: u64,
  ) -> crate::Result<RegisterPublicKeyCredential>;

  fn perform_authentication(
    &mut self,
    status_tx: Sender<StatusUpdate>,
    url: Url,
    options: PublicKeyCredentialRequestOptions,
    timeout: u64,
  ) -> crate::Result<PublicKeyCredential>;
}

impl AuthenticatorExt for AuthenticatorService {
  fn perform_register(
    &mut self,
    status_tx: Sender<StatusUpdate>,
    url: Url,
    options: PublicKeyCredentialCreationOptions,
    timeout: u64,
  ) -> crate::Result<RegisterPublicKeyCredential> {
    let client_data: Vec<u8> = serde_json::to_vec(&CollectedClientData {
      type_: "webauthn.create".to_string(),
      challenge: options.challenge,
      origin: url.clone(),
      cross_origin: None,
      token_binding: None,
      unknown_keys: Default::default(),
    })?;

    let mut hasher = Sha256::new();
    hasher.update(&client_data);
    let client_data_hash = hasher.finish();

    let args = RegisterArgs {
      pin: None,
      client_data_hash,
      origin: url.to_string(),
      user_verification_req: UserVerificationRequirement::Required,
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
      exclude_list: Vec::new(),
      resident_key_req: ResidentKeyRequirement::Required,
      extensions: convert_request_registration_extensions(options.extensions),
      pub_cred_params: convert_algorithms(options.pub_key_cred_params),
    };

    let (register_tx, register_rx) = channel();
    let callback = StateCallback::new(Box::new(move |rv| register_tx.send(rv).unwrap()));

    #[cfg(feature = "log")]
    log::debug!("Registering with args: {args:?}");

    self.register(timeout, args, status_tx, callback)?;
    let result = register_rx.recv().unwrap()?;

    #[cfg(feature = "log")]
    log::debug!("Register result: {result:?}");

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
      id: String::new(),
      raw_id: Vec::new().into(),
      type_: "public-key".to_string(),
    })
  }

  fn perform_authentication(
    &mut self,
    status_tx: Sender<StatusUpdate>,
    url: Url,
    options: PublicKeyCredentialRequestOptions,
    timeout: u64,
  ) -> crate::Result<PublicKeyCredential> {
    let client_data: Vec<u8> = serde_json::to_vec(&CollectedClientData {
      type_: "webauthn.get".to_string(),
      challenge: options.challenge,
      origin: url.clone(),
      cross_origin: None,
      token_binding: None,
      unknown_keys: Default::default(),
    })?;

    let mut hasher = Sha256::new();
    hasher.update(&client_data);
    let client_data_hash = hasher.finish();

    let args = SignArgs {
      pin: None,
      relying_party_id: options.rp_id.clone(),
      client_data_hash,
      origin: url.to_string(),
      user_presence_req: true,
      user_verification_req: UserVerificationRequirement::Required,
      use_ctap1_fallback: false,
      allow_list: Vec::new(),
      extensions: convert_request_authentication_extensions(options.extensions),
    };

    let (sign_tx, sign_rx) = channel();
    let callback = StateCallback::new(Box::new(move |rv| {
      sign_tx.send(rv).unwrap();
    }));

    #[cfg(feature = "log")]
    log::debug!("Signing with args: {args:?}");

    self.sign(timeout, args, status_tx, callback)?;
    let result = sign_rx.recv().unwrap()?;

    #[cfg(feature = "log")]
    log::debug!("Sign result: {result:?}");

    let raw_id = result.assertion.credentials.unwrap().id;
    let data = serde_cbor_2::to_vec(&result.assertion.auth_data)?;

    Ok(PublicKeyCredential {
      id: BASE64_URL_SAFE_NO_PAD.encode(&raw_id),
      raw_id: raw_id.into(),
      type_: "public-key".to_string(),
      response: webauthn_rs_proto::AuthenticatorAssertionResponseRaw {
        client_data_json: Base64UrlSafeData::from(client_data),
        authenticator_data: data[2..].into(),
        signature: result.assertion.signature.into(),
        user_handle: result.assertion.user.map(|h| h.id.into()),
      },
      extensions: convert_response_authentication_extensions(result.extensions),
    })
  }
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

    let event: WebauthnEvent = status.into();
    let _ = app_handle.emit(EVENT_NAME, event);
  });
  status_tx
}

fn convert_response_authentication_extensions(
  extensions: AuthenticationExtensionsClientOutputs,
) -> webauthn_rs_proto::AuthenticationExtensionsClientOutputs {
  webauthn_rs_proto::AuthenticationExtensionsClientOutputs {
    appid: extensions.app_id,
    hmac_get_secret: extensions
      .hmac_get_secret
      .map(|h| webauthn_rs_proto::HmacGetSecretOutput {
        output1: h.output1.to_vec().into(),
        output2: h.output2.map(|s| s.to_vec().into()),
      }),
  }
}

fn convert_request_authentication_extensions(
  extensions: Option<RequestAuthenticationExtensions>,
) -> AuthenticationExtensionsClientInputs {
  extensions
    .map(|e| AuthenticationExtensionsClientInputs {
      app_id: e.appid,
      hmac_get_secret: e.hmac_get_secret.map(|h| HMACGetSecretInput {
        salt1: h.output1.to_vec().try_into().unwrap(),
        salt2: h.output2.map(|s| s.to_vec().try_into().unwrap()),
      }),
      ..Default::default()
    })
    .unwrap_or_default()
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
      .map(|c| webauthn_rs_proto::CredProps { rk: c.rk }),
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
