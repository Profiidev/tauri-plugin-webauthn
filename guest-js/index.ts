import {
  PublicKeyCredential,
  PublicKeyCredentialCreationOptions,
  PublicKeyCredentialRequestOptions,
  RegistrationResponseJSON
} from '@simplewebauthn/types';
import { invoke } from '@tauri-apps/api/core';

export * as types from '@simplewebauthn/types';

export async function register(
  origin: string,
  options: PublicKeyCredentialCreationOptions
): Promise<RegistrationResponseJSON | null> {
  return await invoke<{ value?: RegistrationResponseJSON }>(
    'plugin:webauthn|register',
    {
      origin,
      options
    }
  ).then((r) => (r.value ? r.value : null));
}

export async function authenticate(
  origin: string,
  options: PublicKeyCredentialRequestOptions
): Promise<PublicKeyCredential | null> {
  return await invoke<{ value?: PublicKeyCredential }>(
    'plugin:webauthn|authenticate',
    {
      origin,
      options
    }
  ).then((r) => (r.value ? r.value : null));
}
