import {
  PublicKeyCredentialCreationOptionsJSON,
  PublicKeyCredentialJSON,
  PublicKeyCredentialRequestOptionsJSON,
  RegistrationResponseJSON
} from '@simplewebauthn/types';
import { invoke } from '@tauri-apps/api/core';
import { listen, UnlistenFn } from '@tauri-apps/api/event';

export * as types from '@simplewebauthn/types';

export type WebauthnEvent =
  | {
      type:
        | WebauthnEventType.Processing
        | WebauthnEventType.RequestTouch
        | WebauthnEventType.RequestPin;
    }
  | {
      type: WebauthnEventType.FingerprintEnrollmentFeedback;
      remainingSamples: number;
      feedback?: WebauthnFingerprintEnrollmentFeedback;
    };

export enum WebauthnEventType {
  Processing = 'processing',
  RequestTouch = 'requestTouch',
  RequestPin = 'requestPin',
  FingerprintEnrollmentFeedback = 'fingerprintEnrollmentFeedback'
}

export enum WebauthnFingerprintEnrollmentFeedback {
  Good = 0x00,
  TooHigh = 0x01,
  TooLow = 0x02,
  TooLeft = 0x03,
  TooRight = 0x04,
  TooFast = 0x05,
  TooSlow = 0x06,
  PoorQuality = 0x07,
  TooSkewed = 0x08,
  TooShort = 0x09,
  MergeFailure = 0x0a,
  AlreadyExists = 0x0b,
  // 0x0c unused
  NoUserActivity = 0x0d,
  NoUserPresenceTransition = 0x0e
}

export const EVENT_NAME = 'tauri-plugin-webauthn';

export async function register(
  origin: string,
  options: PublicKeyCredentialCreationOptionsJSON
): Promise<RegistrationResponseJSON> {
  return await invoke<RegistrationResponseJSON>('plugin:webauthn|register', {
    origin,
    options
  });
}

export async function authenticate(
  origin: string,
  options: PublicKeyCredentialRequestOptionsJSON
): Promise<PublicKeyCredentialJSON> {
  return await invoke<PublicKeyCredentialJSON>('plugin:webauthn|authenticate', {
    origin,
    options
  });
}

export async function sendPin(pin: string): Promise<void> {
  return await invoke('plugin:webauthn|send_pin', {
    pin
  });
}

export async function registerListener(
  listener: (event: WebauthnEvent) => void
): Promise<UnlistenFn> {
  return listen(EVENT_NAME, (event) => {
    listener(event.payload as WebauthnEvent);
  });
}
