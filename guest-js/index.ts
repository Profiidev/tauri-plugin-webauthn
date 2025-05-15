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
      type: WebauthnEventType.SelectDevice | WebauthnEventType.PresenceRequired;
    }
  | {
      type: WebauthnEventType.PinEvent;
      event: PinEvent;
    }
  | {
      type: WebauthnEventType.SelectKey;
      keys: AuthKey[];
    };

export enum WebauthnEventType {
  SelectDevice = 'selectDevice',
  PresenceRequired = 'presenceRequired',
  PinEvent = 'pinEvent',
  SelectKey = 'selectKey'
}

export type PinEvent =
  | {
      type:
        | PinEventType.PinRequired
        | PinEventType.PinAuthBlocked
        | PinEventType.PinBlocked
        | PinEventType.UvBlocked;
    }
  | {
      type: PinEventType.InvalidPin | PinEventType.InvalidUv;
      attempts_remaining?: number;
    };

export enum PinEventType {
  PinRequired = 'pinRequired',
  InvalidPin = 'invalidPin',
  PinAuthBlocked = 'pinAuthBlocked',
  PinBlocked = 'pinBlocked',
  InvalidUv = 'invalidUv',
  UvBlocked = 'uvBlocked'
}

export type AuthKey = {
  id: string;
  name?: string;
  displayName?: string;
};

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

export async function selectKey(index: number): Promise<void> {
  return await invoke('plugin:webauthn|select_key', {
    key: index
  });
}

export async function cancel(): Promise<void> {
  return await invoke('plugin:webauthn|cancel');
}

export async function registerListener(
  listener: (event: WebauthnEvent) => void
): Promise<UnlistenFn> {
  return listen(EVENT_NAME, (event) => {
    listener(event.payload as WebauthnEvent);
  });
}
