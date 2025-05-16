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

/**
 * Tries to register using the native WebAuthn API.
 *
 * @param origin The origin of the request. This is used to verify the request.
 * @param options The webauthn options. This is used to create the request.
 * @returns A promise that resolves to the registration response.
 */
export async function register(
  origin: string,
  options: PublicKeyCredentialCreationOptionsJSON
): Promise<RegistrationResponseJSON> {
  return await invoke<RegistrationResponseJSON>('plugin:webauthn|register', {
    origin,
    options
  });
}

/**
 * Tries to authenticate using the native WebAuthn API.
 *
 * @param origin The origin of the request. This is used to verify the request.
 * @param options The webauthn options. This is used to create the request.
 * @returns A promise that resolves to the authentication response.
 */
export async function authenticate(
  origin: string,
  options: PublicKeyCredentialRequestOptionsJSON
): Promise<PublicKeyCredentialJSON> {
  return await invoke<PublicKeyCredentialJSON>('plugin:webauthn|authenticate', {
    origin,
    options
  });
}

/**
 * Sends a pin to the authenticator.
 * Does nothing on windows and mobile.
 *
 * @param pin The pin to send to the authenticator.
 * @returns A promise that resolves when the pin has been sent.
 */
export async function sendPin(pin: string): Promise<void> {
  return await invoke('plugin:webauthn|send_pin', {
    pin
  });
}

/**
 * Select a key from the list of keys received by the `selectKey` event.
 * Does nothing on windows and mobile.
 *
 * @param uv The uv to send to the authenticator.
 * @returns A promise that resolves when the uv has been sent.
 */
export async function selectKey(index: number): Promise<void> {
  return await invoke('plugin:webauthn|select_key', {
    key: index
  });
}

/**
 * Cancels the current operation.
 * Does nothing on windows and mobile.
 *
 * @returns A promise that resolves when the operation has been cancelled.
 */
export async function cancel(): Promise<void> {
  return await invoke('plugin:webauthn|cancel');
}

/**
 * Creates a listener for the webauthn events.
 * No events are triggered on windows and mobile.
 *
 * @param listener The listener to call when the event is triggered.
 * @returns A promise that resolves to a function that can be used to unregister the listener.
 */
export async function registerListener(
  listener: (event: WebauthnEvent) => void
): Promise<UnlistenFn> {
  return listen(EVENT_NAME, (event) => {
    listener(event.payload as WebauthnEvent);
  });
}
