<script lang="ts">
  import type {
    PublicKeyCredentialCreationOptionsJSON,
    PublicKeyCredentialRequestOptionsJSON
  } from '@simplewebauthn/types';
  import { invoke } from '@tauri-apps/api/core';
  import { onMount } from 'svelte';
  import {
    register,
    authenticate,
    registerListener,
    WebauthnEventType,
    sendPin,
    PinEventType,
    selectKey
  } from 'tauri-plugin-webauthn-api';

  let name = $state('');
  let authName = $state('');
  let pin = $state('');
  let status = $state('No status yet');
  let keys = $state<string[]>([]);

  const reg = async () => {
    status = 'Requesting registration information...';
    let options: PublicKeyCredentialCreationOptionsJSON = await invoke(
      'reg_start',
      { name }
    );

    status = 'Registration options received, now calling register()...';
    let response = await register(
      'https://tauri-plugin-webauthn-example.glitch.me/',
      options
    );

    status = 'Registration response received, now calling verification...';
    await invoke('reg_finish', { response });

    status = 'Registration successful!';
  };

  const auth = async () => {
    status = 'Requesting authentication information...';
    let options: PublicKeyCredentialRequestOptionsJSON =
      await invoke('auth_start');

    status = 'Authentication options received, now calling authenticate()...';
    let response = await authenticate(
      'https://tauri-plugin-webauthn-example.glitch.me/',
      options
    );

    status = 'Authentication response received, now calling verification...';
    await invoke('auth_finish', { response });

    status = 'Authentication successful!';
  };

  const auth_non_discoverable = async () => {
    status = 'Requesting authentication information...';
    let options: PublicKeyCredentialRequestOptionsJSON = await invoke(
      'auth_start_non_discoverable',
      { name: authName }
    );

    status = 'Authentication options received, now calling authenticate()...';
    let response = await authenticate(
      'https://tauri-plugin-webauthn-example.glitch.me/',
      options
    );

    status = 'Authentication response received, now calling verification...';
    await invoke('auth_finish_non_discoverable', { response });

    status = 'Authentication successful!';
  };

  const pinSend = async () => {
    status = 'Sending PIN...';
    await sendPin(pin);
    status = 'PIN sent!';
  };

  onMount(() => {
    registerListener((event) => {
      switch (event.type) {
        case WebauthnEventType.SelectDevice:
          status = 'Select device by touching it';
          break;
        case WebauthnEventType.PresenceRequired:
          status = 'Touch the device to confirm presence';
          break;
        case WebauthnEventType.PinEvent:
          switch (event.event.type) {
            case PinEventType.PinRequired:
              status = 'Enter the PIN';
              break;
            case PinEventType.InvalidPin:
              status =
                'Invalid PIN, try again' + event.event.attempts_remaining
                  ? ` (${event.event.attempts_remaining} attempts remaining)`
                  : '';
              break;
            case PinEventType.PinAuthBlocked:
              status = 'PIN authentication blocked';
              break;
            case PinEventType.PinBlocked:
              status = 'PIN blocked';
              break;
            case PinEventType.InvalidUv:
              status =
                'Invalid UV' + event.event.attempts_remaining
                  ? ` (${event.event.attempts_remaining} attempts remaining)`
                  : '';
              break;
            case PinEventType.UvBlocked:
              status = 'UV blocked';
              break;
          }
          break;
        case WebauthnEventType.SelectKey:
          keys = event.keys.map((key) => key.name ?? key.displayName ?? key.id);
          status = 'Select a key to authenticate';
          break;
      }
    });
  });
</script>

<main class="container">
  <form class="row">
    <input
      class="greet-input"
      placeholder="Enter a username..."
      bind:value={name}
    />
    <button onclick={reg}>Register</button>
  </form>
  <div class="row" style="margin-top: 1rem;">
    <button onclick={auth}>Authenticate</button>
  </div>
  <form class="row" style="margin-top: 1rem;">
    <input
      class="greet-input"
      placeholder="Enter a username..."
      bind:value={authName}
    />
    <button onclick={auth_non_discoverable}
      >Authenticate (no discovery)</button
    >
  </form>
  <p>Status: {status}</p>
  <form class="row">
    <input
      class="greet-input"
      placeholder="Enter a pin..."
      type="password"
      bind:value={pin}
    />
    <button onclick={pinSend}>Send</button>
  </form>
  {#if keys.length > 0}
    <p>Click a key to select</p>
  {/if}
  {#each keys as key, i}
    <div class="row">
      <button
        onclick={() => {
          selectKey(i);
          keys = [];
        }}
      >
        {key}
      </button>
    </div>
  {/each}
</main>

<style>
  :root {
    font-family: Inter, Avenir, Helvetica, Arial, sans-serif;
    font-size: 16px;
    line-height: 24px;
    font-weight: 400;

    color: #0f0f0f;
    background-color: #f6f6f6;

    font-synthesis: none;
    text-rendering: optimizeLegibility;
    -webkit-font-smoothing: antialiased;
    -moz-osx-font-smoothing: grayscale;
    -webkit-text-size-adjust: 100%;
  }

  .container {
    margin: 0;
    padding-top: 10vh;
    display: flex;
    flex-direction: column;
    justify-content: center;
    text-align: center;
  }

  .row {
    justify-content: center;
  }

  input,
  button {
    border-radius: 8px;
    border: 1px solid transparent;
    padding: 0.6em 1.2em;
    font-size: 1em;
    font-weight: 500;
    font-family: inherit;
    color: #0f0f0f;
    background-color: #ffffff;
    transition: border-color 0.25s;
    box-shadow: 0 2px 2px rgba(0, 0, 0, 0.2);
  }

  button {
    cursor: pointer;
  }

  button:hover {
    border-color: #396cd8;
  }
  button:active {
    border-color: #396cd8;
    background-color: #e8e8e8;
  }

  input,
  button {
    outline: none;
  }

  .greet-input {
    margin-right: 5px;
  }

  @media (prefers-color-scheme: dark) {
    :root {
      color: #f6f6f6;
      background-color: #2f2f2f;
    }

    input,
    button {
      color: #ffffff;
      background-color: #0f0f0f98;
    }
    button:active {
      background-color: #0f0f0f69;
    }
  }
</style>
