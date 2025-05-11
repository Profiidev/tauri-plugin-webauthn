<script lang="ts">
  import type { PublicKeyCredentialCreationOptionsJSON } from '@simplewebauthn/types';
  import { invoke } from '@tauri-apps/api/core';
  import { onMount } from 'svelte';
  import { register, authenticate, registerListener, WebauthnEventType, sendPin } from 'tauri-plugin-webauthn-api';

  let reg_name = $state('');
  let auth_name = $state('');
  let pin = $state('');
  let status = $state('No status yet');

  const reg = async () => {
    status = 'Requesting registration information...';
    let options: PublicKeyCredentialCreationOptionsJSON = await invoke("reg_start", { name: reg_name });

    status = 'Registration options received, now calling register()...';
    let response = await register("https://webauthn.io", options);

    status = 'Registration response received, now calling verification...';
    await invoke("reg_finish", { username: reg_name, response });

    status = 'Registration successful!';
  };

  const auth = async () => {
    //let reg = await authenticate();
  };

  const pinSend = async () => {
    status = 'Sending PIN...';
    await sendPin(pin);
    status = 'PIN sent!';
  }

  onMount(() => {
    registerListener((event) => {
      switch (event.type) {
        case WebauthnEventType.Processing:
          status = 'Processing...';
          break;
        case WebauthnEventType.RequestTouch:
          status = 'Please touch the device...';
          break;
        case WebauthnEventType.RequestPin:
          status = 'Please enter the PIN...';
          break;
        case WebauthnEventType.FingerprintEnrollmentFeedback:
          status = `Fingerprint enrollment remaining: ${event.remainingSamples}, feedback: ${event.feedback}`;
          break;
      }
    })
  });
</script>

<main class="container">
  <form class="row">
    <input class="greet-input" placeholder="Enter a username..." bind:value={reg_name} />
    <button onclick={reg}>Register</button>
    <button onclick={auth}>Authenticate</button>
  </form>
  <p>Status: {status}</p>
  <form class="row">
    <input class="greet-input" placeholder="Enter a pin..." type="password" bind:value={pin} />
    <button onclick={pinSend}>Send</button>
  </form>
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
  display: flex;
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
