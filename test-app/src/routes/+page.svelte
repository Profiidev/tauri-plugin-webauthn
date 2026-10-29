<script lang="ts">
  // PublicKeyCredentialCreationOptionsJSON / PublicKeyCredentialRequestOptionsJSON are
  // standard DOM types, globally available via the TypeScript "dom" lib — no import
  // needed. The plugin's own API surface declares them the same way.
  import { invoke } from "@tauri-apps/api/core";
  import { onMount } from "svelte";
  import {
    register,
    authenticate,
    cancel,
    isPasskeyError,
    registerListener,
    PasskeyEventType,
    sendPin,
    PinEventType,
    selectKey,
  } from "tauri-plugin-passkey-api";

  type LogEntry = {
    time: string;
    level: "info" | "error" | "action" | "success";
    message: string;
  };

  let name = $state("");
  let authName = $state("");
  let pin = $state("");
  let enablePrf = $state(false);
  let prfSalt1 = $state("");
  let prfSalt2 = $state("");
  let logs = $state<LogEntry[]>([]);
  let keys = $state<string[]>([]);
  let needsPin = $state(false);
  let busy = $state(false);
  let logEl: HTMLElement | undefined = $state();
  let rpOrigin = $state("");
  let rpId = $state("");
  let showSettings = $state(false);
  let settingsRpId = $state("");
  let settingsRpOrigin = $state("");

  function generateSalt(): string {
    const bytes = new Uint8Array(32);
    crypto.getRandomValues(bytes);
    return btoa(String.fromCharCode(...bytes))
      .replace(/\+/g, "-")
      .replace(/\//g, "_")
      .replace(/=/g, "");
  }

  function timestamp() {
    return new Date().toLocaleTimeString();
  }

  function log(level: LogEntry["level"], message: string) {
    logs.push({ time: timestamp(), level, message });
    requestAnimationFrame(() => {
      if (logEl) logEl.scrollTop = logEl.scrollHeight;
    });
  }

  async function loadConfig() {
    // Check localStorage first
    const saved = localStorage.getItem("webauthn_rp_config");
    if (saved) {
      try {
        const config = JSON.parse(saved);
        await invoke("set_rp_config", {
          rpId: config.rp_id,
          rpOrigin: config.rp_origin,
        });
        rpId = config.rp_id;
        rpOrigin = config.rp_origin;
        return;
      } catch {
        localStorage.removeItem("webauthn_rp_config");
      }
    }
    // Fall back to backend defaults (from env vars or hardcoded)
    const config: { rp_id: string; rp_origin: string } =
      await invoke("get_rp_config");
    rpId = config.rp_id;
    rpOrigin = config.rp_origin;
  }

  async function saveSettings() {
    try {
      await invoke("set_rp_config", {
        rpId: settingsRpId,
        rpOrigin: settingsRpOrigin,
      });
      rpId = settingsRpId;
      rpOrigin = settingsRpOrigin;
      localStorage.setItem(
        "webauthn_rp_config",
        JSON.stringify({ rp_id: rpId, rp_origin: rpOrigin })
      );
      showSettings = false;
      log("success", `RP config updated: ${rpId} (${rpOrigin})`);
    } catch (e: any) {
      log(
        "error",
        `Failed to update RP config: ${isPasskeyError(e) ? `${e.kind}: ${e.message}` : String(e)}`
      );
    }
  }

  function openSettings() {
    settingsRpId = rpId;
    settingsRpOrigin = rpOrigin;
    showSettings = true;
  }

  function resetSettings() {
    localStorage.removeItem("webauthn_rp_config");
    showSettings = false;
    // Reload to pick up env/default values
    window.location.reload();
  }

  const reg = async () => {
    if (!name.trim()) {
      log("error", "Please enter a username first.");
      return;
    }
    busy = true;
    needsPin = false;
    try {
      log("info", `Starting registration for "${name}"...`);
      let options: PublicKeyCredentialCreationOptionsJSON = await invoke(
        "reg_start",
        { name, enablePrf }
      );
      log("info", "Got challenge from server. Waiting for authenticator...");
      log("action", "Use Touch ID, security key, or passkey now.");

      let response = await register(rpOrigin, options);
      log("info", "Got response from authenticator. Verifying...");

      await invoke("reg_finish", { response });
      log("success", `Registration successful for "${name}"!`);
    } catch (e: any) {
      log(
        "error",
        `Registration failed: ${isPasskeyError(e) ? `${e.kind}: ${e.message}` : String(e)}`
      );
    } finally {
      busy = false;
      needsPin = false;
    }
  };

  const auth = async () => {
    busy = true;
    needsPin = false;
    try {
      log("info", "Starting discoverable authentication...");
      let options: PublicKeyCredentialRequestOptionsJSON = await invoke(
        "auth_start",
        { salt1: prfSalt1 || null, salt2: prfSalt2 || null }
      );
      log("info", "Got challenge. Waiting for authenticator...");
      log("action", "Use Touch ID, security key, or passkey now.");

      let response = await authenticate(rpOrigin, options);
      log("info", "Got response from authenticator. Verifying...");

      const result = await invoke("auth_finish", { response });
      if (result) {
        log("success", `PRF Results: ${JSON.stringify(result)}`);
      }
      log("success", "Authentication successful!");
    } catch (e: any) {
      log(
        "error",
        `Authentication failed: ${isPasskeyError(e) ? `${e.kind}: ${e.message}` : String(e)}`
      );
    } finally {
      busy = false;
      needsPin = false;
    }
  };

  const auth_non_discoverable = async () => {
    if (!authName.trim()) {
      log("error", "Please enter a username first.");
      return;
    }
    busy = true;
    needsPin = false;
    try {
      log("info", `Starting authentication for "${authName}"...`);
      let options: PublicKeyCredentialRequestOptionsJSON = await invoke(
        "auth_start_non_discoverable",
        { name: authName, salt1: prfSalt1 || null, salt2: prfSalt2 || null }
      );
      log("info", "Got challenge. Waiting for authenticator...");
      log("action", "Use Touch ID, security key, or passkey now.");

      let response = await authenticate(rpOrigin, options);
      log("info", "Got response from authenticator. Verifying...");

      const result = await invoke("auth_finish_non_discoverable", { response });
      if (result) {
        log("success", `PRF Results: ${JSON.stringify(result)}`);
      }
      log("success", "Authentication successful!");
    } catch (e: any) {
      log(
        "error",
        `Authentication failed: ${isPasskeyError(e) ? `${e.kind}: ${e.message}` : String(e)}`
      );
    } finally {
      busy = false;
      needsPin = false;
    }
  };

  const pinSend = async () => {
    if (!pin.trim()) {
      log("error", "Please enter a PIN.");
      return;
    }
    try {
      log("info", "Sending PIN...");
      await sendPin(pin);
      log("info", "PIN sent. Waiting for response...");
      pin = "";
      needsPin = false;
    } catch (e: any) {
      log(
        "error",
        `Failed to send PIN: ${isPasskeyError(e) ? `${e.kind}: ${e.message}` : String(e)}`
      );
    }
  };

  onMount(async () => {
    await loadConfig();
    log("info", `WebAuthn example ready. RP: ${rpId} (${rpOrigin})`);
    registerListener((event) => {
      switch (event.type) {
        case PasskeyEventType.SelectDevice:
          log(
            "action",
            "Multiple devices found. Touch the one you want to use."
          );
          break;
        case PasskeyEventType.PresenceRequired:
          log("action", "Touch your authenticator to confirm.");
          break;
        case PasskeyEventType.PinEvent:
          switch (event.event.type) {
            case PinEventType.PinRequired:
              needsPin = true;
              log("action", "PIN required. Enter it below.");
              break;
            case PinEventType.InvalidPin:
              needsPin = true;
              log(
                "error",
                `Invalid PIN.${event.event.attempts_remaining ? ` ${event.event.attempts_remaining} attempts remaining.` : ""}`
              );
              break;
            case PinEventType.PinAuthBlocked:
              log(
                "error",
                "PIN authentication blocked. Remove and re-insert device."
              );
              needsPin = false;
              break;
            case PinEventType.PinBlocked:
              log("error", "PIN is permanently blocked. Device must be reset.");
              needsPin = false;
              break;
            case PinEventType.InvalidUv:
              log(
                "error",
                `Invalid user verification.${event.event.attempts_remaining ? ` ${event.event.attempts_remaining} attempts remaining.` : ""}`
              );
              break;
            case PinEventType.UvBlocked:
              log("error", "User verification blocked.");
              break;
          }
          break;
        case PasskeyEventType.SelectKey:
          keys = event.keys.map((key) => key.name ?? key.displayName ?? key.id);
          log("action", `${keys.length} keys found. Select one below.`);
          break;
      }
    });
  });
</script>

<main class="container">
  <div class="header">
    <h2>WebAuthn Example</h2>
    <button class="settings-btn" onclick={() => openSettings()} title="Settings"
      ><svg
        xmlns="http://www.w3.org/2000/svg"
        width="18"
        height="18"
        viewBox="0 0 24 24"
        fill="none"
        stroke="currentColor"
        stroke-width="2"
        stroke-linecap="round"
        stroke-linejoin="round"
        ><circle cx="12" cy="12" r="3" /><path
          d="M19.4 15a1.65 1.65 0 0 0 .33 1.82l.06.06a2 2 0 0 1-2.83 2.83l-.06-.06a1.65 1.65 0 0 0-1.82-.33 1.65 1.65 0 0 0-1 1.51V21a2 2 0 0 1-4 0v-.09A1.65 1.65 0 0 0 9 19.4a1.65 1.65 0 0 0-1.82.33l-.06.06a2 2 0 0 1-2.83-2.83l.06-.06A1.65 1.65 0 0 0 4.68 15a1.65 1.65 0 0 0-1.51-1H3a2 2 0 0 1 0-4h.09A1.65 1.65 0 0 0 4.6 9a1.65 1.65 0 0 0-.33-1.82l-.06-.06a2 2 0 0 1 2.83-2.83l.06.06A1.65 1.65 0 0 0 9 4.68a1.65 1.65 0 0 0 1-1.51V3a2 2 0 0 1 4 0v.09a1.65 1.65 0 0 0 1 1.51 1.65 1.65 0 0 0 1.82-.33l.06-.06a2 2 0 0 1 2.83 2.83l-.06.06A1.65 1.65 0 0 0 19.4 9a1.65 1.65 0 0 0 1.51 1H21a2 2 0 0 1 0 4h-.09a1.65 1.65 0 0 0-1.51 1z"
        /></svg
      ></button
    >
  </div>

  {#if showSettings}
    <section class="settings-modal">
      <h3>RP Configuration</h3>
      <form
        onsubmit={(e) => {
          e.preventDefault();
          saveSettings();
        }}
      >
        <label>
          RP ID
          <input
            bind:value={settingsRpId}
            placeholder="e.g. webauthn.dkackman.com"
          />
        </label>
        <label>
          RP Origin
          <input
            bind:value={settingsRpOrigin}
            placeholder="e.g. https://webauthn.dkackman.com"
          />
        </label>
        <div class="settings-actions">
          <button type="submit">Save</button>
          <button
            type="button"
            class="secondary"
            onclick={() => (showSettings = false)}>Cancel</button
          >
          <button type="button" class="danger" onclick={resetSettings}
            >Reset to Defaults</button
          >
        </div>
      </form>
    </section>
  {/if}

  <section class="actions">
    <div class="action-group">
      <h3>Register</h3>
      <form
        class="row"
        onsubmit={(e) => {
          e.preventDefault();
          reg();
        }}
      >
        <input placeholder="Username" bind:value={name} disabled={busy} />
        <label class="checkbox-label">
          <input type="checkbox" bind:checked={enablePrf} disabled={busy} />
          Enable PRF
        </label>
        <button type="submit" disabled={busy}>Register</button>
      </form>
    </div>

    <div class="action-group">
      <h3>Authenticate (discoverable)</h3>
      <div class="row">
        <input
          placeholder="Salt 1 (32 bytes, base64url)"
          bind:value={prfSalt1}
          disabled={busy}
        />
        <button
          type="button"
          class="secondary small"
          onclick={() => (prfSalt1 = generateSalt())}
          disabled={busy}>Gen</button
        >
        <input
          placeholder="Salt 2 (32 bytes, base64url)"
          bind:value={prfSalt2}
          disabled={busy}
        />
        <button
          type="button"
          class="secondary small"
          onclick={() => (prfSalt2 = generateSalt())}
          disabled={busy}>Gen</button
        >
        <button onclick={auth} disabled={busy}>Authenticate</button>
      </div>
    </div>

    <div class="action-group">
      <h3>Authenticate (by username)</h3>
      <form
        class="row"
        onsubmit={(e) => {
          e.preventDefault();
          auth_non_discoverable();
        }}
      >
        <input placeholder="Username" bind:value={authName} disabled={busy} />
        <input
          placeholder="Salt 1 (32 bytes, base64url)"
          bind:value={prfSalt1}
          disabled={busy}
        />
        <button
          type="button"
          class="secondary small"
          onclick={() => (prfSalt1 = generateSalt())}
          disabled={busy}>Gen</button
        >
        <input
          placeholder="Salt 2 (32 bytes, base64url)"
          bind:value={prfSalt2}
          disabled={busy}
        />
        <button
          type="button"
          class="secondary small"
          onclick={() => (prfSalt2 = generateSalt())}
          disabled={busy}>Gen</button
        >
        <button type="submit" disabled={busy}>Authenticate</button>
      </form>
    </div>

    <div class="action-group">
      <h3>Cancel</h3>
      <div class="row">
        <button type="button" onclick={() => cancel()} disabled={!busy}
          >Cancel</button
        >
      </div>
    </div>
  </section>

  {#if needsPin}
    <section class="pin-prompt">
      <h3>PIN Required</h3>
      <form
        class="row"
        onsubmit={(e) => {
          e.preventDefault();
          pinSend();
        }}
      >
        <input placeholder="Enter PIN" type="password" bind:value={pin} />
        <button type="submit">Submit PIN</button>
      </form>
    </section>
  {/if}

  {#if keys.length > 0}
    <section class="key-select">
      <h3>Select a Key</h3>
      {#each keys as key, i}
        <button
          class="key-btn"
          onclick={() => {
            log("info", `Selected key: ${key}`);
            selectKey(i);
            keys = [];
          }}
        >
          {key}
        </button>
      {/each}
    </section>
  {/if}

  <section class="console" bind:this={logEl}>
    <h3>Console</h3>
    {#if logs.length === 0}
      <p class="empty">No events yet.</p>
    {/if}
    {#each logs as entry}
      <div class="log-entry {entry.level}">
        <span class="log-time">{entry.time}</span>
        <span class="log-badge"
          >{entry.level === "action"
            ? "ACTION"
            : entry.level === "success"
              ? "OK"
              : entry.level === "error"
                ? "ERROR"
                : "INFO"}</span
        >
        <span class="log-msg">{entry.message}</span>
      </div>
    {/each}
  </section>
</main>

<style>
  :root {
    font-family:
      -apple-system, BlinkMacSystemFont, "Segoe UI", Roboto, Helvetica, Arial,
      sans-serif;
    font-size: 14px;
    line-height: 1.5;
    color: #1a1a1a;
    background-color: #f5f5f7;
  }

  .container {
    max-width: 640px;
    margin: 0 auto;
    padding: 2rem 1.5rem;
  }

  .header {
    display: flex;
    justify-content: space-between;
    align-items: center;
    margin-top: 2rem;
    margin-bottom: 1.5rem;
  }

  .header h2 {
    margin: 0;
    font-size: 1.4rem;
  }

  .settings-btn {
    background: none !important;
    border: 1px solid #ddd !important;
    border-radius: 6px;
    font-size: 1.2rem;
    padding: 0.3rem 0.6rem;
    cursor: pointer;
    color: #666 !important;
  }
  .settings-btn:hover {
    background: #eee !important;
    color: #333 !important;
  }

  h3 {
    margin: 0 0 0.5rem;
    font-size: 0.85rem;
    text-transform: uppercase;
    letter-spacing: 0.05em;
    color: #666;
  }

  .settings-modal {
    background: #fff;
    border: 2px solid #396cd8;
    border-radius: 8px;
    padding: 1rem;
    margin-bottom: 1rem;
    box-shadow: 0 4px 12px rgba(0, 0, 0, 0.15);
  }
  .settings-modal label {
    display: block;
    margin-bottom: 0.75rem;
    font-size: 0.85rem;
    font-weight: 600;
    color: #555;
  }
  .settings-modal input {
    display: block;
    width: 100%;
    margin-top: 0.25rem;
    box-sizing: border-box;
  }
  .settings-actions {
    display: flex;
    gap: 0.5rem;
    margin-top: 0.75rem;
  }
  .secondary {
    background: #6c757d;
  }
  .secondary:hover:not(:disabled) {
    background: #5a6268;
  }
  .danger {
    background: #dc3545;
  }
  .danger:hover:not(:disabled) {
    background: #c82333;
  }

  .actions {
    display: flex;
    flex-direction: column;
    gap: 1rem;
  }

  .action-group {
    background: #fff;
    border-radius: 8px;
    padding: 1rem;
    box-shadow: 0 1px 3px rgba(0, 0, 0, 0.08);
  }

  .row {
    display: flex;
    gap: 0.5rem;
    align-items: center;
    flex-wrap: wrap;
  }

  .checkbox-label {
    display: flex;
    align-items: center;
    gap: 0.25rem;
    font-size: 0.85rem;
    color: #666;
    cursor: pointer;
    white-space: nowrap;
  }

  .checkbox-label input {
    flex: none;
    width: auto;
  }

  input {
    flex: 1;
    padding: 0.5rem 0.75rem;
    border: 1px solid #ddd;
    border-radius: 6px;
    font-size: 0.95rem;
    background: #fafafa;
  }
  input:focus {
    outline: none;
    border-color: #396cd8;
    background: #fff;
  }

  button {
    padding: 0.5rem 1rem;
    border: none;
    border-radius: 6px;
    font-size: 0.9rem;
    font-weight: 600;
    cursor: pointer;
    background: #396cd8;
    color: white;
    white-space: nowrap;
  }
  button:hover:not(:disabled) {
    background: #2d5abc;
  }
  button:disabled {
    opacity: 0.5;
    cursor: not-allowed;
  }

  button.small {
    padding: 0.5rem 0.6rem;
    font-size: 0.8rem;
  }

  .pin-prompt {
    margin-top: 1rem;
    background: #fff3cd;
    border: 1px solid #ffc107;
    border-radius: 8px;
    padding: 1rem;
  }
  .pin-prompt h3 {
    color: #856404;
  }

  .key-select {
    margin-top: 1rem;
    background: #d1ecf1;
    border: 1px solid #17a2b8;
    border-radius: 8px;
    padding: 1rem;
    display: flex;
    flex-direction: column;
    gap: 0.5rem;
  }
  .key-select h3 {
    color: #0c5460;
  }
  .key-btn {
    background: #17a2b8;
    text-align: left;
  }
  .key-btn:hover {
    background: #138496;
  }

  .console {
    margin-top: 1.5rem;
    background: #1e1e1e;
    border-radius: 8px;
    padding: 1rem;
    max-height: 300px;
    overflow-y: auto;
  }
  .console h3 {
    color: #888;
    margin-bottom: 0.75rem;
  }

  .empty {
    color: #666;
    font-style: italic;
    margin: 0;
  }

  .log-entry {
    display: flex;
    gap: 0.5rem;
    align-items: baseline;
    padding: 0.2rem 0;
    font-family: "SF Mono", Menlo, Consolas, monospace;
    font-size: 0.8rem;
    line-height: 1.4;
  }

  .log-time {
    color: #666;
    flex-shrink: 0;
  }

  .log-badge {
    flex-shrink: 0;
    font-size: 0.7rem;
    font-weight: 700;
    padding: 0.05rem 0.35rem;
    border-radius: 3px;
    text-transform: uppercase;
  }

  .log-msg {
    color: #ccc;
    word-break: break-word;
  }

  .info .log-badge {
    background: #2a4a7f;
    color: #8cb4ff;
  }
  .error .log-badge {
    background: #7f2a2a;
    color: #ff8c8c;
  }
  .error .log-msg {
    color: #ff8c8c;
  }
  .action .log-badge {
    background: #7f6a2a;
    color: #ffd666;
  }
  .action .log-msg {
    color: #ffd666;
  }
  .success .log-badge {
    background: #2a7f3a;
    color: #8cff8c;
  }
  .success .log-msg {
    color: #8cff8c;
  }

  @media (prefers-color-scheme: dark) {
    :root {
      color: #e0e0e0;
      background-color: #1a1a1a;
    }
    .action-group {
      background: #2a2a2a;
      box-shadow: 0 1px 3px rgba(0, 0, 0, 0.3);
    }
    input {
      background: #333;
      border-color: #444;
      color: #e0e0e0;
    }
    input:focus {
      background: #3a3a3a;
    }
    h2 {
      color: #e0e0e0;
    }
    .console {
      background: #111;
    }
    .settings-btn {
      border-color: #444;
      color: #999;
    }
    .settings-btn:hover {
      background: #333;
      color: #e0e0e0;
    }
    .settings-modal {
      background: #2a2a2a;
      border-color: #396cd8;
    }
    .settings-modal label {
      color: #aaa;
    }
  }
</style>
