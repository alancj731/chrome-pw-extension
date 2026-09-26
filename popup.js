import {
  KDF_ITERATIONS,
  MIN_SECRET_LENGTH,
  VaultError,
  createVaultConfig,
  decryptPassword,
  encryptPassword,
  rotateVaultSecret,
  unlockVault,
  validateLabel
} from "./vault.js";

const STORAGE_KEYS = {
  config: "vaultConfig",
  legacyEntries: "credentials",
  credentialPrefix: "credential:"
};

const elements = Object.fromEntries(
  [
    "message",
    "setup-view",
    "setup-form",
    "setup-secret",
    "setup-confirm",
    "vault-view",
    "credential-count",
    "empty-state",
    "reveal-form",
    "credential-select",
    "reveal-secret",
    "revealed-password",
    "password-output",
    "toggle-password",
    "copy-password",
    "hide-password",
    "credential-actions",
    "edit-credential",
    "delete-credential",
    "credential-editor",
    "editor-summary",
    "credential-form",
    "credential-id",
    "website",
    "username",
    "entry-password",
    "password-help",
    "save-secret",
    "save-credential",
    "cancel-edit",
    "change-secret-form",
    "current-secret",
    "new-secret",
    "new-secret-confirm",
    "reset-vault"
  ].map((id) => [id, document.getElementById(id)])
);

let vaultConfig = null;
let credentials = [];
let messageTimer = null;
let syncReloadTimer = null;

function setBusy(form, busy) {
  for (const control of form.elements) {
    control.disabled = busy;
  }
}

function showMessage(text, type = "success", sticky = false) {
  clearTimeout(messageTimer);
  elements.message.textContent = text;
  elements.message.classList.toggle("error", type === "error");
  elements.message.hidden = false;
  if (!sticky) {
    messageTimer = setTimeout(() => {
      elements.message.hidden = true;
    }, 4200);
  }
}

function reportError(error) {
  let message =
    error instanceof VaultError || error instanceof Error
      ? error.message
      : "Something went wrong. Please try again.";
  if (/quota|max_write_operations/i.test(message)) {
    message = "Chrome Sync storage is full or temporarily rate-limited. Please try again later.";
  }
  showMessage(message, "error", true);
}

function credentialStorageKey(id) {
  return `${STORAGE_KEYS.credentialPrefix}${id}`;
}

function isCredentialRecord(value) {
  return (
    value &&
    typeof value.id === "string" &&
    typeof value.website === "string" &&
    typeof value.username === "string" &&
    value.password &&
    typeof value.password.iv === "string" &&
    typeof value.password.ciphertext === "string"
  );
}

function assertSyncItemFits(key, value) {
  const quota = chrome.storage.sync.QUOTA_BYTES_PER_ITEM ?? 8_192;
  const bytes = new TextEncoder().encode(key + JSON.stringify(value)).byteLength;
  if (bytes > quota) {
    throw new VaultError(
      "SYNC_ITEM_TOO_LARGE",
      "This credential is too large for Chrome Sync. Use a shorter website name, username, or password."
    );
  }
}

function syncPayload(config, entries) {
  const payload = { [STORAGE_KEYS.config]: config };
  assertSyncItemFits(STORAGE_KEYS.config, config);
  for (const credential of entries) {
    const key = credentialStorageKey(credential.id);
    assertSyncItemFits(key, credential);
    payload[key] = credential;
  }
  return payload;
}

async function readSyncedVault() {
  const stored = await chrome.storage.sync.get(null);
  return {
    config: stored[STORAGE_KEYS.config] ?? null,
    entries: Object.entries(stored)
      .filter(([key, value]) =>
        key.startsWith(STORAGE_KEYS.credentialPrefix) && isCredentialRecord(value)
      )
      .map(([, value]) => value)
  };
}

async function replaceSyncedVault(config, entries) {
  const payload = syncPayload(config, entries);
  const existing = await chrome.storage.sync.get(null);
  const nextCredentialKeys = new Set(entries.map((entry) => credentialStorageKey(entry.id)));
  const staleKeys = Object.keys(existing).filter(
    (key) =>
      key.startsWith(STORAGE_KEYS.credentialPrefix) && !nextCredentialKeys.has(key)
  );

  await chrome.storage.sync.set(payload);
  if (staleKeys.length > 0) {
    await chrome.storage.sync.remove(staleKeys);
  }
}

async function migrateLegacyLocalVault() {
  const legacy = await chrome.storage.local.get([
    STORAGE_KEYS.config,
    STORAGE_KEYS.legacyEntries
  ]);
  if (!legacy[STORAGE_KEYS.config]) return false;

  const legacyEntries = Array.isArray(legacy[STORAGE_KEYS.legacyEntries])
    ? legacy[STORAGE_KEYS.legacyEntries].filter(isCredentialRecord)
    : [];
  await replaceSyncedVault(legacy[STORAGE_KEYS.config], legacyEntries);
  await chrome.storage.local.remove([STORAGE_KEYS.config, STORAGE_KEYS.legacyEntries]);
  return true;
}

async function loadState({ allowMigration = true } = {}) {
  let synced = await readSyncedVault();
  if (!synced.config && allowMigration && (await migrateLegacyLocalVault())) {
    synced = await readSyncedVault();
    showMessage("Your existing local vault was moved to Chrome Sync.");
  }

  vaultConfig = synced.config;
  credentials = synced.entries;
  credentials.sort((left, right) =>
    `${left.website}\u0000${left.username}`.localeCompare(`${right.website}\u0000${right.username}`)
  );
  render();
}

function render() {
  const configured = Boolean(vaultConfig);
  elements["setup-view"].hidden = configured;
  elements["vault-view"].hidden = !configured;
  if (!configured) return;

  const selectedId = elements["credential-select"].value;
  elements["credential-select"].replaceChildren();
  for (const credential of credentials) {
    const option = document.createElement("option");
    option.value = credential.id;
    option.textContent = `${credential.website} — ${credential.username}`;
    elements["credential-select"].append(option);
  }
  if (credentials.some((credential) => credential.id === selectedId)) {
    elements["credential-select"].value = selectedId;
  }

  const count = credentials.length;
  elements["credential-count"].textContent =
    count === 1 ? "1 saved credential" : `${count} saved credentials`;
  elements["empty-state"].hidden = count !== 0;
  elements["reveal-form"].hidden = count === 0;
  elements["credential-actions"].hidden = count === 0;
  if (count === 0) hideRevealedPassword();
}

function selectedCredential() {
  return credentials.find(
    (credential) => credential.id === elements["credential-select"].value
  );
}

function hideRevealedPassword() {
  elements["password-output"].value = "";
  elements["password-output"].type = "password";
  elements["toggle-password"].textContent = "Show";
  elements["revealed-password"].hidden = true;
}

function resetEditor() {
  elements["credential-form"].reset();
  elements["credential-id"].value = "";
  elements["editor-summary"].textContent = "Add a credential";
  elements["password-help"].textContent = "Required for a new credential.";
  elements["cancel-edit"].hidden = true;
  elements["save-credential"].textContent = "Save credential";
}

elements["setup-form"].addEventListener("submit", async (event) => {
  event.preventDefault();
  const secret = elements["setup-secret"].value;
  if (secret !== elements["setup-confirm"].value) {
    reportError(new Error("The master secrets do not match."));
    return;
  }

  setBusy(elements["setup-form"], true);
  try {
    const nextConfig = await createVaultConfig(secret, KDF_ITERATIONS);
    await replaceSyncedVault(nextConfig, []);
    vaultConfig = nextConfig;
    credentials = [];
    elements["setup-form"].reset();
    render();
    showMessage("Your encrypted vault is ready.");
  } catch (error) {
    reportError(error);
  } finally {
    setBusy(elements["setup-form"], false);
  }
});

elements["reveal-form"].addEventListener("submit", async (event) => {
  event.preventDefault();
  const credential = selectedCredential();
  if (!credential) return;

  setBusy(elements["reveal-form"], true);
  hideRevealedPassword();
  try {
    const key = await unlockVault(elements["reveal-secret"].value, vaultConfig);
    elements["password-output"].value = await decryptPassword(
      credential.password,
      key,
      credential.id
    );
    elements["revealed-password"].hidden = false;
    elements["reveal-secret"].value = "";
  } catch (error) {
    reportError(error);
  } finally {
    setBusy(elements["reveal-form"], false);
  }
});

elements["credential-select"].addEventListener("change", () => {
  hideRevealedPassword();
  elements["reveal-secret"].value = "";
});

elements["toggle-password"].addEventListener("click", () => {
  const showing = elements["password-output"].type === "text";
  elements["password-output"].type = showing ? "password" : "text";
  elements["toggle-password"].textContent = showing ? "Show" : "Hide";
});

elements["hide-password"].addEventListener("click", hideRevealedPassword);

elements["copy-password"].addEventListener("click", async () => {
  try {
    await navigator.clipboard.writeText(elements["password-output"].value);
    showMessage("Password copied to the clipboard.");
  } catch {
    elements["password-output"].select();
    showMessage("Copy was blocked. The password has been selected instead.", "error", true);
  }
});

elements["credential-form"].addEventListener("submit", async (event) => {
  event.preventDefault();
  setBusy(elements["credential-form"], true);
  try {
    const website = validateLabel(elements.website.value, "Website name");
    const username = validateLabel(elements.username.value, "Username", 320);
    const editingId = elements["credential-id"].value;
    const existing = credentials.find((credential) => credential.id === editingId);
    const duplicate = credentials.some(
      (credential) =>
        credential.id !== editingId &&
        credential.website.toLocaleLowerCase() === website.toLocaleLowerCase() &&
        credential.username === username
    );
    if (duplicate) {
      throw new VaultError("DUPLICATE_ENTRY", "That website and username are already saved.");
    }

    const key = await unlockVault(elements["save-secret"].value, vaultConfig);
    const passwordValue = elements["entry-password"].value;
    if (!existing && !passwordValue) {
      throw new VaultError("INVALID_ENTRY", "Password is required.");
    }

    const id = existing?.id ?? crypto.randomUUID();
    const now = new Date().toISOString();
    const credential = {
      id,
      website,
      username,
      password: passwordValue
        ? await encryptPassword(passwordValue, key, id)
        : existing.password,
      createdAt: existing?.createdAt ?? now,
      updatedAt: now
    };

    const nextCredentials = existing
      ? credentials.map((item) => (item.id === id ? credential : item))
      : [...credentials, credential];
    const storageKey = credentialStorageKey(id);
    assertSyncItemFits(storageKey, credential);
    await chrome.storage.sync.set({ [storageKey]: credential });
    credentials = nextCredentials;
    resetEditor();
    elements["credential-editor"].open = false;
    render();
    elements["credential-select"].value = id;
    showMessage(existing ? "Credential updated." : "Credential saved securely.");
  } catch (error) {
    reportError(error);
  } finally {
    setBusy(elements["credential-form"], false);
  }
});

elements["edit-credential"].addEventListener("click", () => {
  const credential = selectedCredential();
  if (!credential) return;
  elements["credential-id"].value = credential.id;
  elements.website.value = credential.website;
  elements.username.value = credential.username;
  elements["entry-password"].value = "";
  elements["save-secret"].value = "";
  elements["editor-summary"].textContent = "Edit credential";
  elements["password-help"].textContent = "Leave blank to keep the current password.";
  elements["cancel-edit"].hidden = false;
  elements["save-credential"].textContent = "Update credential";
  elements["credential-editor"].open = true;
  elements.website.focus();
});

elements["cancel-edit"].addEventListener("click", resetEditor);

elements["delete-credential"].addEventListener("click", async () => {
  const credential = selectedCredential();
  if (!credential) return;
  const secret = elements["reveal-secret"].value;
  if (secret.length < MIN_SECRET_LENGTH) {
    reportError(new Error("Enter your master secret above before deleting a credential."));
    elements["reveal-secret"].focus();
    return;
  }
  if (!confirm(`Delete ${credential.website} — ${credential.username}?`)) return;

  try {
    await unlockVault(secret, vaultConfig);
    await chrome.storage.sync.remove(credentialStorageKey(credential.id));
    credentials = credentials.filter((item) => item.id !== credential.id);
    elements["reveal-secret"].value = "";
    hideRevealedPassword();
    resetEditor();
    render();
    showMessage("Credential deleted.");
  } catch (error) {
    reportError(error);
  }
});

elements["change-secret-form"].addEventListener("submit", async (event) => {
  event.preventDefault();
  const currentSecret = elements["current-secret"].value;
  const newSecret = elements["new-secret"].value;
  if (newSecret !== elements["new-secret-confirm"].value) {
    reportError(new Error("The new master secrets do not match."));
    return;
  }

  setBusy(elements["change-secret-form"], true);
  try {
    const rotated = await rotateVaultSecret(
      credentials,
      currentSecret,
      newSecret,
      vaultConfig
    );
    await replaceSyncedVault(rotated.config, rotated.entries);
    vaultConfig = rotated.config;
    credentials = rotated.entries;
    elements["change-secret-form"].reset();
    hideRevealedPassword();
    showMessage("Master secret changed. All passwords were re-encrypted.");
  } catch (error) {
    reportError(error);
  } finally {
    setBusy(elements["change-secret-form"], false);
  }
});

elements["reset-vault"].addEventListener("click", async () => {
  const confirmation = prompt('Type "RESET" to permanently delete the vault.');
  if (confirmation !== "RESET") return;

  try {
    const stored = await chrome.storage.sync.get(null);
    const vaultKeys = Object.keys(stored).filter(
      (key) => key === STORAGE_KEYS.config || key.startsWith(STORAGE_KEYS.credentialPrefix)
    );
    if (vaultKeys.length > 0) {
      await chrome.storage.sync.remove(vaultKeys);
    }
    await chrome.storage.local.remove([STORAGE_KEYS.config, STORAGE_KEYS.legacyEntries]);
    vaultConfig = null;
    credentials = [];
    hideRevealedPassword();
    resetEditor();
    render();
    showMessage("Vault reset. You can create a new one.");
  } catch (error) {
    reportError(error);
  }
});

window.addEventListener("pagehide", () => {
  hideRevealedPassword();
  for (const input of document.querySelectorAll('input[type="password"]')) {
    input.value = "";
  }
});

chrome.storage.onChanged.addListener((changes, areaName) => {
  const relevantChange = Object.keys(changes).some(
    (key) => key === STORAGE_KEYS.config || key.startsWith(STORAGE_KEYS.credentialPrefix)
  );
  if (areaName !== "sync" || !relevantChange) return;

  clearTimeout(syncReloadTimer);
  syncReloadTimer = setTimeout(() => {
    loadState({ allowMigration: false }).catch(reportError);
  }, 150);
});

loadState().catch(reportError);
