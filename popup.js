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
  entries: "credentials"
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
  const message =
    error instanceof VaultError || error instanceof Error
      ? error.message
      : "Something went wrong. Please try again.";
  showMessage(message, "error", true);
}

async function loadState() {
  const stored = await chrome.storage.local.get([STORAGE_KEYS.config, STORAGE_KEYS.entries]);
  vaultConfig = stored[STORAGE_KEYS.config] ?? null;
  credentials = Array.isArray(stored[STORAGE_KEYS.entries])
    ? stored[STORAGE_KEYS.entries]
    : [];
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

async function saveState() {
  await chrome.storage.local.set({
    [STORAGE_KEYS.config]: vaultConfig,
    [STORAGE_KEYS.entries]: credentials
  });
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
    vaultConfig = await createVaultConfig(secret, KDF_ITERATIONS);
    credentials = [];
    await saveState();
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

    credentials = existing
      ? credentials.map((item) => (item.id === id ? credential : item))
      : [...credentials, credential];
    await saveState();
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
    credentials = credentials.filter((item) => item.id !== credential.id);
    await saveState();
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
    vaultConfig = rotated.config;
    credentials = rotated.entries;
    await saveState();
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
    await chrome.storage.local.remove([STORAGE_KEYS.config, STORAGE_KEYS.entries]);
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

loadState().catch(reportError);
