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
import {
  addTombstones,
  buildBackup,
  isCredentialRecord,
  legacyVaultId,
  mergeMirror,
  missingFromSync,
  parseBackup,
  removeTombstones,
  resolveVaultSnapshot,
  withVaultIdentity
} from "./sync-model.js";

const STORAGE_KEYS = {
  legacyConfig: "vaultConfig",
  configPrefix: "vaultConfig:",
  credentialPrefix: "credential:",
  // Written only when the user explicitly switches vaults. activeVaultV1 was
  // also written implicitly when a new computer created a vault, which hid the
  // established vault everywhere, so it is ignored.
  activeVault: "activeVaultV2",
  obsoleteActiveVault: "activeVaultV1",
  // Records vaults and credentials deleted on purpose, so local mirrors on
  // other computers do not offer to restore them.
  tombstones: "vaultTombstonesV1"
};

// Per-computer copy of the encrypted vaults. Removing the extension on another
// computer deletes its Chrome Sync data everywhere, but not this copy.
const MIRROR_KEY = "vaultMirrorV1";

const LOCAL_KEYS = {
  config: "vaultConfig",
  entries: "credentials",
  safetyBackup: "safetyBackupV1"
};

const elements = Object.fromEntries(
  [
    "message",
    "create-vault-warning",
    "dismiss-create-warning",
    "confirm-create-warning",
    "setup-view",
    "setup-actions",
    "setup-form",
    "setup-secret",
    "setup-confirm",
    "refresh-sync",
    "begin-create-vault",
    "cancel-create-vault",
    "vault-view",
    "orphan-notice",
    "orphan-notice-text",
    "restore-panel",
    "restore-summary",
    "restore-vaults",
    "restore-notice",
    "restore-notice-text",
    "restore-vaults-inline",
    "import-backup-setup",
    "export-backup",
    "import-backup",
    "import-file",
    "multi-vault-notice",
    "vault-switch-form",
    "vault-switch-select",
    "vault-switch-secret",
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
    "toggle-entry-password",
    "password-help",
    "save-secret",
    "save-credential",
    "cancel-edit",
    "change-secret-form",
    "current-secret",
    "new-secret",
    "new-secret-confirm",
    "reset-vault-warning",
    "reset-vault-form",
    "reset-vault-summary",
    "reset-confirm-input",
    "cancel-reset-vault",
    "confirm-reset-vault",
    "prune-vaults-section",
    "prune-vaults-warning",
    "prune-vaults-summary",
    "cancel-prune-vaults",
    "confirm-prune-vaults",
    "prune-secret",
    "prune-vaults",
    "reset-vault"
  ].map((id) => [id, document.getElementById(id)])
);

let vaultConfig = null;
let credentials = [];
let syncedVaults = [];
let missingVaults = [];
let orphanedEntries = [];
let mirrorSavedAt = null;
let messageTimer = null;
let syncReloadTimer = null;
let setupFormRevealed = false;

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
  const configKey = `${STORAGE_KEYS.configPrefix}${config.vaultId}`;
  const payload = { [configKey]: config };
  assertSyncItemFits(configKey, config);
  for (const credential of entries) {
    const taggedCredential = { ...credential, vaultId: config.vaultId };
    const key = credentialStorageKey(taggedCredential.id);
    assertSyncItemFits(key, taggedCredential);
    payload[key] = taggedCredential;
  }
  return payload;
}

function isVaultKey(key) {
  return (
    key === STORAGE_KEYS.legacyConfig ||
    key === STORAGE_KEYS.activeVault ||
    key === STORAGE_KEYS.obsoleteActiveVault ||
    key.startsWith(STORAGE_KEYS.configPrefix) ||
    key.startsWith(STORAGE_KEYS.credentialPrefix)
  );
}

function storedLegacyConfig(stored) {
  return stored[STORAGE_KEYS.legacyConfig]
    ? withVaultIdentity(stored[STORAGE_KEYS.legacyConfig])
    : null;
}

function vaultIsStored(stored, vaultId) {
  return Boolean(
    stored[`${STORAGE_KEYS.configPrefix}${vaultId}`] ||
      storedLegacyConfig(stored)?.vaultId === vaultId
  );
}

async function readSyncedVault() {
  const stored = await chrome.storage.sync.get(null);
  const configs = Object.entries(stored)
    .filter(
      ([key, value]) =>
        key.startsWith(STORAGE_KEYS.configPrefix) && typeof value?.vaultId === "string"
    )
    .map(([, value]) => value);
  const selectedVaultId =
    typeof stored[STORAGE_KEYS.activeVault]?.vaultId === "string"
      ? stored[STORAGE_KEYS.activeVault].vaultId
      : null;
  const allEntries = Object.entries(stored)
    .filter(([key, value]) =>
      key.startsWith(STORAGE_KEYS.credentialPrefix) && isCredentialRecord(value)
    )
    .map(([, value]) => value);
  return {
    ...resolveVaultSnapshot(configs, storedLegacyConfig(stored), selectedVaultId, allEntries),
    tombstones: stored[STORAGE_KEYS.tombstones] ?? null,
    credentialIds: new Set(allEntries.map((entry) => entry.id))
  };
}

async function updateTombstones(change) {
  const stored = await chrome.storage.sync.get(STORAGE_KEYS.tombstones);
  const next = change(stored[STORAGE_KEYS.tombstones] ?? null);
  assertSyncItemFits(STORAGE_KEYS.tombstones, next);
  await chrome.storage.sync.set({ [STORAGE_KEYS.tombstones]: next });
}

async function markDeleted(ids) {
  await updateTombstones((tombstones) =>
    addTombstones(tombstones, ids, new Date().toISOString())
  );
}

async function readMirror() {
  const local = await chrome.storage.local.get(MIRROR_KEY);
  return local[MIRROR_KEY] ?? null;
}

// Local only: Sync is never written while refreshing the mirror.
async function refreshMirror(synced) {
  const mirror = await readMirror();
  const savedAt = synced.vaults.length > 0 ? new Date().toISOString() : mirror?.savedAt ?? null;
  const next = mergeMirror(mirror, synced.vaults, synced.tombstones, savedAt);
  await chrome.storage.local.set({ [MIRROR_KEY]: next });
  mirrorSavedAt = next.savedAt;
  missingVaults = missingFromSync(
    next,
    new Set(synced.vaults.map((vault) => vault.config.vaultId)),
    synced.credentialIds,
    synced.tombstones
  );
}

// Additive: writes only vaults and credentials that Sync does not have, and
// never overwrites or deletes anything.
async function restoreToSync(vaults) {
  const stored = await chrome.storage.sync.get(null);
  const payload = {};
  let vaultCount = 0;
  let credentialCount = 0;
  for (const { config, entries } of vaults) {
    if (!vaultIsStored(stored, config.vaultId)) {
      const configKey = `${STORAGE_KEYS.configPrefix}${config.vaultId}`;
      assertSyncItemFits(configKey, config);
      payload[configKey] = config;
      vaultCount += 1;
    }
    for (const entry of entries) {
      const key = credentialStorageKey(entry.id);
      if (stored[key] || payload[key]) continue;
      const tagged = { ...entry, vaultId: config.vaultId };
      assertSyncItemFits(key, tagged);
      payload[key] = tagged;
      credentialCount += 1;
    }
  }
  if (Object.keys(payload).length > 0) {
    await chrome.storage.sync.set(payload);
  }
  await updateTombstones((tombstones) =>
    removeTombstones(tombstones, {
      vaults: vaults.map(({ config }) => config.vaultId),
      credentials: vaults.flatMap(({ entries }) => entries.map((entry) => entry.id))
    })
  );
  return { vaultCount, credentialCount };
}

async function replaceSyncedVault(config, entries) {
  const payload = syncPayload(config, entries);
  await chrome.storage.sync.set(payload);
}

async function selectSyncedVault(vaultId) {
  const activeVault = { vaultId, selectedAt: new Date().toISOString() };
  assertSyncItemFits(STORAGE_KEYS.activeVault, activeVault);
  await chrome.storage.sync.set({ [STORAGE_KEYS.activeVault]: activeVault });
}

// Only called from an explicit, confirmed user action.
async function removeOtherSyncedVaults(config) {
  const stored = await chrome.storage.sync.get(null);
  const legacyId = storedLegacyConfig(stored)?.vaultId ?? null;
  const obsoleteKeys = Object.entries(stored)
    .filter(([key, value]) => {
      if (key === STORAGE_KEYS.legacyConfig) return legacyId !== config.vaultId;
      if (key === STORAGE_KEYS.obsoleteActiveVault) return true;
      if (key.startsWith(STORAGE_KEYS.configPrefix)) {
        return key !== `${STORAGE_KEYS.configPrefix}${config.vaultId}`;
      }
      if (key.startsWith(STORAGE_KEYS.credentialPrefix) && isCredentialRecord(value)) {
        return (value.vaultId ?? legacyId) !== config.vaultId;
      }
      return false;
    })
    .map(([key]) => key);
  if (obsoleteKeys.length > 0) {
    await chrome.storage.sync.remove(obsoleteKeys);
  }
}

// Older versions kept the vault (or a safety copy of it) in chrome.storage.local.
// Copy any such vault into Sync as an additional vault, and only then clear the
// local copy. Nothing already in Sync is overwritten.
async function migrateLocalVaults() {
  const local = await chrome.storage.local.get(Object.values(LOCAL_KEYS));
  const sources = [];
  if (local[LOCAL_KEYS.config]) {
    sources.push({
      config: local[LOCAL_KEYS.config],
      entries: local[LOCAL_KEYS.entries]
    });
  }
  const backup = local[LOCAL_KEYS.safetyBackup];
  if (backup?.config) {
    sources.push({ config: backup.config, entries: backup.entries });
  }
  if (sources.length === 0) return;

  const stored = await chrome.storage.sync.get(null);
  const pending = sources.map((source) => ({
    config: withVaultIdentity(
      source.config,
      source.config.vaultId ?? legacyVaultId(source.config)
    ),
    entries: (Array.isArray(source.entries) ? source.entries : []).filter(
      (entry) =>
        isCredentialRecord(entry) && !stored[credentialStorageKey(entry.id)]
    )
  }));
  for (const { config, entries } of pending) {
    if (!vaultIsStored(stored, config.vaultId)) {
      await replaceSyncedVault(config, entries);
    }
  }

  const verified = await chrome.storage.sync.get(null);
  if (pending.every(({ config }) => vaultIsStored(verified, config.vaultId))) {
    await chrome.storage.local.remove(Object.values(LOCAL_KEYS));
  }
}

async function loadState() {
  try {
    await migrateLocalVaults();
  } catch (error) {
    reportError(error);
  }
  // Keep startup and Sync event handling free of deletions. A partial snapshot
  // must never cause records to be removed from every synchronized computer.
  const synced = await readSyncedVault();
  try {
    await refreshMirror(synced);
  } catch (error) {
    reportError(error);
  }

  vaultConfig = synced.config;
  credentials = synced.entries;
  syncedVaults = synced.vaults;
  orphanedEntries = synced.orphanedEntries;
  credentials.sort((left, right) =>
    `${left.website}\u0000${left.username}`.localeCompare(`${right.website}\u0000${right.username}`)
  );
  render();
}

function formatVaultOption({ config, count }) {
  const created = new Date(config.createdAt);
  const date =
    config.createdAt && created.getTime() > 0
      ? created.toLocaleDateString()
      : "an earlier version";
  const countText = count === 1 ? "1 credential" : `${count} credentials`;
  const current = config.vaultId === vaultConfig?.vaultId ? " (in use)" : "";
  return `Created ${date} — ${countText}${current}`;
}

function plural(count, singular, pluralForm = `${singular}s`) {
  return `${count} ${count === 1 ? singular : pluralForm}`;
}

function confirmPruneVaults(vaultCount, credentialCount) {
  const dialog = elements["prune-vaults-warning"];
  elements["prune-vaults-summary"].textContent =
    `${plural(vaultCount, "vault")} and ${plural(credentialCount, "saved credential")} ` +
    "will be permanently removed from every computer using this Chrome Sync account.";
  return new Promise((resolve) => {
    const finish = (confirmed) => {
      elements["confirm-prune-vaults"].removeEventListener("click", onConfirm);
      elements["cancel-prune-vaults"].removeEventListener("click", onCancel);
      dialog.removeEventListener("cancel", onCancel);
      dialog.close();
      resolve(confirmed);
    };
    const onConfirm = () => finish(true);
    const onCancel = () => finish(false);
    elements["confirm-prune-vaults"].addEventListener("click", onConfirm);
    elements["cancel-prune-vaults"].addEventListener("click", onCancel);
    dialog.addEventListener("cancel", onCancel);
    dialog.showModal();
    elements["cancel-prune-vaults"].focus();
  });
}

const RESET_CONFIRMATION = "RESET";

function confirmResetVault(vaultCount, credentialCount) {
  const dialog = elements["reset-vault-warning"];
  const form = elements["reset-vault-form"];
  const input = elements["reset-confirm-input"];
  const confirmButton = elements["confirm-reset-vault"];
  elements["reset-vault-summary"].textContent =
    `${plural(vaultCount, "vault")} and ${plural(credentialCount, "saved credential")} ` +
    "will be permanently removed from every computer using this Chrome Sync account.";
  input.value = "";
  confirmButton.disabled = true;

  return new Promise((resolve) => {
    const matches = () => input.value.trim() === RESET_CONFIRMATION;
    const onInput = () => {
      confirmButton.disabled = !matches();
    };
    const finish = (confirmed) => {
      input.removeEventListener("input", onInput);
      form.removeEventListener("submit", onSubmit);
      elements["cancel-reset-vault"].removeEventListener("click", onCancel);
      dialog.removeEventListener("cancel", onCancel);
      input.value = "";
      dialog.close();
      resolve(confirmed);
    };
    const onSubmit = (event) => {
      event.preventDefault();
      if (matches()) finish(true);
    };
    const onCancel = () => finish(false);
    input.addEventListener("input", onInput);
    form.addEventListener("submit", onSubmit);
    elements["cancel-reset-vault"].addEventListener("click", onCancel);
    dialog.addEventListener("cancel", onCancel);
    dialog.showModal();
    input.focus();
  });
}

function renderVaultSwitcher() {
  const multiple = syncedVaults.length > 1;
  elements["multi-vault-notice"].hidden = !multiple;
  elements["prune-vaults-section"].hidden = !multiple;
  if (!multiple) return;

  const select = elements["vault-switch-select"];
  const previous = select.value;
  select.replaceChildren();
  for (const vault of syncedVaults) {
    const option = document.createElement("option");
    option.value = vault.config.vaultId;
    option.textContent = formatVaultOption(vault);
    select.append(option);
  }
  select.value = syncedVaults.some((vault) => vault.config.vaultId === previous)
    ? previous
    : vaultConfig.vaultId;
}

function missingSummary() {
  const vaultCount = missingVaults.filter((vault) => vault.configMissing).length;
  const credentialCount = missingVaults.reduce(
    (total, vault) => total + vault.entries.length,
    0
  );
  const parts = [];
  if (vaultCount > 0) parts.push(plural(vaultCount, "vault"));
  if (credentialCount > 0) parts.push(plural(credentialCount, "saved credential"));
  return parts.join(" and ");
}

function renderOrphans() {
  const restorable = new Set(
    missingVaults.filter((vault) => vault.configMissing).map((vault) => vault.config.vaultId)
  );
  const stranded = orphanedEntries.filter((entry) => !restorable.has(entry.vaultId));
  elements["orphan-notice"].hidden = stranded.length === 0;
  if (stranded.length === 0) return;

  const names = stranded.map((entry) => `${entry.website} — ${entry.username}`).join(", ");
  elements["orphan-notice-text"].textContent =
    `${plural(stranded.length, "saved credential")} (${names}) arrived from Chrome Sync, ` +
    `but the vault ${stranded.length === 1 ? "it belongs" : "they belong"} to is missing. ` +
    "On the computer where it was saved, open " +
    "ChromePW and select Restore to Chrome Sync, or import a backup file here.";
}

function renderRestore(configured) {
  renderOrphans();
  const hasMissing = missingVaults.length > 0;
  elements["restore-panel"].hidden = configured || !hasMissing;
  elements["restore-notice"].hidden = !configured || !hasMissing;
  if (!hasMissing) return;

  const saved = mirrorSavedAt ? new Date(mirrorSavedAt).toLocaleString() : null;
  const summary = missingSummary();
  elements["restore-summary"].textContent =
    `This computer kept a copy of ${summary}` +
    (saved ? ` (last updated ${saved})` : "") +
    " that is no longer in Chrome Sync. This happens when ChromePW is removed on another computer.";
  elements["restore-notice-text"].textContent =
    `Missing from Chrome Sync but saved on this computer: ${summary}.`;
}

function render() {
  const configured = Boolean(vaultConfig);
  renderRestore(configured);
  elements["setup-view"].hidden = configured;
  elements["vault-view"].hidden = !configured;
  elements["setup-actions"].hidden = configured || setupFormRevealed;
  elements["setup-form"].hidden = configured || !setupFormRevealed;
  if (!configured) {
    elements["multi-vault-notice"].hidden = true;
    return;
  }
  renderVaultSwitcher();

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

function setEntryPasswordVisible(visible) {
  const label = visible ? "Hide password" : "Show password";
  elements["entry-password"].type = visible ? "text" : "password";
  elements["toggle-entry-password"].setAttribute("aria-pressed", String(visible));
  elements["toggle-entry-password"].setAttribute("aria-label", label);
  elements["toggle-entry-password"].title = label;
}

function resetEditor() {
  elements["credential-form"].reset();
  setEntryPasswordVisible(false);
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
    const latestSynced = await readSyncedVault();
    if (latestSynced.config) {
      elements["setup-form"].reset();
      setupFormRevealed = false;
      await loadState();
      showMessage("A synchronized vault arrived, so ChromePW used it instead of creating a new one.");
      return;
    }
    const cryptoConfig = await createVaultConfig(secret, KDF_ITERATIONS);
    const nextConfig = withVaultIdentity(
      cryptoConfig,
      crypto.randomUUID(),
      new Date().toISOString()
    );
    // Additive only: never select or delete other vaults here. If an existing
    // vault arrives from Sync later, the older vault is shown and this one
    // stays available in the vault switcher.
    await replaceSyncedVault(nextConfig, []);
    elements["setup-form"].reset();
    setupFormRevealed = false;
    await loadState();
    showMessage("Your encrypted vault is ready.");
  } catch (error) {
    reportError(error);
  } finally {
    setBusy(elements["setup-form"], false);
  }
});

elements["begin-create-vault"].addEventListener("click", async () => {
  elements["begin-create-vault"].disabled = true;
  try {
    await loadState();
    if (vaultConfig) {
      showMessage("Your synchronized vault is available. ChromePW will use it.");
      return;
    }
    elements["create-vault-warning"].showModal();
  } catch (error) {
    reportError(error);
  } finally {
    elements["begin-create-vault"].disabled = false;
  }
});

elements["dismiss-create-warning"].addEventListener("click", () => {
  elements["create-vault-warning"].close();
});

elements["confirm-create-warning"].addEventListener("click", () => {
  elements["create-vault-warning"].close();
  setupFormRevealed = true;
  render();
  elements["setup-secret"].focus();
});

elements["cancel-create-vault"].addEventListener("click", () => {
  elements["setup-form"].reset();
  setupFormRevealed = false;
  render();
});

elements["refresh-sync"].addEventListener("click", async () => {
  elements["refresh-sync"].disabled = true;
  try {
    await loadState();
    if (vaultConfig) {
      showMessage("Your synchronized vault is now available.");
    } else {
      showMessage(
        "No synchronized vault has arrived yet. Keep Chrome Sync enabled and try again shortly.",
        "error",
        true
      );
    }
  } catch (error) {
    reportError(error);
  } finally {
    elements["refresh-sync"].disabled = false;
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
      vaultId: vaultConfig.vaultId,
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
  setEntryPasswordVisible(false);
  elements["save-secret"].value = "";
  elements["editor-summary"].textContent = "Edit credential";
  elements["password-help"].textContent = "Leave blank to keep the current password.";
  elements["cancel-edit"].hidden = false;
  elements["save-credential"].textContent = "Update credential";
  elements["credential-editor"].open = true;
  elements.website.focus();
});

elements["cancel-edit"].addEventListener("click", resetEditor);

elements["toggle-entry-password"].addEventListener("click", () => {
  setEntryPasswordVisible(elements["entry-password"].type === "password");
  elements["entry-password"].focus();
});

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
    await markDeleted({ credentials: [credential.id] });
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
    const rotatedConfig = withVaultIdentity(
      rotated.config,
      vaultConfig.vaultId,
      vaultConfig.createdAt
    );
    const rotatedEntries = rotated.entries.map((entry) => ({
      ...entry,
      vaultId: vaultConfig.vaultId
    }));
    await replaceSyncedVault(rotatedConfig, rotatedEntries);
    vaultConfig = rotatedConfig;
    credentials = rotatedEntries;
    elements["change-secret-form"].reset();
    hideRevealedPassword();
    showMessage("Master secret changed. All passwords were re-encrypted.");
  } catch (error) {
    reportError(error);
  } finally {
    setBusy(elements["change-secret-form"], false);
  }
});

elements["vault-switch-form"].addEventListener("submit", async (event) => {
  event.preventDefault();
  const chosen = syncedVaults.find(
    (vault) => vault.config.vaultId === elements["vault-switch-select"].value
  );
  if (!chosen) return;

  setBusy(elements["vault-switch-form"], true);
  try {
    await unlockVault(elements["vault-switch-secret"].value, chosen.config);
    await selectSyncedVault(chosen.config.vaultId);
    elements["vault-switch-secret"].value = "";
    hideRevealedPassword();
    resetEditor();
    await loadState();
    showMessage("Switched vaults on every synchronized computer.");
  } catch (error) {
    reportError(error);
  } finally {
    setBusy(elements["vault-switch-form"], false);
  }
});

elements["prune-vaults"].addEventListener("click", async () => {
  const secret = elements["prune-secret"].value;
  if (secret.length < MIN_SECRET_LENGTH) {
    reportError(new Error("Enter the master secret of the vault in use."));
    elements["prune-secret"].focus();
    return;
  }
  const others = syncedVaults.filter(
    (vault) => vault.config.vaultId !== vaultConfig.vaultId
  );
  const otherCount = others.reduce((total, vault) => total + vault.count, 0);

  try {
    await unlockVault(secret, vaultConfig);
    if (!(await confirmPruneVaults(others.length, otherCount))) return;
    await selectSyncedVault(vaultConfig.vaultId);
    await markDeleted({ vaults: others.map((vault) => vault.config.vaultId) });
    await removeOtherSyncedVaults(vaultConfig);
    elements["prune-secret"].value = "";
    await loadState();
    showMessage(`${plural(others.length, "vault")} deleted.`);
  } catch (error) {
    reportError(error);
  }
});

async function restoreMissingVaults(button) {
  button.disabled = true;
  try {
    const restored = await restoreToSync(missingVaults);
    await loadState();
    showMessage(
      `Restored ${plural(restored.vaultCount, "vault")} and ${plural(
        restored.credentialCount,
        "credential"
      )} to Chrome Sync.`
    );
  } catch (error) {
    reportError(error);
  } finally {
    button.disabled = false;
  }
}

elements["restore-vaults"].addEventListener("click", () =>
  restoreMissingVaults(elements["restore-vaults"])
);
elements["restore-vaults-inline"].addEventListener("click", () =>
  restoreMissingVaults(elements["restore-vaults-inline"])
);

elements["export-backup"].addEventListener("click", () => {
  if (syncedVaults.length === 0) {
    reportError(new Error("There is no vault to export yet."));
    return;
  }
  const exportedAt = new Date().toISOString();
  const backup = buildBackup(syncedVaults, exportedAt);
  const url = URL.createObjectURL(
    new Blob([JSON.stringify(backup, null, 2)], { type: "application/json" })
  );
  const link = document.createElement("a");
  link.href = url;
  link.download = `chromepw-backup-${exportedAt.slice(0, 10)}.json`;
  link.click();
  setTimeout(() => URL.revokeObjectURL(url), 1000);
  showMessage("Backup exported. Passwords in the file stay encrypted with your master secret.");
});

for (const id of ["import-backup", "import-backup-setup"]) {
  elements[id].addEventListener("click", () => {
    elements["import-file"].value = "";
    elements["import-file"].click();
  });
}

elements["import-file"].addEventListener("change", async () => {
  const [file] = elements["import-file"].files;
  if (!file) return;
  try {
    const vaults = parseBackup(await file.text());
    const restored = await restoreToSync(vaults);
    await loadState();
    showMessage(
      restored.vaultCount + restored.credentialCount === 0
        ? "Everything in this backup is already in Chrome Sync."
        : `Imported ${plural(restored.vaultCount, "vault")} and ${plural(
            restored.credentialCount,
            "credential"
          )}.`
    );
  } catch (error) {
    reportError(error);
  } finally {
    elements["import-file"].value = "";
  }
});

elements["reset-vault"].addEventListener("click", async () => {
  const vaultCount = Math.max(syncedVaults.length, 1);
  const credentialCount = syncedVaults.reduce((total, vault) => total + vault.count, 0);
  if (!(await confirmResetVault(vaultCount, credentialCount))) return;

  try {
    const mirror = await readMirror();
    await markDeleted({
      vaults: [
        ...syncedVaults.map((vault) => vault.config.vaultId),
        ...Object.keys(mirror?.vaults ?? {})
      ]
    });
    const stored = await chrome.storage.sync.get(null);
    const vaultKeys = Object.keys(stored).filter(isVaultKey);
    if (vaultKeys.length > 0) {
      await chrome.storage.sync.remove(vaultKeys);
    }
    await chrome.storage.local.remove(MIRROR_KEY);
    vaultConfig = null;
    credentials = [];
    syncedVaults = [];
    missingVaults = [];
    hideRevealedPassword();
    resetEditor();
    render();
    showMessage("ChromePW was reset. You can now create a new vault.");
  } catch (error) {
    reportError(error);
  }
});

window.addEventListener("pagehide", () => {
  hideRevealedPassword();
  setEntryPasswordVisible(false);
  for (const input of document.querySelectorAll('input[type="password"]')) {
    input.value = "";
  }
});

chrome.storage.onChanged.addListener((changes, areaName) => {
  const relevantChange = Object.keys(changes).some(
    (key) => isVaultKey(key) || key === STORAGE_KEYS.tombstones
  );
  if (areaName !== "sync" || !relevantChange) return;

  clearTimeout(syncReloadTimer);
  syncReloadTimer = setTimeout(() => {
    loadState().catch(reportError);
  }, 150);
});

loadState().catch(reportError);
