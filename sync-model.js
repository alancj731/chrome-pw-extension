export function isCredentialRecord(value) {
  return Boolean(
    value &&
      typeof value.id === "string" &&
      typeof value.website === "string" &&
      typeof value.username === "string" &&
      value.password &&
      typeof value.password.iv === "string" &&
      typeof value.password.ciphertext === "string"
  );
}

export function isVaultConfig(value) {
  return Boolean(
    value &&
      typeof value.kdf?.salt === "string" &&
      typeof value.verifier?.iv === "string" &&
      typeof value.verifier?.ciphertext === "string"
  );
}

export function legacyVaultId(config) {
  const salt = String(config?.kdf?.salt ?? "unknown")
    .replaceAll("+", "-")
    .replaceAll("/", "_")
    .replace(/=+$/u, "");
  return `legacy-${salt}`;
}

export function withVaultIdentity(
  config,
  vaultId = config?.vaultId ?? legacyVaultId(config),
  createdAt = config?.createdAt ?? "1970-01-01T00:00:00.000Z"
) {
  return { ...config, vaultId, createdAt };
}

export function selectCanonicalVault(configs) {
  if (configs.length === 0) return null;
  return [...configs].sort(compareVaults)[0];
}

function compareVaults(left, right) {
  const dateOrder = String(left.createdAt).localeCompare(String(right.createdAt));
  return dateOrder || String(left.vaultId).localeCompare(String(right.vaultId));
}

// Credentials written before vault IDs existed have no vaultId; they belong to
// the legacy (unversioned) vault config.
function entryVaultId(entry, legacyConfig) {
  return entry.vaultId ?? legacyConfig?.vaultId ?? null;
}

export function resolveVaultSnapshot(
  configs,
  legacyConfig,
  selectedVaultId,
  allEntries
) {
  const candidates = [...configs];
  if (
    legacyConfig &&
    !candidates.some((config) => config.vaultId === legacyConfig.vaultId)
  ) {
    candidates.push(legacyConfig);
  }

  // An explicit selection wins only while that vault still exists; otherwise
  // the oldest vault is used so a newly created vault can never hide an
  // established one.
  const selectedConfig = selectedVaultId
    ? candidates.find((config) => config.vaultId === selectedVaultId) ?? null
    : null;
  const config = selectedConfig ?? selectCanonicalVault(candidates);
  const entries = config
    ? allEntries
        .filter((entry) => entryVaultId(entry, legacyConfig) === config.vaultId)
        .map((entry) => ({ ...entry, vaultId: config.vaultId }))
    : [];
  const vaults = [...candidates].sort(compareVaults).map((candidate) => {
    const vaultEntries = allEntries
      .filter((entry) => entryVaultId(entry, legacyConfig) === candidate.vaultId)
      .map((entry) => ({ ...entry, vaultId: candidate.vaultId }));
    return { config: candidate, entries: vaultEntries, count: vaultEntries.length };
  });

  return {
    config,
    entries,
    vaults,
    vaultCount: candidates.length
  };
}

// Removing the extension on one computer makes Chrome delete its Sync data on
// every computer. Each computer therefore keeps a local mirror of the encrypted
// vaults. Tombstones record intentional deletions so they are not restored.
export const TOMBSTONE_LIMIT = 100;

function tombstoneMap(tombstones, kind) {
  const map = tombstones?.[kind];
  return map && typeof map === "object" ? map : {};
}

function newestEntries(map, limit) {
  return Object.fromEntries(
    Object.entries(map)
      .sort(([, left], [, right]) => String(right).localeCompare(String(left)))
      .slice(0, limit)
  );
}

export function addTombstones(
  tombstones,
  { vaults = [], credentials = [] },
  deletedAt,
  limit = TOMBSTONE_LIMIT
) {
  const next = {
    vaults: { ...tombstoneMap(tombstones, "vaults") },
    credentials: { ...tombstoneMap(tombstones, "credentials") }
  };
  for (const id of vaults) next.vaults[id] = deletedAt;
  for (const id of credentials) next.credentials[id] = deletedAt;
  return {
    vaults: newestEntries(next.vaults, limit),
    credentials: newestEntries(next.credentials, limit)
  };
}

export function removeTombstones(tombstones, { vaults = [], credentials = [] }) {
  const next = {
    vaults: { ...tombstoneMap(tombstones, "vaults") },
    credentials: { ...tombstoneMap(tombstones, "credentials") }
  };
  for (const id of vaults) delete next.vaults[id];
  for (const id of credentials) delete next.credentials[id];
  return next;
}

// syncVaults: [{ config, entries }] for every vault currently in Sync.
// Vaults and credentials that disappear from Sync stay in the mirror unless a
// tombstone says they were deleted on purpose; Sync wins for everything present.
export function mergeMirror(mirror, syncVaults, tombstones, savedAt) {
  const deletedVaults = tombstoneMap(tombstones, "vaults");
  const deletedCredentials = tombstoneMap(tombstones, "credentials");
  const vaults = {};
  for (const [vaultId, vault] of Object.entries(mirror?.vaults ?? {})) {
    if (!deletedVaults[vaultId]) vaults[vaultId] = vault;
  }
  for (const { config, entries } of syncVaults) {
    const merged = new Map(
      (vaults[config.vaultId]?.entries ?? []).map((entry) => [entry.id, entry])
    );
    for (const entry of entries) merged.set(entry.id, entry);
    vaults[config.vaultId] = { config, entries: [...merged.values()] };
  }
  for (const vault of Object.values(vaults)) {
    vault.entries = vault.entries.filter((entry) => !deletedCredentials[entry.id]);
  }
  return { savedAt, vaults };
}

// Returns what the mirror holds that Sync has lost: whole vaults (configMissing)
// and individual credentials, excluding anything deleted on purpose.
export function missingFromSync(mirror, syncVaultIds, syncCredentialIds, tombstones) {
  const deletedVaults = tombstoneMap(tombstones, "vaults");
  const deletedCredentials = tombstoneMap(tombstones, "credentials");
  const missing = [];
  for (const [vaultId, vault] of Object.entries(mirror?.vaults ?? {})) {
    if (deletedVaults[vaultId]) continue;
    const configMissing = !syncVaultIds.has(vaultId);
    const entries = vault.entries.filter(
      (entry) => !syncCredentialIds.has(entry.id) && !deletedCredentials[entry.id]
    );
    if (configMissing || entries.length > 0) {
      missing.push({ config: vault.config, entries, configMissing });
    }
  }
  return missing;
}

export const BACKUP_FORMAT = "chromepw-backup";
export const BACKUP_VERSION = 1;

export function buildBackup(vaults, exportedAt) {
  return {
    format: BACKUP_FORMAT,
    version: BACKUP_VERSION,
    exportedAt,
    vaults: vaults.map(({ config, entries }) => ({ config, entries }))
  };
}

export function parseBackup(text) {
  let data;
  try {
    data = JSON.parse(text);
  } catch {
    throw new Error("This file is not a ChromePW backup.");
  }
  if (data?.format !== BACKUP_FORMAT || !Array.isArray(data.vaults)) {
    throw new Error("This file is not a ChromePW backup.");
  }
  if (data.version !== BACKUP_VERSION) {
    throw new Error("This backup was made by a newer version of ChromePW.");
  }
  const vaults = data.vaults.map((vault) => {
    if (!isVaultConfig(vault?.config) || !Array.isArray(vault.entries)) {
      throw new Error("This backup is damaged and cannot be imported.");
    }
    const config = withVaultIdentity(vault.config);
    if (!vault.entries.every(isCredentialRecord)) {
      throw new Error("This backup is damaged and cannot be imported.");
    }
    return {
      config,
      entries: vault.entries.map((entry) => ({ ...entry, vaultId: config.vaultId }))
    };
  });
  if (vaults.length === 0) {
    throw new Error("This backup does not contain any vaults.");
  }
  return vaults;
}
