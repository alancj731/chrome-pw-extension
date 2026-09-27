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
  const vaults = [...candidates].sort(compareVaults).map((candidate) => ({
    config: candidate,
    count: allEntries.filter(
      (entry) => entryVaultId(entry, legacyConfig) === candidate.vaultId
    ).length
  }));

  return {
    config,
    entries,
    vaults,
    vaultCount: candidates.length
  };
}
