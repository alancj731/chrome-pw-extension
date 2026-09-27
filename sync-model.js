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
  return [...configs].sort((left, right) => {
    const dateOrder = String(left.createdAt).localeCompare(String(right.createdAt));
    return dateOrder || String(left.vaultId).localeCompare(String(right.vaultId));
  })[0];
}
