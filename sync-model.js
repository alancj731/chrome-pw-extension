export function sameVaultConfig(left, right) {
  return Boolean(left && right && JSON.stringify(left) === JSON.stringify(right));
}

export function mergeSafetyBackup(
  existingBackup,
  config,
  entries,
  { deletedIds = [], forceReplace = false, savedAt = new Date().toISOString() } = {}
) {
  if (!config) return existingBackup ?? null;

  const existingIsValid =
    existingBackup?.config && Array.isArray(existingBackup?.entries);
  if (!existingIsValid) {
    return { version: 1, savedAt, config, entries: [...entries] };
  }

  if (sameVaultConfig(existingBackup.config, config)) {
    const merged = new Map(existingBackup.entries.map((entry) => [entry.id, entry]));
    for (const entry of entries) merged.set(entry.id, entry);
    for (const id of deletedIds) merged.delete(id);
    return { version: 1, savedAt, config, entries: [...merged.values()] };
  }

  if (!forceReplace && entries.length < existingBackup.entries.length) {
    return existingBackup;
  }

  return { version: 1, savedAt, config, entries: [...entries] };
}

export function missingBackupEntries(backup, config, entries) {
  if (
    !backup?.config ||
    !Array.isArray(backup?.entries) ||
    !sameVaultConfig(backup.config, config)
  ) {
    return [];
  }

  const syncedIds = new Set(entries.map((entry) => entry.id));
  return backup.entries.filter((entry) => !syncedIds.has(entry.id));
}
