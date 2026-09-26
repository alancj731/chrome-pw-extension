const textEncoder = new TextEncoder();
const textDecoder = new TextDecoder();

export const VAULT_VERSION = 1;
export const KDF_ITERATIONS = 600_000;
export const MIN_SECRET_LENGTH = 12;

const VERIFIER_TEXT = "ChromePW vault verifier v1";
const VERIFIER_AAD = textEncoder.encode("chromepw:verifier:v1");

function cryptoApi() {
  if (!globalThis.crypto?.subtle) {
    throw new Error("The Web Crypto API is unavailable.");
  }
  return globalThis.crypto;
}

function bytesToBase64(bytes) {
  let binary = "";
  const chunkSize = 0x8000;
  for (let offset = 0; offset < bytes.length; offset += chunkSize) {
    binary += String.fromCharCode(...bytes.subarray(offset, offset + chunkSize));
  }
  return btoa(binary);
}

function base64ToBytes(value) {
  try {
    const binary = atob(value);
    return Uint8Array.from(binary, (character) => character.charCodeAt(0));
  } catch {
    throw new VaultError("CORRUPT_VAULT", "The saved vault contains invalid data.");
  }
}

function randomBytes(length) {
  return cryptoApi().getRandomValues(new Uint8Array(length));
}

function requireSecret(secret) {
  if (typeof secret !== "string" || secret.length < MIN_SECRET_LENGTH) {
    throw new VaultError(
      "WEAK_SECRET",
      `The master secret must be at least ${MIN_SECRET_LENGTH} characters.`
    );
  }
}

function validateConfig(config) {
  const valid =
    config &&
    config.version === VAULT_VERSION &&
    config.kdf?.name === "PBKDF2" &&
    config.kdf?.hash === "SHA-256" &&
    Number.isInteger(config.kdf?.iterations) &&
    config.kdf.iterations > 0 &&
    typeof config.kdf?.salt === "string" &&
    config.verifier?.algorithm === "AES-GCM" &&
    typeof config.verifier?.iv === "string" &&
    typeof config.verifier?.ciphertext === "string";

  if (!valid) {
    throw new VaultError("CORRUPT_VAULT", "The saved vault configuration is invalid.");
  }
}

function validateEncryptedPassword(encryptedPassword) {
  const valid =
    encryptedPassword?.algorithm === "AES-GCM" &&
    typeof encryptedPassword?.iv === "string" &&
    typeof encryptedPassword?.ciphertext === "string";

  if (!valid) {
    throw new VaultError("CORRUPT_ENTRY", "This saved password is invalid or damaged.");
  }
}

async function deriveKey(secret, config) {
  const importedSecret = await cryptoApi().subtle.importKey(
    "raw",
    textEncoder.encode(secret),
    "PBKDF2",
    false,
    ["deriveKey"]
  );

  return cryptoApi().subtle.deriveKey(
    {
      name: "PBKDF2",
      hash: config.kdf.hash,
      salt: base64ToBytes(config.kdf.salt),
      iterations: config.kdf.iterations
    },
    importedSecret,
    { name: "AES-GCM", length: 256 },
    false,
    ["encrypt", "decrypt"]
  );
}

async function encryptText(plaintext, key, additionalData) {
  const iv = randomBytes(12);
  const ciphertext = await cryptoApi().subtle.encrypt(
    { name: "AES-GCM", iv, additionalData },
    key,
    textEncoder.encode(plaintext)
  );

  return {
    algorithm: "AES-GCM",
    iv: bytesToBase64(iv),
    ciphertext: bytesToBase64(new Uint8Array(ciphertext))
  };
}

async function decryptText(encryptedValue, key, additionalData) {
  try {
    const plaintext = await cryptoApi().subtle.decrypt(
      {
        name: "AES-GCM",
        iv: base64ToBytes(encryptedValue.iv),
        additionalData
      },
      key,
      base64ToBytes(encryptedValue.ciphertext)
    );
    return textDecoder.decode(plaintext);
  } catch (error) {
    if (error instanceof VaultError) {
      throw error;
    }
    throw new VaultError("DECRYPT_FAILED", "The master secret is incorrect or the data is damaged.");
  }
}

function entryAad(entryId) {
  return textEncoder.encode(`chromepw:entry:v1:${entryId}`);
}

export class VaultError extends Error {
  constructor(code, message) {
    super(message);
    this.name = "VaultError";
    this.code = code;
  }
}

export function validateLabel(value, fieldName, maximumLength = 200) {
  if (typeof value !== "string" || !value.trim()) {
    throw new VaultError("INVALID_ENTRY", `${fieldName} is required.`);
  }
  if (value.trim().length > maximumLength) {
    throw new VaultError(
      "INVALID_ENTRY",
      `${fieldName} must be ${maximumLength} characters or fewer.`
    );
  }
  return value.trim();
}

export async function createVaultConfig(secret, iterations = KDF_ITERATIONS) {
  requireSecret(secret);
  if (!Number.isInteger(iterations) || iterations <= 0) {
    throw new VaultError("INVALID_KDF", "The key derivation settings are invalid.");
  }

  const config = {
    version: VAULT_VERSION,
    kdf: {
      name: "PBKDF2",
      hash: "SHA-256",
      iterations,
      salt: bytesToBase64(randomBytes(16))
    }
  };
  const key = await deriveKey(secret, config);
  config.verifier = await encryptText(VERIFIER_TEXT, key, VERIFIER_AAD);
  return config;
}

export async function unlockVault(secret, config) {
  requireSecret(secret);
  validateConfig(config);
  const key = await deriveKey(secret, config);
  const verifier = await decryptText(config.verifier, key, VERIFIER_AAD);
  if (verifier !== VERIFIER_TEXT) {
    throw new VaultError("DECRYPT_FAILED", "The master secret is incorrect.");
  }
  return key;
}

export async function encryptPassword(password, key, entryId) {
  if (typeof password !== "string" || password.length === 0) {
    throw new VaultError("INVALID_ENTRY", "Password is required.");
  }
  if (password.length > 10_000) {
    throw new VaultError("INVALID_ENTRY", "Password is too long.");
  }
  if (typeof entryId !== "string" || !entryId) {
    throw new VaultError("INVALID_ENTRY", "Credential ID is required.");
  }
  return encryptText(password, key, entryAad(entryId));
}

export async function decryptPassword(encryptedPassword, key, entryId) {
  validateEncryptedPassword(encryptedPassword);
  return decryptText(encryptedPassword, key, entryAad(entryId));
}

export async function rotateVaultSecret(entries, currentSecret, newSecret, currentConfig) {
  const currentKey = await unlockVault(currentSecret, currentConfig);
  const plaintextPasswords = await Promise.all(
    entries.map((entry) => decryptPassword(entry.password, currentKey, entry.id))
  );

  const nextConfig = await createVaultConfig(newSecret);
  const nextKey = await unlockVault(newSecret, nextConfig);
  const nextEntries = await Promise.all(
    entries.map(async (entry, index) => ({
      ...entry,
      password: await encryptPassword(plaintextPasswords[index], nextKey, entry.id),
      updatedAt: new Date().toISOString()
    }))
  );

  return { config: nextConfig, entries: nextEntries };
}
