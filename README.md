# ChromePW

ChromePW is a small Chrome extension for manually storing encrypted passwords and synchronizing them through Chrome Sync. It does not inspect websites, autofill forms, make its own network requests, or request access to browsing activity.

## Features

- Set up one master secret (minimum 12 characters).
- Save a website label, username, and password.
- Select a saved website and username, enter the master secret, and decrypt the password.
- Copy, show, or hide a decrypted password.
- Edit and delete credentials.
- Change the master secret and re-encrypt every saved password.
- Synchronize the encrypted vault between Chrome browsers signed into the same Google account.
- Keep master-secret fields hidden on startup unless creating a brand-new vault or performing a protected operation.
- Check Chrome Sync before offering vault creation; creating a vault never removes or hides an existing one.
- Switch between vaults (with that vault's master secret) if several exist in Chrome Sync.
- Keep an encrypted copy of the vault on each computer and restore it if Chrome Sync loses it.
- Export and import an encrypted backup file.
- Reset the vault if the master secret is lost.

## Install in Chrome

1. Open `chrome://extensions`.
2. Enable **Developer mode**.
3. Select **Load unpacked**.
4. Choose this project directory.
5. Pin ChromePW from the extensions menu if desired.

Click the ChromePW toolbar icon to create or use the vault.

## How to use ChromePW

### 1. Let ChromePW check Sync first

When ChromePW opens on a new computer, it checks Chrome Sync for an existing vault. If no vault appears yet, wait for Chrome Sync to finish and select **Check Chrome Sync again**.

Do not create a new vault if you already use ChromePW on another computer.

![ChromePW waiting for a synchronized vault](screenshots/no-synced-vault.png)

### 2. Create a vault only when you need a new one

If you are certain that no existing vault should be used, select **Create a new vault**. ChromePW asks for confirmation first.

Creating a vault is additive: it never deletes or hides another vault. If an older vault arrives from Chrome Sync afterwards, ChromePW uses the older vault and lists both under **Switch vault**. Unwanted vaults can be removed explicitly with **Vault settings → Delete other vaults**.

![ChromePW confirmation before creating a separate vault](screenshots/replace-vault-warning.png)

After confirming, enter and confirm a master secret of at least 12 characters. The master secret is never saved and cannot be recovered.

### 3. Save and retrieve credentials

Open **Add a credential** to save a website name, username, and password. Enter the master secret to encrypt and save the password.

To retrieve a password:

1. Select the website and username.
2. Enter the master secret.
3. Select **Decrypt password**.
4. Copy the password or hide it when finished.

![ChromePW credential selection and password decryption screen](screenshots/password-vault.png)

Use **Edit selected** or **Delete selected** to manage a credential. Open **Vault settings** to change the master secret or reset the vault.

### 4. Removing, updating and backing up

**Removing ChromePW on one computer affects every computer.** When an extension is removed, Chrome deletes its Chrome Sync data, and that deletion reaches every computer signed into the same Google account. No extension can prevent this, because the extension does not run while it is being removed.

**To update ChromePW, select reload ↻ on its card in `chrome://extensions`. Do not remove it.**

#### Restoring after a removal

Every computer keeps its own encrypted copy of the vault, which removal on another computer cannot delete. If the synchronized vault disappears:

1. Open ChromePW on a computer that still has it installed. It shows **Your vault can be restored**.
2. Select **Restore to Chrome Sync**.
3. The vault returns on every computer, including the one where ChromePW is reinstalled. The master secret stays the same.

![ChromePW offering to restore a vault that is missing from Chrome Sync](screenshots/restore.png)

Restoring only adds what is missing and never overwrites anything. Credentials and vaults you deleted on purpose (**Delete selected**, **Delete other vaults**, **Reset vault**) are not offered for restore.

#### Limitations

- The computer you restore from must run ChromePW 1.7.0 or later, and ChromePW must have been opened on it at least once. Earlier versions keep no local copy.
- Each computer's copy contains what ChromePW showed the last time it was opened on that computer. If you add a password on computer A and remove ChromePW from A before opening ChromePW on computer B, that password cannot be restored from B.
- If a password arrives from Chrome Sync but its vault is missing, ChromePW says so and names the password. Restore the vault from the computer where it was saved, or import a backup file.
- If ChromePW is removed on your only computer, nothing is left to restore from except a backup file.

#### Backup files

Open **Vault settings → Export backup** from time to time and keep the file somewhere safe. Use **Import backup** (or **Import a backup file** on the setup screen) to restore it. The passwords in the file stay encrypted and still need the master secret.

## Security design

- The master secret is never stored.
- PBKDF2-HMAC-SHA-256 with 600,000 iterations and a random 16-byte salt derives an AES-256-GCM key.
- Each password has a new random 12-byte IV and authenticated encryption.
- Passwords are stored in `chrome.storage.sync`; website labels and usernames remain plaintext so they can be selected before entering the master secret.
- Each credential is stored as a separate sync item to respect Chrome's per-item storage quota.
- Vault configurations use immutable unique IDs, so first-run setup on a partially synced computer cannot overwrite an established vault.
- If several vault records arrive out of order, ChromePW consistently selects the oldest established vault.
- Creating a vault never marks it active or removes other vaults; only an explicit **Use this vault** (verified with that vault's master secret) changes which vault every computer shows.
- A partially synchronized device never deletes credentials merely because they are absent from its current snapshot.
- Opening ChromePW and processing Sync updates are read-only; synchronized records are deleted only by an explicit user action.
- Each computer keeps an encrypted mirror of the synchronized vaults in `chrome.storage.local`. Removing the extension on another computer cannot delete it. The mirror is written only locally, and it goes back to Chrome Sync only when you select **Restore to Chrome Sync**.
- Intentional deletions are recorded as tombstones in Chrome Sync, so mirrors on other computers never offer to restore them.
- A vault left in `chrome.storage.local` by an earlier version is copied into Chrome Sync as an additional vault (never overwriting synced records), and the old local copy is removed only after the copy is confirmed.
- Backup files contain only the already-encrypted vault data; they do not contain the master secret.
- The extension requests only Chrome's `storage` permission and has no content scripts, host permissions, background worker, analytics, or network code.
- Closing the popup discards entered secrets and decrypted values from the extension page.

Chrome handles transport and account synchronization; the extension itself never receives Google credentials. Chrome Sync must be enabled for the same Google account on each computer, and the extension must have the same ID on each installation.

The master secret cannot be recovered. Anyone who can access the synchronized ciphertext can attempt offline guesses, so use a long and unique secret. ChromePW cannot protect data on a compromised computer or from malicious browser extensions with sufficient access.

## Development

The extension has no runtime dependencies.

