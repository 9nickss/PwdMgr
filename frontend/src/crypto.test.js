import test from 'node:test';
import assert from 'node:assert/strict';

import {
  encryptEntry,
  decryptEntry,
  generateVaultKey,
  wrapKey,
  unwrapKey,
  deriveMasterKey,
  encryptPrivateKey,
  exportEcdhPrivateKey,
  exportEcdhPublicKey,
  importEcdhPrivateKey,
  importEcdhPublicKey,
  deriveSharedKey,
  generateSalt,
  generateEcdhKeyPair,
  splitMasterKey,
  exportRawKey,
  unwrapSharedKey,
  wrapSharedKey
} from './crypto.js';

test('encryptEntry/decryptEntry round-trip should preserve JSON payload and validate integrity', async () => {
  const vaultKey = await generateVaultKey();
  const payload = {
    title: 'GitHub',
    username: 'alice',
    password: 'super-secret',
    notes: 'sensitive note'
  };

  const encrypted = await encryptEntry(payload, vaultKey);

  assert.ok(encrypted && typeof encrypted === 'object');
  assert.ok(Array.isArray(encrypted.iv));
  assert.ok(Array.isArray(encrypted.ciphertext));
  assert.ok(encrypted.iv.length > 0);
  assert.ok(encrypted.ciphertext.length > 0);

  const decrypted = await decryptEntry(encrypted, vaultKey);
  assert.deepStrictEqual(decrypted, payload);

  const tampered = {
    ...encrypted,
    ciphertext: encrypted.ciphertext.slice(0, -1).concat([((encrypted.ciphertext.at(-1) + 1) % 256)])
  };

  await assert.rejects(() => decryptEntry(tampered, vaultKey), /OperationError|Integrity|Authentication|decrypt/);
});

test('encryptEntry should produce different IVs for the same payload', async () => {
  const vaultKey = await generateVaultKey();
  const payload = { title: 'GitHub', username: 'alice', password: 'secret' };

  const firstEncryption = await encryptEntry(payload, vaultKey);
  const secondEncryption = await encryptEntry(payload, vaultKey);

  assert.notDeepStrictEqual(firstEncryption.iv, secondEncryption.iv);
  assert.notDeepStrictEqual(firstEncryption.ciphertext, secondEncryption.ciphertext);
});

test('decryptEntry should reject a blob encrypted with another Vault Key', async () => {
  const vaultKey = await generateVaultKey();
  const otherVaultKey = await generateVaultKey();
  const encrypted = await encryptEntry({ title: 'GitHub' }, vaultKey);

  await assert.rejects(
    () => decryptEntry(encrypted, otherVaultKey),
    /OperationError|decrypt/
  );
});

test('wrapKey/unwrapKey should protect and restore the Vault Key', async () => {
  const vaultKey = await generateVaultKey();
  const salt = await generateSalt();
  const masterKey = await deriveMasterKey('master-password', salt, 1);
  const { localKey } = await splitMasterKey(masterKey, salt);
  const wrongMasterKey = await deriveMasterKey('wrong-password', salt, 1);
  const { localKey: wrongLocalKey } = await splitMasterKey(wrongMasterKey, salt);
  const originalVaultKeyBytes = Array.from(await exportRawKey(vaultKey));

  const wrappedVaultKey = await wrapKey(vaultKey, localKey);
  const restoredVaultKey = await unwrapKey(wrappedVaultKey, localKey);

  assert.ok(Array.isArray(wrappedVaultKey.iv));
  assert.ok(Array.isArray(wrappedVaultKey.wrappedKey));
  assert.notDeepStrictEqual(wrappedVaultKey.wrappedKey, originalVaultKeyBytes);
  assert.deepStrictEqual(
    Array.from(await exportRawKey(restoredVaultKey)),
    originalVaultKeyBytes
  );
  await assert.rejects(
    () => unwrapKey(wrappedVaultKey, wrongLocalKey),
    /OperationError|decrypt/
  );
});

test('generateEcdhKeyPair should expose the public key and encrypt the private key', async () => {
  const keyPair = await generateEcdhKeyPair();
  const publicKey = await exportEcdhPublicKey(keyPair.publicKey);
  const privateKey = await exportEcdhPrivateKey(keyPair.privateKey);
  const salt = await generateSalt();
  const masterKey = await deriveMasterKey('master-password', salt, 1);
  const { localKey } = await splitMasterKey(masterKey, salt);
  const encryptedPrivateKey = await encryptPrivateKey(privateKey, localKey);

  assert.equal(publicKey.kty, 'EC');
  assert.equal(publicKey.crv, 'P-256');
  assert.equal(privateKey.kty, 'EC');
  assert.ok(Array.isArray(encryptedPrivateKey.iv));
  assert.ok(Array.isArray(encryptedPrivateKey.ciphertext));
  assert.notEqual(JSON.stringify(encryptedPrivateKey), JSON.stringify(privateKey));
});

test('ECDH shared keys should wrap and restore a Vault Key for the recipient', async () => {
  const sender = await generateEcdhKeyPair();
  const recipient = await generateEcdhKeyPair();
  const senderPrivateKey = await importEcdhPrivateKey(
    await exportEcdhPrivateKey(sender.privateKey)
  );
  const senderRecipientPublicKey = await importEcdhPublicKey(
    await exportEcdhPublicKey(recipient.publicKey)
  );
  const recipientPrivateKey = await importEcdhPrivateKey(
    await exportEcdhPrivateKey(recipient.privateKey)
  );
  const recipientSenderPublicKey = await importEcdhPublicKey(
    await exportEcdhPublicKey(sender.publicKey)
  );
  const senderSharedKey = await deriveSharedKey(
    senderPrivateKey,
    senderRecipientPublicKey
  );
  const recipientSharedKey = await deriveSharedKey(
    recipientPrivateKey,
    recipientSenderPublicKey
  );
  const vaultKey = await generateVaultKey();
  const wrappedKey = await wrapSharedKey(vaultKey, senderSharedKey);
  const restoredKey = await unwrapSharedKey(wrappedKey, recipientSharedKey);

  assert.deepStrictEqual(
    Array.from(await exportRawKey(restoredKey)),
    Array.from(await exportRawKey(vaultKey))
  );
  const wrongUser = await generateEcdhKeyPair();
  const wrongSharedKey = await deriveSharedKey(
    await importEcdhPrivateKey(await exportEcdhPrivateKey(wrongUser.privateKey)),
    recipientSenderPublicKey
  );
  await assert.rejects(
    () => unwrapSharedKey(wrappedKey, wrongSharedKey),
    /OperationError|decrypt/
  );
});
