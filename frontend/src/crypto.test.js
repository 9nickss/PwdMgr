import test from 'node:test';
import assert from 'node:assert/strict';

import {
  encryptEntry,
  decryptEntry,
  generateVaultKey
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
