export async function generateSalt() {
  return await crypto.getRandomValues(new Uint8Array(16));
}

export async function deriveMasterKey(password, salt, iterations = 600000) {
  const encoder = new TextEncoder();
  const passwordBuffer = encoder.encode(password);
  const passwordKey = await crypto.subtle.importKey(
    'raw',
    passwordBuffer,
    { name: 'PBKDF2' },
    false,
    ['deriveKey']
  );
  return await crypto.subtle.deriveKey(
    {
      name: 'PBKDF2',
      salt: salt,
      iterations: iterations,
      hash: 'SHA-256'
    },
    passwordKey,
    { name: 'AES-GCM', length: 256 },
    true,
    ['encrypt', 'decrypt']
  );
}

export async function exportRawKey(key) {
  return await crypto.subtle.exportKey('raw', key);
}

export async function importRawKey(keyBytes, algorithm = { name: 'HKDF' }) {
  return await crypto.subtle.importKey(
    'raw',
    keyBytes,
    algorithm,
    false,
    ['deriveKey']
  );
}

export async function deriveHkdfKey(sharedSecret, salt, info, keyLength) {
  return await crypto.subtle.deriveKey(
    {
      name: 'HKDF',
      hash: 'SHA-256',
      salt: salt,
      info: new TextEncoder().encode(info)
    },
    sharedSecret,
    { name: 'AES-GCM', length: keyLength * 8 },
    false,
    ['encrypt', 'decrypt']
  );
}

export async function splitMasterKey(masterKey, salt) {
  const masterKeyBytes = await exportRawKey(masterKey);
  const sharedSecret = await importRawKey(masterKeyBytes, { name: 'HKDF' });
  const localKey = await deriveHkdfKey(
    sharedSecret,
    salt,
    'VaultMgr-LocalKey',
    32
  );
  const authKey = await deriveHkdfKey(
    sharedSecret,
    salt,
    'VaultMgr-AuthKey',
    32
  );
  return { localKey, authKey };
}

export async function generateVaultKey() {
  return await crypto.subtle.generateKey(
    { name: 'AES-GCM', length: 256 },
    true,
    ['encrypt', 'decrypt']
  );
}

export async function encryptEntry(plaintextObject, vaultKey) {
  const encoder = new TextEncoder();
  const plaintext = encoder.encode(JSON.stringify(plaintextObject));
  const iv = await crypto.getRandomValues(new Uint8Array(12));
  const ciphertext = await crypto.subtle.encrypt(
    {
      name: 'AES-GCM',
      iv: iv
    },
    vaultKey,
    plaintext
  );
  return {
    iv: Array.from(new Uint8Array(iv)),
    ciphertext: Array.from(new Uint8Array(ciphertext))
  };
}

export async function decryptEntry(encryptedObject, vaultKey) {
  const iv = new Uint8Array(encryptedObject.iv);
  const ciphertext = new Uint8Array(encryptedObject.ciphertext);
  const plaintext = await crypto.subtle.decrypt(
    {
      name: 'AES-GCM',
      iv: iv
    },
    vaultKey,
    ciphertext
  );
  const decoder = new TextDecoder();
  return JSON.parse(decoder.decode(plaintext));
}

export async function wrapKey(vaultKey, localKey) {
  const vaultKeyBytes = await exportRawKey(vaultKey);
  const iv = await crypto.getRandomValues(new Uint8Array(12));
  const wrappedKey = await crypto.subtle.encrypt(
    {
      name: 'AES-GCM',
      iv: iv
    },
    localKey,
    vaultKeyBytes
  );
  return {
    iv: Array.from(new Uint8Array(iv)),
    wrappedKey: Array.from(new Uint8Array(wrappedKey))
  };
}

export async function unwrapKey(wrappedObject, localKey) {
  const iv = new Uint8Array(wrappedObject.iv);
  const wrappedKey = new Uint8Array(wrappedObject.wrappedKey);
  const vaultKeyBytes = await crypto.subtle.decrypt(
    {
      name: 'AES-GCM',
      iv: iv
    },
    localKey,
    wrappedKey
  );
  return await crypto.subtle.importKey(
    'raw',
    vaultKeyBytes,
    { name: 'AES-GCM', length: 256 },
    true,
    ['encrypt', 'decrypt']
  );
}