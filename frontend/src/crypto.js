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