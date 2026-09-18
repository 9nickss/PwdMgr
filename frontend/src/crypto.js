// frontend/src/crypto.js

/**
 * Generate a random salt for PBKDF2.
 * @returns {Promise<ArrayBuffer>} A random salt of 16 bytes.
 */
export async function generateSalt() {
  return await crypto.getRandomValues(new Uint8Array(16));
}

/**
 * Derive a master key from a master password and salt using PBKDF2-SHA256.
 * @param {string} password - The master password.
 * @param {ArrayBuffer} salt - The salt to use.
 * @param {number} iterations - Number of iterations (default: 600000).
 * @returns {Promise<CryptoKey>} The derived master key (extractable).
 */
export async function deriveMasterKey(password, salt, iterations = 600000) {
  const encoder = new TextEncoder();
  const passwordBuffer = encoder.encode(password);

  // Import the password as a raw key for PBKDF2
  const passwordKey = await crypto.subtle.importKey(
    'raw',
    passwordBuffer,
    { name: 'PBKDF2' },
    false,
    ['deriveKey']
  );

  // Derive the master key
  return await crypto.subtle.deriveKey(
    {
      name: 'PBKDF2',
      salt: salt,
      iterations: iterations,
      hash: 'SHA-256'
    },
    passwordKey,
    { name: 'AES-GCM', length: 256 }, // We are deriving an AES-GCM key
    true, // extractable
    ['encrypt', 'decrypt'] // We can use this key for encryption/decryption
  );
}