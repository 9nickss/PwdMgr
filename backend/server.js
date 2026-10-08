const crypto = require('crypto');
const express = require('express');
const jwt = require('jsonwebtoken');
const { Pool } = require('pg');

const app = express();
const port = process.env.PORT || 3000;
const jwtSecret = process.env.JWT_SECRET || 'securevault-development-secret';
const pool = new Pool({
  host: process.env.PGHOST || 'localhost',
  port: process.env.PGPORT || 5432,
  user: process.env.PGUSER || 'securevault',
  password: process.env.PGPASSWORD || 'securevault_pass',
  database: process.env.PGDATABASE || 'securevault'
});

app.use(express.json({ limit: '1mb' }));

function normalizeEmail(email) {
  return typeof email === 'string' ? email.trim().toLowerCase() : '';
}

function hashAuthProof(authHash) {
  return new Promise((resolve, reject) => {
    const salt = crypto.randomBytes(16);
    crypto.scrypt(authHash, salt, 64, (error, derivedKey) => {
      if (error) {
        reject(error);
        return;
      }
      resolve(`scrypt$${salt.toString('base64')}$${derivedKey.toString('base64')}`);
    });
  });
}

function verifyAuthProof(authHash, storedHash) {
  return new Promise((resolve, reject) => {
    const [algorithm, saltBase64, hashBase64] = String(storedHash).split('$');

    if (algorithm !== 'scrypt' || !saltBase64 || !hashBase64) {
      resolve(false);
      return;
    }

    const salt = Buffer.from(saltBase64, 'base64');
    const expectedHash = Buffer.from(hashBase64, 'base64');
    crypto.scrypt(authHash, salt, expectedHash.length, (error, derivedHash) => {
      if (error) {
        reject(error);
        return;
      }

      resolve(
        derivedHash.length === expectedHash.length &&
        crypto.timingSafeEqual(derivedHash, expectedHash)
      );
    });
  });
}

function authenticateToken(req, res, next) {
  const authorization = req.get('authorization') || '';
  const [scheme, token] = authorization.split(' ');

  if (scheme !== 'Bearer' || !token) {
    res.status(401).json({ error: 'Authentication required' });
    return;
  }

  try {
    req.user = jwt.verify(token, jwtSecret);
    next();
  } catch (error) {
    res.status(401).json({ error: 'Invalid or expired token' });
  }
}

function getVaultPayload(body) {
  const payload = body && typeof body === 'object' ? body : {};
  const encryptedBlob = payload.encryptedBlob ?? payload.encrypted_blob;
  const vaultKeyWrapped = payload.vaultKeyWrapped ?? payload.vault_key_wrapped;

  if ([encryptedBlob, payload.nonce, payload.tag, vaultKeyWrapped]
    .some((value) => typeof value !== 'string' || !value)) {
    return null;
  }

  return {
    encryptedBlob,
    nonce: payload.nonce,
    tag: payload.tag,
    vaultKeyWrapped
  };
}

app.get('/', (req, res) => {
  res.send('SecureVault Backend');
});

app.get('/auth/salt/:email', async (req, res) => {
  const email = normalizeEmail(req.params.email);

  if (!email) {
    res.status(400).json({ error: 'A valid email is required' });
    return;
  }

  try {
    const result = await pool.query(
      'SELECT salt FROM users WHERE email = $1',
      [email]
    );

    if (result.rowCount === 0) {
      res.status(404).json({ error: 'User not found' });
      return;
    }

    res.json({ salt: result.rows[0].salt });
  } catch (error) {
    console.error('Failed to retrieve authentication salt:', error);
    res.status(500).json({ error: 'Internal server error' });
  }
});

app.post('/auth/register', async (req, res) => {
  const body = req.body && typeof req.body === 'object' ? req.body : {};
  const { email: rawEmail, authHash, salt, publicKey } = body;
  const email = normalizeEmail(rawEmail);

  if ('password' in body || 'masterPassword' in body) {
    res.status(400).json({ error: 'The master password must not be sent' });
    return;
  }

  if (!email || typeof authHash !== 'string' || !authHash || typeof salt !== 'string' || !salt) {
    res.status(400).json({ error: 'email, authHash and salt are required' });
    return;
  }

  try {
    const hashedAuthProof = await hashAuthProof(authHash);
    const result = await pool.query(
      `INSERT INTO users (email, auth_hash, salt, public_key)
       VALUES ($1, $2, $3, $4)
       RETURNING id, email, salt, public_key, created_at`,
      [email, hashedAuthProof, salt, typeof publicKey === 'string' ? publicKey : null]
    );

    res.status(201).json({ user: result.rows[0] });
  } catch (error) {
    if (error.code === '23505') {
      res.status(409).json({ error: 'A user with this email already exists' });
      return;
    }

    console.error('Failed to register user:', error);
    res.status(500).json({ error: 'Internal server error' });
  }
});

app.post('/auth/login', async (req, res) => {
  const body = req.body && typeof req.body === 'object' ? req.body : {};
  const { email: rawEmail, authHash } = body;
  const email = normalizeEmail(rawEmail);

  if ('password' in body || 'masterPassword' in body) {
    res.status(400).json({ error: 'The master password must not be sent' });
    return;
  }

  if (!email || typeof authHash !== 'string' || !authHash) {
    res.status(400).json({ error: 'email and authHash are required' });
    return;
  }

  try {
    const result = await pool.query(
      'SELECT id, email, auth_hash FROM users WHERE email = $1',
      [email]
    );

    if (result.rowCount === 0 || !(await verifyAuthProof(authHash, result.rows[0].auth_hash))) {
      res.status(401).json({ error: 'Invalid credentials' });
      return;
    }

    const user = result.rows[0];
    const token = jwt.sign(
      { sub: user.id, email: user.email },
      jwtSecret,
      { expiresIn: '1h' }
    );

    res.json({ token });
  } catch (error) {
    console.error('Failed to log in user:', error);
    res.status(500).json({ error: 'Internal server error' });
  }
});

app.get('/vault', authenticateToken, async (req, res) => {
  try {
    const result = await pool.query(
      `SELECT id, encrypted_blob, nonce, tag, vault_key_wrapped, created_at, updated_at
       FROM vault_items
       WHERE user_id = $1
       ORDER BY updated_at DESC`,
      [req.user.sub]
    );

    res.json({ items: result.rows });
  } catch (error) {
    console.error('Failed to retrieve vault items:', error);
    res.status(500).json({ error: 'Internal server error' });
  }
});

app.get('/vault/:id', authenticateToken, async (req, res) => {
  try {
    const result = await pool.query(
      `SELECT id, encrypted_blob, nonce, tag, vault_key_wrapped, created_at, updated_at
       FROM vault_items
       WHERE id = $1 AND user_id = $2`,
      [req.params.id, req.user.sub]
    );

    if (result.rowCount === 0) {
      res.status(404).json({ error: 'Vault item not found' });
      return;
    }

    res.json({ item: result.rows[0] });
  } catch (error) {
    if (error.code === '22P02') {
      res.status(404).json({ error: 'Vault item not found' });
      return;
    }
    console.error('Failed to retrieve vault item:', error);
    res.status(500).json({ error: 'Internal server error' });
  }
});

app.post('/vault', authenticateToken, async (req, res) => {
  const payload = getVaultPayload(req.body);

  if (!payload) {
    res.status(400).json({
      error: 'encryptedBlob, nonce, tag and vaultKeyWrapped are required'
    });
    return;
  }

  try {
    const result = await pool.query(
      `INSERT INTO vault_items (user_id, encrypted_blob, nonce, tag, vault_key_wrapped)
       VALUES ($1, $2, $3, $4, $5)
       RETURNING id, encrypted_blob, nonce, tag, vault_key_wrapped, created_at, updated_at`,
      [req.user.sub, payload.encryptedBlob, payload.nonce, payload.tag, payload.vaultKeyWrapped]
    );

    res.status(201).json({ item: result.rows[0] });
  } catch (error) {
    console.error('Failed to create vault item:', error);
    res.status(500).json({ error: 'Internal server error' });
  }
});

app.put('/vault/:id', authenticateToken, async (req, res) => {
  const payload = getVaultPayload(req.body);

  if (!payload) {
    res.status(400).json({
      error: 'encryptedBlob, nonce, tag and vaultKeyWrapped are required'
    });
    return;
  }

  try {
    const result = await pool.query(
      `UPDATE vault_items
       SET encrypted_blob = $1, nonce = $2, tag = $3, vault_key_wrapped = $4, updated_at = NOW()
       WHERE id = $5 AND user_id = $6
       RETURNING id, encrypted_blob, nonce, tag, vault_key_wrapped, created_at, updated_at`,
      [
        payload.encryptedBlob,
        payload.nonce,
        payload.tag,
        payload.vaultKeyWrapped,
        req.params.id,
        req.user.sub
      ]
    );

    if (result.rowCount === 0) {
      res.status(404).json({ error: 'Vault item not found' });
      return;
    }

    res.json({ item: result.rows[0] });
  } catch (error) {
    if (error.code === '22P02') {
      res.status(404).json({ error: 'Vault item not found' });
      return;
    }
    console.error('Failed to update vault item:', error);
    res.status(500).json({ error: 'Internal server error' });
  }
});

app.delete('/vault/:id', authenticateToken, async (req, res) => {
  try {
    const result = await pool.query(
      'DELETE FROM vault_items WHERE id = $1 AND user_id = $2 RETURNING id',
      [req.params.id, req.user.sub]
    );

    if (result.rowCount === 0) {
      res.status(404).json({ error: 'Vault item not found' });
      return;
    }

    res.status(204).send();
  } catch (error) {
    if (error.code === '22P02') {
      res.status(404).json({ error: 'Vault item not found' });
      return;
    }
    console.error('Failed to delete vault item:', error);
    res.status(500).json({ error: 'Internal server error' });
  }
});

if (require.main === module) {
  app.listen(port, () => {
    console.log(`Server running on port ${port}`);
  });
}

module.exports = { app, pool };
