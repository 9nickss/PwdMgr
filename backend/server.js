const crypto = require('crypto');
const express = require('express');
const { Pool } = require('pg');

const app = express();
const port = process.env.PORT || 3000;
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

if (require.main === module) {
  app.listen(port, () => {
    console.log(`Server running on port ${port}`);
  });
}

module.exports = { app, pool };
