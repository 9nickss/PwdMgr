const assert = require('node:assert/strict');
const crypto = require('node:crypto');
const http = require('node:http');
const test = require('node:test');
const jwt = require('jsonwebtoken');

const { app, pool } = require('./server');

function hashAuthProof(authHash, salt) {
  return new Promise((resolve, reject) => {
    crypto.scrypt(authHash, salt, 64, (error, derivedKey) => {
      if (error) {
        reject(error);
        return;
      }
      resolve(`scrypt$${salt.toString('base64')}$${derivedKey.toString('base64')}`);
    });
  });
}

function request(options, body) {
  return new Promise((resolve, reject) => {
    const request = http.request(
      {
        ...options,
        method: 'POST',
        path: '/auth/login',
        headers: { 'content-type': 'application/json' }
      },
      (response) => {
        let responseBody = '';
        response.setEncoding('utf8');
        response.on('data', (chunk) => {
          responseBody += chunk;
        });
        response.on('end', () => {
          resolve({
            statusCode: response.statusCode,
            body: JSON.parse(responseBody)
          });
        });
      }
    );

    request.on('error', reject);
    request.end(JSON.stringify(body));
  });
}

test('POST /auth/login verifies the auth proof and returns a JWT', async (t) => {
  const authHash = 'derived-auth-key';
  const storedHash = await hashAuthProof(authHash, Buffer.alloc(16, 7));
  const originalQuery = pool.query;
  pool.query = async (query, values) => {
    assert.match(query, /SELECT id, email, auth_hash FROM users/);
    assert.deepStrictEqual(values, ['alice@example.com']);
    return {
      rowCount: 1,
      rows: [{ id: 'user-id', email: 'alice@example.com', auth_hash: storedHash }]
    };
  };
  t.after(() => {
    pool.query = originalQuery;
  });

  const server = app.listen(0);
  t.after(() => server.close());
  const address = server.address();
  const validResponse = await request(
    { host: '127.0.0.1', port: address.port },
    { email: ' Alice@Example.com ', authHash }
  );

  assert.equal(validResponse.statusCode, 200);
  assert.ok(validResponse.body.token);
  const claims = jwt.verify(
    validResponse.body.token,
    process.env.JWT_SECRET || 'securevault-development-secret'
  );
  assert.equal(claims.sub, 'user-id');
  assert.equal(claims.email, 'alice@example.com');
  assert.equal(typeof claims.iat, 'number');
  assert.equal(typeof claims.exp, 'number');
});

test('POST /auth/login rejects an invalid auth proof', async (t) => {
  const originalQuery = pool.query;
  pool.query = async () => ({
    rowCount: 1,
    rows: [{
      id: 'user-id',
      email: 'alice@example.com',
      auth_hash: await hashAuthProof('correct-auth-key', Buffer.alloc(16, 7))
    }]
  });
  t.after(() => {
    pool.query = originalQuery;
  });

  const server = app.listen(0);
  t.after(() => server.close());
  const address = server.address();
  const response = await request(
    { host: '127.0.0.1', port: address.port },
    { email: 'alice@example.com', authHash: 'wrong-auth-key' }
  );

  assert.equal(response.statusCode, 401);
  assert.deepStrictEqual(response.body, { error: 'Invalid credentials' });
});
