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
        method: options.method || 'POST',
        path: options.path || '/auth/login',
        headers: {
          'content-type': 'application/json',
          ...options.headers
        }
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

test('vault routes reject requests without a JWT', async (t) => {
  const server = app.listen(0);
  t.after(() => server.close());
  const address = server.address();
  const response = await request({
    host: '127.0.0.1',
    port: address.port,
    method: 'GET',
    path: '/vault'
  });

  assert.equal(response.statusCode, 401);
  assert.deepStrictEqual(response.body, { error: 'Authentication required' });
});

test('POST /vault stores an encrypted item for the authenticated user', async (t) => {
  const token = jwt.sign(
    { sub: 'user-id', email: 'alice@example.com' },
    process.env.JWT_SECRET || 'securevault-development-secret'
  );
  const originalQuery = pool.query;
  pool.query = async (query, values) => {
    assert.match(query, /INSERT INTO vault_items/);
    assert.deepStrictEqual(values, [
      'user-id',
      'encrypted-data',
      'nonce-value',
      'tag-value',
      'wrapped-vault-key'
    ]);
    return {
      rowCount: 1,
      rows: [{
        id: 'item-id',
        encrypted_blob: 'encrypted-data',
        nonce: 'nonce-value',
        tag: 'tag-value',
        vault_key_wrapped: 'wrapped-vault-key'
      }]
    };
  };
  t.after(() => {
    pool.query = originalQuery;
  });

  const server = app.listen(0);
  t.after(() => server.close());
  const address = server.address();
  const response = await request(
    {
      host: '127.0.0.1',
      port: address.port,
      method: 'POST',
      path: '/vault',
      headers: { authorization: `Bearer ${token}` }
    },
    {
      encryptedBlob: 'encrypted-data',
      nonce: 'nonce-value',
      tag: 'tag-value',
      vaultKeyWrapped: 'wrapped-vault-key'
    }
  );

  assert.equal(response.statusCode, 201);
  assert.equal(response.body.item.id, 'item-id');
});

test('sharing routes reject requests without a JWT', async (t) => {
  const server = app.listen(0);
  t.after(() => server.close());
  const address = server.address();
  const response = await request({
    host: '127.0.0.1',
    port: address.port,
    method: 'GET',
    path: '/sharing/with-me'
  });

  assert.equal(response.statusCode, 401);
  assert.deepStrictEqual(response.body, { error: 'Authentication required' });
});

test('POST /sharing/:itemId resolves the recipient and stores the wrapped key', async (t) => {
  const token = jwt.sign(
    { sub: 'owner-id', email: 'owner@example.com' },
    process.env.JWT_SECRET || 'securevault-development-secret'
  );
  const originalQuery = pool.query;
  let queryCount = 0;
  pool.query = async (query, values) => {
    queryCount += 1;
    if (queryCount === 1) {
      assert.match(query, /SELECT id, email, public_key FROM users/);
      assert.deepStrictEqual(values, ['recipient@example.com']);
      return {
        rowCount: 1,
        rows: [{ id: 'recipient-id', email: 'recipient@example.com', public_key: '{"kty":"EC"}' }]
      };
    }
    if (queryCount === 2) {
      assert.match(query, /SELECT id FROM vault_items/);
      assert.deepStrictEqual(values, ['item-id', 'owner-id']);
      return { rowCount: 1, rows: [{ id: 'item-id' }] };
    }

    assert.match(query, /INSERT INTO shares/);
    assert.deepStrictEqual(values, ['item-id', 'recipient-id', '{"iv":[1],"wrappedKey":[2]}']);
    return {
      rowCount: 1,
      rows: [{
        id: 'share-id',
        item_id: 'item-id',
        shared_with_user_id: 'recipient-id',
        encrypted_vault_key_for_shared_user: '{"iv":[1],"wrappedKey":[2]}'
      }]
    };
  };
  t.after(() => {
    pool.query = originalQuery;
  });

  const server = app.listen(0);
  t.after(() => server.close());
  const address = server.address();
  const response = await request(
    {
      host: '127.0.0.1',
      port: address.port,
      method: 'POST',
      path: '/sharing/item-id',
      headers: { authorization: `Bearer ${token}` }
    },
    {
      sharedWithEmail: ' Recipient@Example.com ',
      encryptedVaultKeyForSharedUser: '{"iv":[1],"wrappedKey":[2]}'
    }
  );

  assert.equal(response.statusCode, 201);
  assert.equal(response.body.share.id, 'share-id');
  assert.equal(response.body.recipient.publicKey, '{"kty":"EC"}');
});
