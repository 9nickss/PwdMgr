-- SecureVault database schema

-- Enable uuid extension
CREATE EXTENSION IF NOT EXISTS "uuid-ossp";

-- Users table
CREATE TABLE users (
    id UUID PRIMARY KEY DEFAULT uuid_generate_v4(),
    email TEXT UNIQUE NOT NULL,
    auth_hash TEXT NOT NULL,          -- hash of auth key (for verification)
    salt TEXT NOT NULL,               -- salt for auth hash
    public_key TEXT,                  -- ECDH public key (base64)
    created_at TIMESTAMP WITH TIME ZONE DEFAULT NOW()
);

-- Vault items table (encrypted blobs)
CREATE TABLE vault_items (
    id UUID PRIMARY KEY DEFAULT uuid_generate_v4(),
    user_id UUID NOT NULL REFERENCES users(id) ON DELETE CASCADE,
    encrypted_blob TEXT NOT NULL,     -- AES-GCM ciphertext+tag (base64)
    nonce TEXT NOT NULL,              -- nonce for GCM (base64)
    tag TEXT NOT NULL,                -- authentication tag (base64)
    vault_key_wrapped TEXT NOT NULL,  -- encrypted vault key (with local key) base64
    created_at TIMESTAMP WITH TIME ZONE DEFAULT NOW(),
    updated_at TIMESTAMP WITH TIME ZONE DEFAULT NOW()
);

-- Shares table
CREATE TABLE shares (
    id UUID PRIMARY KEY DEFAULT uuid_generate_v4(),
    item_id UUID NOT NULL REFERENCES vault_items(id) ON DELETE CASCADE,
    shared_with_user_id UUID NOT NULL REFERENCES users(id) ON DELETE CASCADE,
    encrypted_vault_key_for_shared_user TEXT NOT NULL, -- vault key wrapped with shared user's public key via ECDH
    created_at TIMESTAMP WITH TIME ZONE DEFAULT NOW(),
    UNIQUE(item_id, shared_with_user_id)
);

-- Audit log table (metadata only)
CREATE TABLE audit_log (
    id UUID PRIMARY KEY DEFAULT uuid_generate_v4(),
    user_id UUID NOT NULL REFERENCES users(id) ON DELETE CASCADE,
    action TEXT NOT NULL,             -- e.g., 'login', 'create_item', 'share_item'
    details JSONB,                    -- arbitrary metadata (no plaintext secrets)
    timestamp TIMESTAMP WITH TIME ZONE DEFAULT NOW()
);

-- Indexes for performance
CREATE INDEX idx_vault_items_user_id ON vault_items(user_id);
CREATE INDEX idx_shares_item_id ON shares(item_id);
CREATE INDEX idx_shares_shared_with_user_id ON shares(shared_with_user_id);
CREATE INDEX idx_audit_log_user_id ON audit_log(user_id);
CREATE INDEX idx_audit_log_timestamp ON audit_log(timestamp);
