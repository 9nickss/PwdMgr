# Schéma de la base de données SecureVault

## Tables

### users
| Colonne | Type | Description |
|---------|------|-------------|
| id | UUID | Identifiant unique de l'utilisateur |
| email | TEXT | Adresse e‑mail de l'utilisateur (unique) |
| auth_hash | TEXT | Hash de la clé d'authentification (dérivée du mot‑de‑passe maître + salt) |
| salt | TEXT | Salt aléatoire utilisé pour le hash d'authentification |
| public_key | TEXT | Clé publique ECDH de l'utilisateur (base64) |
| created_at | TIMESTAMPTZ | Date/heure de création du compte

### vault_items
| Colonne | Type | Description |
|---------|------|-------------|
| id | UUID | Identifiant unique de l'élément du coffre |
| user_id | UUID | Référence à l'utilisateur propriétaire |
| encrypted_blob | TEXT | Contenu chiffré de l'élément (AES‑256‑GCM, base64) |
| nonce | TEXT | Nonce/vecteur d'initialisation pour GCM (base64) |
| tag | TEXT | Tag d'authentification GCM (base64) |
| vault_key_wrapped | TEXT | Vault Key enveloppée avec la clé locale de l'utilisateur (base64) |
| created_at | TIMESTAMPTZ | Date/heure de création |
| updated_at | TIMESTAMPTZ | Date/heure de dernière mise à jour

### shares
| Colonne | Type | Description |
|---------|------|-------------|
| id | UUID | Identifiant unique du partage |
| item_id | UUID | Référence à l'élément du coffre partagé |
| shared_with_user_id | UUID | Référence à l'utilisateur destinataire |
| encrypted_vault_key_for_shared_user | TEXT | Vault Key enveloppée avec la clé publique du destinataire (via ECDH, base64) |
| created_at | TIMESTAMPTZ | Date/heure du partage

### audit_log
| Colonne | Type | Description |
|---------|------|-------------|
| id | UUID | Identifiant unique de l'entrée de journal |
| user_id | UUID | Référence à l'utilisateur ayant déclenché l'action |
| action | TEXT | Type d'action (login, create_item, share_item, etc.) |
| details | JSONB | Métadonnées supplémentaires (IP, user‑agent, etc.) – aucun secret |
| timestamp | TIMESTAMPTZ | Date/heure de l'action
