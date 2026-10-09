import React, { useState } from 'react';
import {
  decryptEntry,
  deriveMasterKey,
  exportRawKey,
  encryptEntry,
  encryptPrivateKey,
  exportEcdhPrivateKey,
  exportEcdhPublicKey,
  generateEcdhKeyPair,
  generateSalt,
  generateVaultKey,
  splitMasterKey,
  unwrapKey,
  wrapKey
} from './crypto';
import './App.css';

const apiBaseUrl = import.meta.env.VITE_API_URL || '';
const recoveryWords = [
  'ambre', 'ancre', 'aurore', 'brume', 'chêne', 'cuivre', 'étoile', 'fjord',
  'lumière', 'mistral', 'nuage', 'olivier', 'plume', 'rivage', 'sauge', 'sillage'
];

function bytesToBase64(bytes) {
  let binary = '';
  for (const byte of bytes) {
    binary += String.fromCharCode(byte);
  }
  return btoa(binary);
}

function parseEncryptedField(value) {
  if (typeof value !== 'string') {
    return value;
  }

  try {
    return JSON.parse(value);
  } catch {
    return null;
  }
}

function generateRecoveryPhrase() {
  const randomBytes = crypto.getRandomValues(new Uint8Array(12));
  return Array.from(randomBytes, (byte) => recoveryWords[byte % recoveryWords.length]).join(' ');
}

async function registerUser(email, password) {
  const salt = await generateSalt();
  const masterKey = await deriveMasterKey(password, salt);
  const { authKey, localKey } = await splitMasterKey(masterKey, salt);
  const authHash = bytesToBase64(new Uint8Array(await exportRawKey(authKey)));
  const keyPair = await generateEcdhKeyPair();
  const publicKey = await exportEcdhPublicKey(keyPair.publicKey);
  const privateKey = await exportEcdhPrivateKey(keyPair.privateKey);
  const encryptedPrivateKey = await encryptPrivateKey(privateKey, localKey);

  const response = await fetch(`${apiBaseUrl}/auth/register`, {
    method: 'POST',
    headers: { 'Content-Type': 'application/json' },
    body: JSON.stringify({
      email,
      salt: bytesToBase64(salt),
      authHash,
      publicKey: JSON.stringify(publicKey)
    })
  });

  const result = await response.json();
  if (!response.ok) {
    throw new Error(result.error || 'Registration failed');
  }

  localStorage.setItem(
    `securevault_ecdh_private_key:${email}`,
    JSON.stringify(encryptedPrivateKey)
  );
  return result;
}

async function loginUser(email, password) {
  const saltResponse = await fetch(
    `${apiBaseUrl}/auth/salt/${encodeURIComponent(email)}`
  );
  const saltResult = await saltResponse.json();
  if (!saltResponse.ok) {
    throw new Error(saltResult.error || 'Unable to retrieve login salt');
  }

  const salt = Uint8Array.from(atob(saltResult.salt), (character) => character.charCodeAt(0));
  const masterKey = await deriveMasterKey(password, salt);
  const { authKey, localKey } = await splitMasterKey(masterKey, salt);
  const authHash = bytesToBase64(new Uint8Array(await exportRawKey(authKey)));
  const response = await fetch(`${apiBaseUrl}/auth/login`, {
    method: 'POST',
    headers: { 'Content-Type': 'application/json' },
    body: JSON.stringify({ email, authHash })
  });

  const result = await response.json();
  if (!response.ok) {
    throw new Error(result.error || 'Login failed');
  }

  return { token: result.token, localKey };
}

async function fetchVaultItems(token, localKey) {
  const response = await fetch(`${apiBaseUrl}/vault`, {
    headers: { Authorization: `Bearer ${token}` }
  });
  const result = await response.json();
  if (!response.ok) {
    throw new Error(result.error || 'Unable to load the vault');
  }

  return Promise.all(result.items.map(async (item) => {
    try {
      const wrappedKey = parseEncryptedField(item.vault_key_wrapped);
      const encryptedBlob = parseEncryptedField(item.encrypted_blob);
      const vaultKey = await unwrapKey(wrappedKey, localKey);
      const payload = await decryptEntry(encryptedBlob, vaultKey);
      return { ...item, payload, decryptError: false };
    } catch {
      return { ...item, payload: null, decryptError: true };
    }
  }));
}

async function saveVaultItem(token, payload, itemId) {
  const vaultKey = await generateVaultKey();
  const encryptedBlob = await encryptEntry(payload.data, vaultKey);
  const wrappedKey = await wrapKey(vaultKey, payload.localKey);
  const response = await fetch(`${apiBaseUrl}/vault${itemId ? `/${itemId}` : ''}`, {
    method: itemId ? 'PUT' : 'POST',
    headers: {
      'Content-Type': 'application/json',
      Authorization: `Bearer ${token}`
    },
    body: JSON.stringify({
      encryptedBlob: JSON.stringify(encryptedBlob),
      nonce: JSON.stringify(encryptedBlob.iv),
      tag: JSON.stringify(encryptedBlob.ciphertext.slice(-16)),
      vaultKeyWrapped: JSON.stringify(wrappedKey)
    })
  });
  const result = await response.json();
  if (!response.ok) {
    throw new Error(result.error || 'Unable to save the vault entry');
  }
  return result.item;
}

async function deleteVaultItem(token, itemId) {
  const response = await fetch(`${apiBaseUrl}/vault/${itemId}`, {
    method: 'DELETE',
    headers: { Authorization: `Bearer ${token}` }
  });

  if (!response.ok) {
    const result = await response.json();
    throw new Error(result.error || 'Unable to delete the vault entry');
  }
}

function EntryForm({ entry, isSaving, onCancel, onSave }) {
  const [form, setForm] = useState({
    title: entry?.payload?.title || '',
    username: entry?.payload?.username || '',
    password: entry?.payload?.password || '',
    notes: entry?.payload?.notes || ''
  });
  const [error, setError] = useState('');

  function updateField(event) {
    setForm((current) => ({ ...current, [event.target.name]: event.target.value }));
  }

  async function handleSubmit(event) {
    event.preventDefault();
    setError('');
    try {
      await onSave(form);
    } catch (saveError) {
      setError(saveError.message);
    }
  }

  return (
    <form className="entry-form" onSubmit={handleSubmit}>
      <h2>{entry ? 'Modifier une entrée' : 'Ajouter une entrée'}</h2>
      <label htmlFor="entry-title">Titre</label>
      <input id="entry-title" name="title" value={form.title} onChange={updateField} required />
      <label htmlFor="entry-username">Identifiant</label>
      <input id="entry-username" name="username" value={form.username} onChange={updateField} />
      <label htmlFor="entry-password">Mot de passe</label>
      <input id="entry-password" name="password" type="password" value={form.password} onChange={updateField} />
      <label htmlFor="entry-notes">Notes</label>
      <textarea id="entry-notes" name="notes" value={form.notes} onChange={updateField} rows="4" />
      {error && <p className="status error" role="alert">{error}</p>}
      <div className="entry-actions">
        <button type="submit" disabled={isSaving}>{isSaving ? 'Chiffrement...' : 'Enregistrer'}</button>
        <button type="button" className="secondary-button" onClick={onCancel} disabled={isSaving}>Annuler</button>
      </div>
    </form>
  );
}

function VaultView({ items, onLogout, onSave, onDelete, isSaving }) {
  const [editingItem, setEditingItem] = useState(false);
  const [deleteError, setDeleteError] = useState('');
  const [visibleCredentials, setVisibleCredentials] = useState({});

  function toggleCredentials(itemId) {
    setVisibleCredentials((current) => ({
      ...current,
      [itemId]: !current[itemId]
    }));
  }

  return (
    <main className="auth-page">
      <section className="auth-panel vault-panel" aria-labelledby="vault-title">
        <div className="vault-header">
          <div>
            <p className="eyebrow">SecureVault</p>
            <h1 id="vault-title">Votre coffre</h1>
          </div>
          <button type="button" className="logout-button" onClick={onLogout}>Se déconnecter</button>
        </div>
        <button type="button" className="new-entry-button" onClick={() => setEditingItem(null)}>
          + Nouvelle entrée
        </button>
        {deleteError && <p className="status error" role="alert">{deleteError}</p>}

        {editingItem !== false && (
          <EntryForm
            entry={editingItem}
            isSaving={isSaving}
            onCancel={() => setEditingItem(false)}
            onSave={async (data) => {
              await onSave(data, editingItem?.id);
              setEditingItem(false);
            }}
          />
        )}

        {items.length === 0 ? (
          <p className="empty-vault">Votre coffre est vide pour le moment.</p>
        ) : (
          <section className="vault-list" aria-label="Entrées du coffre">
            <h2>Entrées enregistrées</h2>
            {items.map((item) => (
              <article className="vault-item" key={item.id}>
                {item.decryptError ? (
                  <p className="status error">Cette entrée ne peut pas être déchiffrée avec cette clé.</p>
                ) : (
                  <>
                    <h3>{item.payload.title || 'Entrée sans titre'}</h3>
                    <dl>
                      <dt>Identifiant</dt>
                      <dd>
                        {visibleCredentials[item.id]
                          ? (item.payload.username || 'Non renseigné')
                          : '••••••••'}
                      </dd>
                      <dt>Mot de passe</dt>
                      <dd>
                        {visibleCredentials[item.id]
                          ? (item.payload.password || 'Non renseigné')
                          : '••••••••'}
                      </dd>
                    </dl>
                    {item.payload.notes && <p>{item.payload.notes}</p>}
                    <button
                      type="button"
                      className="secondary-button credentials-button"
                      onClick={() => toggleCredentials(item.id)}
                    >
                      {visibleCredentials[item.id] ? 'Masquer les identifiants' : 'Afficher les identifiants'}
                    </button>
                  </>
                )}
                {!item.decryptError && (
                  <button type="button" className="secondary-button" onClick={() => setEditingItem(item)}>
                    Modifier
                  </button>
                )}
                <button
                  type="button"
                  className="delete-button"
                  onClick={async () => {
                    if (!window.confirm('Supprimer définitivement cette entrée ?')) {
                      return;
                    }
                    setDeleteError('');
                    try {
                      await onDelete(item.id);
                    } catch (error) {
                      setDeleteError(error.message);
                    }
                  }}
                  disabled={isSaving}
                >
                  Supprimer
                </button>
              </article>
            ))}
          </section>
        )}
      </section>
    </main>
  );
}

function App() {
  const [mode, setMode] = useState('register');
  const [email, setEmail] = useState('');
  const [password, setPassword] = useState('');
  const [confirmation, setConfirmation] = useState('');
  const [recoveryPhrase, setRecoveryPhrase] = useState('');
  const [vaultItems, setVaultItems] = useState([]);
  const [isAuthenticated, setIsAuthenticated] = useState(false);
  const [session, setSession] = useState(null);
  const [status, setStatus] = useState({ type: '', message: '' });
  const [isSubmitting, setIsSubmitting] = useState(false);

  async function handleSubmit(event) {
    event.preventDefault();
    setStatus({ type: '', message: '' });

    if (mode === 'register' && password !== confirmation) {
      setStatus({ type: 'error', message: 'Les mots de passe ne correspondent pas.' });
      return;
    }

    setIsSubmitting(true);
    try {
      const normalizedEmail = email.trim();
      if (mode === 'register') {
        await registerUser(normalizedEmail, password);
        setRecoveryPhrase(generateRecoveryPhrase());
        setStatus({ type: 'success', message: 'Compte créé. Notez votre phrase de récupération avant de continuer.' });
      } else {
        const { token, localKey } = await loginUser(normalizedEmail, password);
        localStorage.setItem('securevault_token', token);
        setVaultItems(await fetchVaultItems(token, localKey));
        setSession({ token, localKey });
        setIsAuthenticated(true);
        setStatus({ type: 'success', message: 'Connexion réussie.' });
      }
      setPassword('');
      setConfirmation('');
    } catch (error) {
      setStatus({ type: 'error', message: error.message });
    } finally {
      setIsSubmitting(false);
    }
  }

  if (isAuthenticated) {
    return (
      <VaultView
        items={vaultItems}
        isSaving={isSubmitting}
        onSave={async (data, itemId) => {
          setIsSubmitting(true);
          try {
            const item = await saveVaultItem(
              session.token,
              { data, localKey: session.localKey },
              itemId
            );
            const refreshedItems = await fetchVaultItems(session.token, session.localKey);
            setVaultItems(refreshedItems.map((current) => (
              current.id === item.id ? { ...current, payload: data, decryptError: false } : current
            )));
          } finally {
            setIsSubmitting(false);
          }
        }}
        onDelete={async (itemId) => {
          setIsSubmitting(true);
          try {
            await deleteVaultItem(session.token, itemId);
            setVaultItems((current) => current.filter((item) => item.id !== itemId));
          } finally {
            setIsSubmitting(false);
          }
        }}
        onLogout={() => {
          localStorage.removeItem('securevault_token');
          setVaultItems([]);
          setSession(null);
          setIsAuthenticated(false);
          setMode('login');
        }}
      />
    );
  }

  return (
    <main className="auth-page">
      <section className="auth-panel" aria-labelledby="auth-title">
        <p className="eyebrow">SecureVault</p>
        <div className="mode-switch" role="tablist" aria-label="Mode d'authentification">
          <button
            type="button"
            className={mode === 'register' ? 'mode-button active' : 'mode-button'}
            onClick={() => { setMode('register'); setRecoveryPhrase(''); setStatus({ type: '', message: '' }); }}
            role="tab"
            aria-selected={mode === 'register'}
          >
            Inscription
          </button>
          <button
            type="button"
            className={mode === 'login' ? 'mode-button active' : 'mode-button'}
            onClick={() => { setMode('login'); setRecoveryPhrase(''); setStatus({ type: '', message: '' }); }}
            role="tab"
            aria-selected={mode === 'login'}
          >
            Connexion
          </button>
        </div>
        <h1 id="auth-title">{mode === 'register' ? 'Créer votre coffre' : 'Retrouver votre coffre'}</h1>
        <p className="intro">
          Votre mot de passe maître reste dans votre navigateur et ne quitte jamais votre appareil.
        </p>

        <form onSubmit={handleSubmit}>
          <label htmlFor="email">Adresse e-mail</label>
          <input
            id="email"
            type="email"
            value={email}
            onChange={(event) => setEmail(event.target.value)}
            autoComplete="email"
            required
          />

          <label htmlFor="password">Mot de passe maître</label>
          <input
            id="password"
            type="password"
            value={password}
            onChange={(event) => setPassword(event.target.value)}
            autoComplete={mode === 'register' ? 'new-password' : 'current-password'}
            minLength="12"
            required
          />

          {mode === 'register' && (
            <>
              <label htmlFor="confirmation">Confirmer le mot de passe</label>
              <input
                id="confirmation"
                type="password"
                value={confirmation}
                onChange={(event) => setConfirmation(event.target.value)}
                autoComplete="new-password"
                minLength="12"
                required
              />
            </>
          )}

          <button type="submit" disabled={isSubmitting}>
            {isSubmitting
              ? (mode === 'register' ? 'Création en cours...' : 'Connexion en cours...')
              : (mode === 'register' ? 'Créer mon compte' : 'Me connecter')}
          </button>
        </form>

        {recoveryPhrase && (
          <aside className="recovery-box" aria-live="polite">
            <strong>Phrase de récupération</strong>
            <p>{recoveryPhrase}</p>
            <small>Elle ne sera plus affichée après avoir changé de mode ou rechargé la page.</small>
          </aside>
        )}

        {status.message && (
          <p className={`status ${status.type}`} role="status">{status.message}</p>
        )}
      </section>
    </main>
  );
}

export default App;
