import React, { useState } from 'react';
import { deriveMasterKey, exportRawKey, generateSalt, splitMasterKey } from './crypto';
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

function generateRecoveryPhrase() {
  const randomBytes = crypto.getRandomValues(new Uint8Array(12));
  return Array.from(randomBytes, (byte) => recoveryWords[byte % recoveryWords.length]).join(' ');
}

async function registerUser(email, password) {
  const salt = await generateSalt();
  const masterKey = await deriveMasterKey(password, salt);
  const { authKey } = await splitMasterKey(masterKey, salt);
  const authHash = bytesToBase64(new Uint8Array(await exportRawKey(authKey)));

  const response = await fetch(`${apiBaseUrl}/auth/register`, {
    method: 'POST',
    headers: { 'Content-Type': 'application/json' },
    body: JSON.stringify({
      email,
      salt: bytesToBase64(salt),
      authHash
    })
  });

  const result = await response.json();
  if (!response.ok) {
    throw new Error(result.error || 'Registration failed');
  }

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
  const { authKey } = await splitMasterKey(masterKey, salt);
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

  return result.token;
}

function App() {
  const [mode, setMode] = useState('register');
  const [email, setEmail] = useState('');
  const [password, setPassword] = useState('');
  const [confirmation, setConfirmation] = useState('');
  const [recoveryPhrase, setRecoveryPhrase] = useState('');
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
        const token = await loginUser(normalizedEmail, password);
        localStorage.setItem('securevault_token', token);
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
