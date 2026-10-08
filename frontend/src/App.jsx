import React, { useState } from 'react';
import { deriveMasterKey, exportRawKey, generateSalt, splitMasterKey } from './crypto';
import './App.css';

const apiBaseUrl = import.meta.env.VITE_API_URL || '';

function bytesToBase64(bytes) {
  let binary = '';
  for (const byte of bytes) {
    binary += String.fromCharCode(byte);
  }
  return btoa(binary);
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

function App() {
  const [email, setEmail] = useState('');
  const [password, setPassword] = useState('');
  const [confirmation, setConfirmation] = useState('');
  const [status, setStatus] = useState({ type: '', message: '' });
  const [isSubmitting, setIsSubmitting] = useState(false);

  async function handleSubmit(event) {
    event.preventDefault();
    setStatus({ type: '', message: '' });

    if (password !== confirmation) {
      setStatus({ type: 'error', message: 'Les mots de passe ne correspondent pas.' });
      return;
    }

    setIsSubmitting(true);
    try {
      await registerUser(email.trim(), password);
      setPassword('');
      setConfirmation('');
      setStatus({ type: 'success', message: 'Compte créé. Vous pouvez maintenant vous connecter.' });
    } catch (error) {
      setStatus({ type: 'error', message: error.message });
    } finally {
      setIsSubmitting(false);
    }
  }

  return (
    <main className="auth-page">
      <section className="auth-panel" aria-labelledby="registration-title">
        <p className="eyebrow">SecureVault</p>
        <h1 id="registration-title">Créer votre coffre</h1>
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
            autoComplete="new-password"
            minLength="12"
            required
          />

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

          <button type="submit" disabled={isSubmitting}>
            {isSubmitting ? 'Création en cours...' : 'Créer mon compte'}
          </button>
        </form>

        {status.message && (
          <p className={`status ${status.type}`} role="status">{status.message}</p>
        )}
      </section>
    </main>
  );
}

export default App;
