# SecureVault

Gestionnaire de mots de passe zero-knowledge realise avec React, Node.js et
PostgreSQL. Le mot de passe maitre ne quitte jamais le navigateur. Le serveur
stocke uniquement des preuves d'authentification, des blobs chiffres et des
cles enveloppees.

## Fonctionnalites

- Inscription et connexion sans envoyer le mot de passe maitre.
- Derivation PBKDF2 puis separation HKDF en cle locale et cle d'authentification.
- Chiffrement des entrees avec AES-256-GCM avant envoi au serveur.
- CRUD des entrees du coffre avec JWT.
- Masquage des identifiants et mots de passe dans l'interface.
- Partage d'une entree avec ECDH P-256 et enveloppement de sa Vault Key.
- Liste des entrees partagees et revocation d'un partage.
- Tests unitaires des primitives cryptographiques et tests backend de l'API.

## Architecture

```text
Navigateur React/Vite
   | Web Crypto API: PBKDF2, HKDF, AES-GCM, ECDH
   | HTTP + JWT
Backend Node/Express
   | validation JWT, droits d'acces, stockage de blobs
PostgreSQL
```

Le frontend chiffre et dechiffre. Le backend ne recoit jamais une entree en
clair et ne possede pas les cles privees ECDH.

## Demarrage recommande

Prerequis: Node.js 20+, npm et Docker Compose.

### 1. Demarrer PostgreSQL

Depuis la racine du projet:

```bash
sudo docker compose up -d
sudo docker compose ps
```

Le schema est initialise depuis `backend/init/schema.sql` lors de la creation
du volume PostgreSQL.

### 2. Installer les dependances

```bash
cd backend && npm install
cd ../frontend && npm install
```

### 3. Lancer le backend et le frontend

Dans un terminal:

```bash
cd backend
npm run dev
```

Le backend ecoute sur `http://localhost:3000`.

Dans un second terminal:

```bash
cd frontend
npm run dev
```

L'interface est disponible sur `http://localhost:5173`.

## Variables d'environnement backend

Les valeurs par defaut correspondent au Compose:

| Variable | Valeur par defaut |
|---|---|
| `PORT` | `3000` |
| `PGHOST` | `localhost` |
| `PGPORT` | `5432` |
| `PGUSER` | `securevault` |
| `PGPASSWORD` | `securevault_pass` |
| `PGDATABASE` | `securevault` |
| `JWT_SECRET` | secret de developpement, a remplacer en production |

## Modele cryptographique

### Authentification

1. Le navigateur genere un salt aleatoire.
2. PBKDF2/SHA-256 derive une master key a partir du mot de passe maitre.
3. HKDF produit deux cles independantes:
    - `localKey`: ne quitte pas le navigateur et protege les Vault Keys;
    - `authKey`: preuve envoyee au serveur, jamais utilisee pour dechiffrer.
4. Le backend hash l'`authKey` avec scrypt et emet un JWT apres verification.

### Coffre

Chaque entree est transformee en JSON puis chiffree avec une Vault Key aleatoire
et AES-256-GCM. La Vault Key est elle-meme enveloppee avec `localKey`.
Le serveur stocke donc le blob, l'IV/tag et la Vault Key enveloppee, mais ne
peut pas afficher le contenu.

### Partage

Chaque compte possede une paire ECDH P-256. La cle publique est stockee dans
PostgreSQL; la cle privee est chiffree localement avec `localKey`.

Pour partager une entree, le navigateur derive un secret commun avec ECDH,
le transforme en cle AES-GCM via HKDF, puis enveloppe la Vault Key avec cette
cle. Le backend ne fait que relayer et stocker ce paquet.

## API principale

Toutes les routes protegees attendent:

```http
Authorization: Bearer <jwt>
```

### Authentification

- `GET /auth/salt/:email`
- `GET /auth/public-key/:email`
- `POST /auth/register`
- `POST /auth/login`

### Coffre

- `GET /vault`
- `GET /vault/:id`
- `POST /vault`
- `PUT /vault/:id`
- `DELETE /vault/:id`

### Partage

- `POST /sharing/:itemId`
- `GET /sharing/with-me`
- `GET /sharing/by-me`
- `DELETE /sharing/:itemId/:userId`

## Emplacement du code

| Fonctionnalite | Fichier |
|---|---|
| PBKDF2, HKDF, AES-GCM et ECDH | `frontend/src/crypto.js` |
| Interface inscription, connexion et coffre | `frontend/src/App.jsx` |
| Styles de l'interface | `frontend/src/App.css` |
| API, JWT, droits et PostgreSQL | `backend/server.js` |
| Schema des tables | `backend/init/schema.sql` |
| Tests crypto | `frontend/src/crypto.test.js` |
| Tests API | `backend/server.test.js` |
| Configuration Docker PostgreSQL | `docker-compose.yml` |
| Fiche de soutenance | `docs/defense.md` |

## Tests et validation

Frontend:

```bash
cd frontend
npm test
npm run build
npm run lint
```

Backend:

```bash
cd backend
npm test
npm run lint
```

## Base de donnees

Le schema contient les tables `users`, `vault_items`, `shares` et `audit_log`.
Les colonnes sensibles de `vault_items` et `shares` contiennent uniquement des
valeurs chiffrees ou des metadonnees necessaires au routage.

Pour reinitialiser la base de developpement et rejouer le schema, cela supprime
les donnees locales:

```bash
sudo docker compose down -v
sudo docker compose up -d
```

## Limites connues

- La phrase de recuperation est affichee a l'inscription, mais le mecanisme de
   recuperation complet n'est pas encore implemente.
- La cle privee ECDH est stockee chiffre dans le navigateur qui l'a generee;
   un autre appareil ne peut pas encore recuperer automatiquement cette cle.
- Le secret JWT par defaut est uniquement adapte au developpement.
- Le serveur stocke des blobs fournis par le client et ne peut pas prouver qu'un
   client malveillant a chiffre son contenu; le frontend officiel respecte ce
   contrat.

## Documentation complementaire

- [Schema PostgreSQL](docs/schema.md)
- [Fiche de defense](docs/defense.md)

## Licence

MIT
