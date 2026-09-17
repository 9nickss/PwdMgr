# SecureVault — Backlog du projet

Projet Epitech *"Partage sécurisé de données sensibles"* — domaine choisi :
**gestionnaire de mots de passe zero-knowledge (familial/équipe)**.

## Consignes du brief (Epitech — Partage sécurisé de données sensibles)

**Le problème.** Beaucoup d'applications qui manipulent des données
sensibles (mots de passe, documents confidentiels, notes privées) se
contentent de chiffrer la base côté serveur, ce qui protège contre un vol de
disque mais pas contre un hébergeur malveillant ou compromis qui a accès à
la clé. L'objectif est que les données ne soient **jamais lisibles en clair
côté serveur**, y compris par l'administrateur de la plateforme, tout en
restant partageables entre plusieurs utilisateurs et récupérables en cas de
mot de passe oublié.

**Tension technique centrale.** Chiffrement de bout en bout, gestion des
clés côté client, partage sécurisé sans exposer la clé au serveur,
récupération de compte sans backdoor.

**Domaines possibles (au choix de l'étudiant) :**
- Gestionnaire de mots de passe familial ou d'équipe *(domaine retenu ici)*
- Partage de documents confidentiels entre associés d'une entreprise
- Coffre-fort numérique de codes d'accès entre techniciens d'une structure
- Messagerie chiffrée pour une petite organisation

**Produits réels illustrant le concept.** Bitwarden (zero-knowledge),
1Password (partage sécurisé de coffres en équipe), ProtonMail (messagerie
chiffrée de bout en bout).

**Fonctionnalités attendues — socle minimal :**
- Création de compte avec dérivation de clé à partir du mot de passe maître
  (jamais stocké en clair, jamais transmis au serveur)
- Chiffrement des données côté client avant tout envoi au serveur,
  déchiffrement côté client à la réception
- Partage d'un élément avec un autre utilisateur sans que le serveur puisse
  à aucun moment lire la donnée en clair
- Gestion basique de plusieurs comptes et de leurs accès respectifs

**Pousser à fond (bonus) :** vrai partage par chiffrement asymétrique
(chaque utilisateur a une paire de clés, la donnée partagée est re-chiffrée
avec la clé publique du destinataire), révocation d'accès après un partage,
rotation de clé, journal d'audit des accès.

**Pistes techniques pour démarrer :** chiffrement symétrique AES-256,
dérivation de clé (PBKDF2 ou Argon2), chiffrement asymétrique RSA ou ECC,
modèle « zero-knowledge ». Outils suggérés : Web Crypto API (navigateur),
libsodium, module `crypto` de Node.js.

Stack : **React (Vite) + Node/Express + PostgreSQL**, chiffrement 100% côté
client via Web Crypto API (le serveur ne stocke/voit jamais de donnée en
clair).

Budget total estimé : **~5 jours-homme (1 semaine)**.

---

## Issue 1 — Setup repo (0.5 j)

Poser les fondations du repo pour pouvoir développer dessus dès la 2ᵉ issue.

- [ ] **1.1** Structure du repo (`backend/`, `frontend/`, `docs/`) + `.gitignore` + `README.md`
- [ ] **1.2** `docker-compose.yml` Postgres local + schéma SQL (`users`, `vault_items`, `shares`, `audit_log`)
- [ ] **1.3** CI GitHub Actions (lint/build sur push et PR)

---

## Issue 2 — Module crypto client (1 j)

Le cœur du projet : rien de tout ça ne doit dépendre du serveur.

- [ ] **2.1** Dérivation de clé depuis le mot de passe maître (PBKDF2, salt aléatoire, itérations élevées)
- [ ] **2.2** Split de la clé maîtresse en clé locale / clé d'auth (HKDF) — la clé d'auth part au serveur, jamais la clé locale
- [ ] **2.3** Génération + chiffrement AES-256-GCM d'une entrée (JSON → blob chiffré)
- [ ] **2.4** Chiffrement/déchiffrement de la Vault Key elle-même (wrap/unwrap avec la clé locale)
- [ ] **2.5** Tests unitaires sur des vecteurs connus (round-trip chiffrement/déchiffrement, tag d'intégrité)

---

## Issue 3 — Auth zero-knowledge (1 j)

Le serveur ne doit jamais voir le mot de passe maître, seulement une preuve dérivée.

- [ ] **3.1** API : `GET /auth/salt/:email` + `POST /auth/register` (stocke un hash d'auth, jamais le mot de passe)
- [ ] **3.2** API : `POST /auth/login` (vérification du hash + émission d'un JWT)
- [ ] **3.3** Front : page inscription (dérivation de clé + appel API)
- [ ] **3.4** Front : page connexion + stockage du JWT + affichage unique de la phrase de récupération à l'inscription

---

## Issue 4 — Coffre : CRUD des entrées (1 j)

- [ ] **4.1** API : routes CRUD `/vault` protégées par JWT, stockage de blobs chiffrés uniquement
- [ ] **4.2** Front : liste des entrées + déchiffrement à l'affichage
- [ ] **4.3** Front : formulaire ajout/édition d'une entrée (chiffrement avant envoi)
- [ ] **4.4** Front : suppression + confirmation

---

## Issue 5 — Partage entre utilisateurs (1 j)

- [ ] **5.1** Génération de la paire de clés ECDH à l'inscription + stockage de la clé publique côté serveur
- [ ] **5.2** Fonctions crypto : dérivation du secret partagé (ECDH) + wrap/unwrap d'une clé d'entrée
- [ ] **5.3** API : `POST /sharing/:itemId`, `GET /sharing/with-me`, `DELETE /sharing/:itemId/:userId`
- [ ] **5.4** Front : modal "partager avec" + liste des entrées partagées avec moi

---

## Issue 6 — Tests, doc, démo (0.5 j)

- [ ] **6.1** Vérification manuelle : dump direct de la DB → confirmer que rien n'est lisible
- [ ] **6.2** Complétion du README (setup, captures d'écran, choix techniques et pourquoi)
- [ ] **6.3** Script/scénario de démo pour la soutenance

---

## Backlog bonus (hors budget des 5 j, si le temps le permet)

- [ ] Révocation d'un partage + rotation de la clé d'une entrée
- [ ] Journal d'audit des accès (métadonnées seulement, jamais le contenu)
- [ ] Changement de mot de passe maître sans re-chiffrer tout le coffre
- [ ] 2FA (TOTP) en plus de l'auth hash
- [ ] Vérification de mots de passe compromis façon k-anonymity (type Have I Been Pwned)

---

## Modèle de sécurité (rappel pour Claude Code)

- Le **mot de passe maître** ne quitte jamais le navigateur.
- Il sert à dériver une **clé locale** (ne sert qu'à chiffrer/déchiffrer la
  Vault Key) et un **auth key** distinct (envoyé au serveur, jamais
  réutilisable pour déchiffrer quoi que ce soit).
- La **Vault Key** (clé symétrique aléatoire, pas dérivée du mot de passe)
  chiffre réellement les entrées du coffre — ça permet de changer le mot de
  passe maître sans tout re-chiffrer.
- Le **partage** passe par ECDH : chaque utilisateur a une paire de clés, et
  partager une entrée = re-chiffrer sa clé avec un secret dérivé de
  (ma clé privée, la clé publique du destinataire). Le serveur relaie sans
  jamais pouvoir lire.
- Le serveur ne stocke/voit **jamais** : le mot de passe maître, la Vault
  Key en clair, le contenu en clair d'une entrée, ou une clé privée en clair.
