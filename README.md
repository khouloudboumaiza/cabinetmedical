# Système sécurisé d'authentification et de cryptographie

Application Flask de démonstration mettant en pratique :
- l'authentification (inscription, connexion, sessions sécurisées)
- l'autorisation côté serveur (RBAC : rôles `user` / `admin`)
- la cryptographie (hachage bcrypt, HMAC, AES-256-GCM)
- la connexion via **Google (OAuth2 / OpenID Connect)**
- la **détection automatique d'anomalies de connexion** (nouveau pays,
  brute-force, heure inhabituelle) avec dashboard d'alertes pour l'admin

---

## 1. Structure du projet

```
projet2_app/
├── app.py              # Point d'entrée, création de l'application
├── config.py            # Configuration (variables d'environnement)
├── models.py             # Modèles SQLAlchemy : User, LoginLog, SecurityAlert
├── auth.py               # Inscription / connexion / déconnexion classique
├── oauth.py               # Connexion Google (OAuth2)
├── detection.py            # Règles de détection d'anomalies
├── decorators.py            # Décorateurs RBAC (admin_required, etc.)
├── admin.py                  # Dashboard admin (alertes, logs, utilisateurs)
├── crypto_utils.py            # HMAC, AES-256-GCM
├── requirements.txt
├── .env.example
├── templates/                  # Pages HTML (Jinja2)
├── static/style.css
└── tests/test_security.py       # Cas de tests de sécurité (pytest)
```

---

## 2. Installation

### Prérequis
- Python 3.9 ou supérieur

### Étapes

```bash
# 1. Se placer dans le dossier du projet
cd projet2_app

# 2. Créer et activer un environnement virtuel
python3 -m venv venv
source venv/bin/activate        # Linux / macOS
venv\Scripts\activate           # Windows

# 3. Installer les dépendances
pip install -r requirements.txt

# 4. Copier le fichier d'environnement et le remplir
cp .env.example .env
```

Ouvrir `.env` et au minimum définir `SECRET_KEY` et `HMAC_SECRET` :

```bash
python -c "import secrets; print(secrets.token_hex(32))"
```
Copier la valeur générée dans `SECRET_KEY`, refaire une fois pour `HMAC_SECRET`.

---

## 3. Lancer l'application

```bash
python app.py
```

L'application est accessible sur **http://localhost:5000**

Au premier lancement, un compte administrateur est créé automatiquement.
Ses identifiants (email + mot de passe généré aléatoirement) s'affichent
dans la console :

```
============================================================
 Compte administrateur créé automatiquement :
   Email    : admin@example.com
   Password : xxxxxxxxxxxxx
============================================================
```

Notez ce mot de passe, il ne sera affiché qu'une seule fois.

---

## 4. Configurer la connexion Google (OAuth2)

Sans cette étape, l'application fonctionne normalement en mode classique
(email/mot de passe) — seul le bouton « Continuer avec Google » affichera
un message d'erreur.

1. Aller sur [console.cloud.google.com](https://console.cloud.google.com)
2. Créer un nouveau projet
3. Menu **APIs & Services → Credentials → Create Credentials → OAuth Client ID**
4. Type d'application : **Web application**
5. Dans **Authorized redirect URIs**, ajouter :
   ```
   http://localhost:5000/auth/google/callback
   ```
6. Copier le **Client ID** et le **Client Secret** générés
7. Les coller dans le fichier `.env` :
   ```
   GOOGLE_CLIENT_ID=xxxxxxxx.apps.googleusercontent.com
   GOOGLE_CLIENT_SECRET=xxxxxxxx
   ```
8. Redémarrer l'application

---

## 5. Utilisation

| Route | Description |
|---|---|
| `/` | Page d'accueil |
| `/register` | Créer un compte (email/mot de passe) |
| `/login` | Connexion classique |
| `/auth/google/login` | Connexion via Google |
| `/dashboard` | Espace utilisateur (historique de connexions) |
| `/admin/alerts` | Dashboard des alertes de sécurité (admin uniquement) |
| `/admin/logs` | Historique complet des connexions (admin uniquement) |
| `/admin/users` | Liste des utilisateurs (admin uniquement) |

---

## 6. Détection d'anomalies — comment la tester

### a) Nouveau pays
La détection ne se déclenche qu'après un historique existant (au moins une
connexion réussie enregistrée avec un pays connu). En local, les connexions
sont classées "Local" et ignorées par cette règle — pour la tester, il faut
simuler une IP externe ou déployer l'app avec une vraie IP publique.

### b) Brute-force

```bash
# Envoyer 6 tentatives de connexion échouées rapidement
for i in {1..6}; do
  curl -s -X POST http://localhost:5000/login \
    -d "email=admin@example.com&password=mauvais_mdp" -o /dev/null -w "%{http_code}\n"
done
```
La 6e requête doit renvoyer un code **429** (trop de tentatives), et une
alerte `brute_force` doit apparaître dans `/admin/alerts`.

### c) Heure inhabituelle
Se déclenche automatiquement quand un utilisateur ayant un historique de
connexions se connecte à une heure très différente de ses habitudes
(nécessite au moins 5 connexions réussies enregistrées).

---

## 7. Lancer les tests de sécurité

```bash
pip install pytest   # si pas déjà installé via requirements.txt
pytest tests/ -v
```

Les tests couvrent :
- rejet des mots de passe faibles
- hachage effectif des mots de passe (jamais stockés en clair)
- résistance à l'injection SQL (grâce à l'ORM SQLAlchemy)
- messages d'erreur génériques (pas d'énumération de comptes)
- contrôle d'accès RBAC (routes admin inaccessibles aux users normaux)
- blocage après tentatives de brute-force répétées
- intégrité des tokens HMAC (détection de falsification et d'expiration)

---

## 8. Vérifier soi-même les vulnérabilités avec Burp Suite

1. Configurer le navigateur pour utiliser Burp comme proxy (127.0.0.1:8080)
2. Naviguer sur l'application et intercepter les requêtes
3. Tests recommandés :
   - **SQL Injection** : essayer `' OR '1'='1` dans le champ email du login
   - **IDOR** : si une route `/user/<id>` existe, changer l'ID dans l'URL
     avec un autre compte connecté
   - **Session fixation** : vérifier que l'ID de session change après login
   - **Brute-force** : répéter des tentatives de connexion échouées

---

## 9. Rappels de sécurité appliqués dans ce projet

- Mots de passe hachés avec **bcrypt** (jamais en clair, jamais MD5/SHA1 seul)
- Comparaison de mot de passe en temps constant (bcrypt) pour éviter les
  attaques par timing
- Autorisation vérifiée **côté serveur uniquement** (`@admin_required`)
- Cookies de session `HttpOnly`, `SameSite=Lax` (`Secure` en production)
- Tokens sensibles signés avec **HMAC-SHA256** (intégrité + expiration)
- Chiffrement disponible via **AES-256-GCM** (`crypto_utils.py`)
- Détection d'anomalies de connexion avec alertes consultables par un admin
- Requêtes base de données exclusivement via l'ORM (SQLAlchemy) → pas de
  concaténation de chaînes SQL, donc pas d'injection SQL classique

---

## 10. Prochaines améliorations possibles

- 2FA / TOTP (Google Authenticator)
- Vérification "Have I Been Pwned" à l'inscription
- Envoi réel des alertes par email (voir `ALERTS_BY_EMAIL` dans `.env`)
- Rate limiting global avec Flask-Limiter
- Passage à PostgreSQL/MySQL en production

---

## 11. Protection anti-falsification des logs (anti-forensics)

**Problème** : si un attaquant compromet l'application ou obtient un accès
direct à la base de données, il peut modifier ou supprimer les entrées de
`login_logs` pour effacer ses traces. Trois mécanismes ont été ajoutés
pour s'en prémunir.

### a) Chaînage cryptographique (`log_integrity.py`)
Chaque entrée de log stocke `prev_hash` (le hash de l'entrée précédente)
et `entry_hash` = `HMAC-SHA256(HMAC_SECRET, prev_hash + données)`.
C'est le même principe qu'une blockchain : modifier ou supprimer UNE
seule ligne casse la chaîne à cet endroit, et c'est détectable.

**Vérifier l'intégrité** : se connecter en tant qu'admin puis aller sur
`/admin/logs/verify` (ou lien "🔍 Vérifier intégrité" dans le menu).

### b) Triggers SQLite append-only (`app.py`)
Des triggers `BEFORE UPDATE` / `BEFORE DELETE` empêchent toute
modification ou suppression de `login_logs`, même via un accès SQL
direct (`sqlite3 app.db`) ou une requête injectée. Seul l'`INSERT` reste
possible.

### c) Tester la protection soi-même

```bash
# Tenter de supprimer les logs directement en base -> doit échouer
sqlite3 app.db "DELETE FROM login_logs;"
# -> Error: login_logs est en lecture seule (append-only)
```

```bash
pytest tests/test_security.py -k tamper -v
# vérifie que toute falsification est détectée par la chaîne de hash
# et que le DELETE direct est bloqué par les triggers
```

### Limite honnête (à mentionner dans ton rapport)
Si l'attaquant vole aussi `HMAC_SECRET` (stocké dans `.env`), il peut en
théorie recalculer une chaîne cohérente après modification. C'est
pourquoi en environnement réel, on combine toujours ceci avec :
- **`HMAC_SECRET` stocké séparément** de la base (ex: un coffre-fort de
  secrets / variable d'environnement injectée au runtime, jamais dans
  les sauvegardes de la BDD)
- **Envoi des logs en temps réel vers un stockage externe** en écriture
  seule (syslog distant, SIEM, bucket WORM) — même si l'attaquant
  contrôle totalement le serveur applicatif après coup, il ne peut pas
  revenir modifier ce qui a déjà été envoyé ailleurs
- Des **permissions filesystem restrictives** sur le fichier `app.db`
  (l'utilisateur qui exécute l'app ne devrait pas pouvoir écrire
  arbitrairement en dehors de l'application elle-même)

Documenter cette limite honnêtement dans ton rapport (plutôt que de
prétendre que c'est "impossible à contourner") montre une vraie maturité
en sécurité — aucun mécanisme n'est invulnérable, ce qui compte c'est de
savoir lequel choisir et pourquoi, et quelles hypothèses il repose sur.

---

## 12. Messagerie sécurisée Patient ↔ Médecin

Le module de messagerie permet des échanges médicaux sécurisés et chiffrés de bout en bout entre un patient et ses médecins autorisés.

### a) Routes de la messagerie

| Méthode | Route | Description | Autorisation |
|---|---|---|---|
| `GET` | `/messages` | Liste des conversations actives et contacts éligibles avec compteur de non-lus | Patient ou Médecin |
| `GET` | `/messages/<id>` | Affichage de la conversation, déchiffrement à la volée et marquage de lecture | Membre de la conversation uniquement (Patient ou Médecin lié) |
| `POST` | `/messages/<id>/send` | Envoi d'un message chiffré AES-256-GCM avec AAD (`conversation_id`) | Membre de la conversation |
| `GET` | `/messages/<id>/poll?after=<id>` | Polling AJAX (toutes les 5 s) des nouveaux messages | Membre de la conversation |
| `POST` | `/messages/new` | Démarrage d'une conversation après vérification de la relation médicale | Patient vers médecin avec relation OU Médecin vers patient avec compte |

### b) Sécurité et défense en profondeur

1. **Chiffrement AES-256-GCM avec AAD** :
   - Clé AES-256 (32 octets) partagée avec les dossiers médicaux (`ENCRYPTION_KEY`).
   - Tirage d'un `nonce` cryptographique aléatoire et unique de 12 octets par message (`os.urandom(12)`).
   - Intégration de l'identifiant `conversation_id` comme Données Associées Authentifiées (**AAD**) : empêche toute tentative de déplacer ou rejouer un message chiffré d'une conversation à une autre.
   - Aucun texte en clair n'est stocké en base de données.

2. **Contrôle d'accès strict & Anti-IDOR (404 systématique)** :
   - Les rôles `admin` et `secretaire` sont **strictement exclus** de la messagerie : toute tentative renvoie une `404 Not Found` (avec journalisation d'audit).
   - Un patient ou un médecin ne peut accéder qu'aux conversations dont il est directement membre.
   - Toute tentative d'accès non autorisé par un identifiant d'URL manipulé (IDOR) renvoie une `404 Not Found` et génère automatiquement une `SecurityAlert` (type `idor_message_attempt`) via `detection.py`.

3. **Protection CSRF (Formulaires et API Fetch)** :
   - Validation stricte du token CSRF en temps constant (`hmac.compare_digest`) sur toutes les requêtes `POST`.
   - Prise en charge des requêtes asynchrones `fetch` via l'en-tête `X-CSRFToken`.

4. **Rate Limiting** :
   - Limitation à l'envoi de **20 messages par minute par utilisateur** pour prévenir les attaques par déni de service ou saturation.

5. **Validation & Protection Anti-XSS** :
   - Nettoyage des chaînes (`strip`), rejet des messages vides ou excédant 2000 caractères.
   - Échappement HTML automatique dans Jinja2 (aucun filtre `|safe`).
   - Insertion côté client JavaScript via `textContent` exclusivement (jamais `innerHTML`).

6. **Journalisation d'audit intègre (Log Integrity)** :
   - Enregistrement des événements (ouverture de conversation, envoi de message, accès refusé) dans `message_logs`.
   - Chaînage HMAC-SHA256 anti-falsification et triggers SQLite append-only.
   - **Le contenu des messages n'est JAMAIS consigné dans les logs.**

### c) Limite connue sur la clé de chiffrement

- **Architecture actuelle (Chiffrement côté serveur / Symétrique)** :
  La clé AES-256 est gérée au niveau du serveur (`secret_aes.key` ou variable `ENCRYPTION_KEY_HEX`).
  - *Avantage* : Simple à maintenir, performant, permet aux patients et médecins d'accéder à leurs échanges depuis n'importe quel appareil sans gestion de trousseau complexe côté client.
  - *Limite connue* : Un administrateur système disposant d'un accès root direct au serveur et à la mémoire du processus pourrait potentiellement extraire la clé symétrique et déchiffrer les messages.
  - *Recommandation pour un déploiement hospitalier/HDS de grande échelle* : Évolution vers un chiffrement asymétrique de bout en bout (E2EE) avec paires de clés publiques/privées (ex: X25519 / Signal Protocol) générées et conservées exclusivement dans le navigateur/terminal des utilisateurs, ou intégration d'un module HSM / KMS pour la dérivation des clés.

