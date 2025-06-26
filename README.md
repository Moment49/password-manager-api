# Password Manager API

A secure, extensible, and modern API for managing passwords and sensitive account data, built with Django, Django REST Framework, and JWT authentication. This project is designed to serve as the backend for a password manager application, with a strong focus on cryptographic best practices, user privacy, and extensibility for future features.

---

## Table of Contents

- [Features](#features)
- [Architecture Overview](#architecture-overview)
- [Security Model](#security-model)
- [API Endpoints](#api-endpoints)
- [Authentication & Authorization](#authentication--authorization)
- [Password Vault & Encryption](#password-vault--encryption)
- [Frontend Simulation](#frontend-simulation)
- [Project Structure](#project-structure)
- [Setup & Installation](#setup--installation)
- [Contributing](#contributing)
- [License](#license)

---

## Features

- **User Registration & JWT Authentication**
- **Master Password Vault**: Each user has a unique vault protected by a master password (never sent to the server).
- **Strong Cryptography**: Passwords are encrypted client-side using keys derived from the master password and a unique salt.
- **Password Generation**: Secure random password generation with customizable length and character sets.
- **Social Account Password Storage**: Store and manage encrypted passwords for various accounts.
- **RESTful API**: Built with Django REST Framework, supporting CRUD operations.
- **Role-based Permissions**: Vault access is protected and requires explicit login.
- **Frontend Simulation Script**: Python script to simulate frontend cryptographic operations and API interactions.

---

## Architecture Overview

- **Backend**: Django + Django REST Framework
- **Authentication**: JWT (JSON Web Tokens) via `djangorestframework_simplejwt`
- **Cryptography**: PBKDF2-HMAC-SHA256 for key derivation, AES (via Fernet) for encryption
- **Frontend Simulation**: Python script (`scripts/frontend_script.py`) mimics client-side cryptography and API usage

---

## Security Model

- **Master Password**: Never transmitted or stored on the server. All cryptographic keys are derived client-side.
- **Salt**: Randomly generated per user and stored in the database (binary, base64-encoded for transport).
- **Token**: Derived from the master password and salt, sent to the server for vault authentication.
- **Encryption Key**: Derived client-side, used to encrypt/decrypt passwords before sending to or after receiving from the server.
- **Encrypted Data**: All sensitive data (passwords) is stored encrypted in the database.

---

## API Endpoints

### Authentication

- `POST /api/auth/register/` — Register a new user
- `POST /api/auth/login/` — Obtain JWT tokens
- `POST /api/auth/logout/` — Invalidate JWT tokens

### Vault Management

- `POST /api/user/vault/create/` — Create a password vault (send token & salt)
- `GET /api/user/vault/salt/` — Retrieve the user's salt (for key derivation)
- `POST /api/user/vault/login/` — Login to the vault (send token & salt)

### Password Generation

- `POST /api/vault/generate-password/` — Generate and store a new password (encrypted)
- `GET /api/vault/generate-password/` — List all generated passwords
- `GET /api/vault/generate-password/<id>/` — Retrieve a specific password
- `PUT /api/vault/generate-password/<id>/` — Update a password

### Social Account Passwords

- `POST /api/social-accounts/` — Add a new social account password (encrypted)
- `GET /api/social-accounts/` — List all social account passwords

---

## Authentication & Authorization

- **JWT Authentication**: All endpoints (except registration and login) require a valid JWT token.
- **Vault Login**: Even after authenticating, users must "log in" to their vault by sending the derived token and salt.
- **Custom Permissions**: Only users who have logged into their vault can access or modify their passwords.

---

## Password Vault & Encryption

### How It Works

1. **Vault Creation**:  
   - User generates a master password client-side.
   - A random salt is generated.
   - PBKDF2 is used to derive a key from the master password and salt.
   - A token (SHA256 hash of the key) is generated and sent to the server along with the salt.
   - The server stores the token and salt (never the master password or key).

2. **Vault Login**:  
   - User re-enters the master password.
   - Client re-derives the key and token using the stored salt.
   - Token and salt are sent to the server for verification.

3. **Password Encryption**:  
   - Passwords are encrypted client-side using the derived key (Fernet/AES).
   - Encrypted passwords are sent to the server and stored as binary data.

4. **Password Retrieval**:  
   - Encrypted passwords are fetched from the server.
   - Client decrypts them using the derived key.

---

## Frontend Simulation

A Python script (`scripts/frontend_script.py`) is provided to simulate all frontend cryptographic operations and API interactions. This allows you to test the full workflow (registration, vault creation, login, password generation, encryption/decryption) without a dedicated frontend.

**Key Functions:**
- `generate_key_token(master_password)`: Generates encryption key, token, and salt.
- `regenerate_key_token(master_password, salt)`: Re-derives key and token for login.
- Full interactive CLI for login, vault management, password generation, and decryption.

---

## Project Structure

---

## Setup & Installation

### Prerequisites

- Python 3.8+
- pip

### Installation

1. **Clone the repository**
   ```bash
   git clone https://github.com/yourusername/password-manager-api.git
   cd password-manager-api

2. **Install dependencies**
    pip install -r requirements.txt

3. **Apply migrations**
    python manage.py makemigrations
    python manage.py migrate

4. **Run the development server**
 python manage.py runserver

5. **(Optional) Run the frontend simulation script**
 python scripts/frontend_script.py

Contributing
Contributions are welcome! Please open issues or submit pull requests for new features, bug fixes, or improvements.
For major changes, please open an issue first to discuss what you would like to change.

Areas for contribution:

API endpoints and features
Security enhancements
Documentation and examples
Frontend clients (web, mobile)
Automated tests

Acknowledgements
Django
Django REST Framework
cryptography
djangorestframework-simplejwt
Built with security and privacy in mind. Your master password never leaves your device.