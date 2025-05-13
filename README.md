# Striver Pod Backend

This is a simple Express backend for login and sign up functionality.

## Setup

1. Install dependencies:

   ```bash
   npm install
   ```

2. Start the server:

   ```bash
   npm start
   ```

The server will run on http://localhost:5000

## Endpoints

- `POST /api/signup` — Sign up with `{ name, email, password }`
- `POST /api/login` — Login with `{ email, password }`

This backend uses an in-memory user store. For production, use a database. 