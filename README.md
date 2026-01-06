# ChatApp2

## What this is
This is a simple real-time chat app built with **Node.js + Express + Socket.IO**.

## Features
- Username/password login (local)
- Google login via Firebase Auth (optional)
- Real-time messaging + read receipts
- **Message history**: if you send messages before someone logs in, they will still see the previous messages after they connect.
  - Uses **Postgres** when `DATABASE_URL` is set
  - Falls back to **in-memory** storage when Postgres is not configured (messages will be lost on server restart)

## Run
```bash
npm start
```
Then open `http://127.0.0.1:3000`.

## Firebase Google Login (optional)
If you want Google login using Firebase Auth, set these env vars in `.env` (or rely on the embedded dev config):
- `FIREBASE_API_KEY`
- `FIREBASE_AUTH_DOMAIN`
- `FIREBASE_PROJECT_ID`
- `FIREBASE_APP_ID`

For production, you should also configure Firebase Admin credentials (recommended):
- `FIREBASE_SERVICE_ACCOUNT_PATH=/absolute/path/to/serviceAccountKey.json`
  - or `FIREBASE_SERVICE_ACCOUNT_JSON=...`
  - or `GOOGLE_APPLICATION_CREDENTIALS=/absolute/path/to/serviceAccountKey.json`

## Status
- Google authentication is currently under investigation: we are analyzing the errors and working on a fix.
- Everything else is working as expected.

## Roadmap
Right now this app is **not** a multi-room chat app yet.
Soon, it will be updated to support:
- **Group chats**
- **1:1 (direct) chats**


