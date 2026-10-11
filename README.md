# CIVIX — Live Working Application

This is a real full-stack CIVIX application, not the previous presentation-only demo.

## Stack
- Node.js + Express
- MySQL + mysql2
- bcryptjs password hashing
- JWT authentication
- Multer image upload
- HTML/CSS/JavaScript frontend served by Express

## Run locally

1. Install Node.js and MySQL.
2. Create the database:
   `mysql -u root -p < schema_mysql.sql`
3. Copy `.env.example` to `.env` and enter your MySQL credentials.
4. Install packages:
   `npm install`
5. Start:
   `npm start`
6. Open:
   `http://localhost:3000`

## Real workflows included
- Citizen registration
- Citizen login
- Admin login
- Protected report creation
- Photo uploads
- Public community reports
- My reports
- Categories
- Report detail API
- Comments
- Status history
- Notifications
- Admin status updates
- MySQL persistence

## Admin
Set ADMIN_EMAIL and ADMIN_PASSWORD in `.env`, then use POST `/api/admin/login`.
Use the returned JWT as `Authorization: Bearer <token>` for admin status updates.

## Deploying publicly
Deploy the Node application to a host such as Render, Railway, Fly.io, a VPS, or another Node-compatible host and use a managed MySQL database. Set the same environment variables on the host. The app is already structured so the frontend and API are served from one deployment.

Important: a public URL cannot be created from this chat alone because deployment requires access to a hosting account/domain/database. This package is the deployable application.
