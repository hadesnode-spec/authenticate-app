STOCKFLOW ELECTRONICS - Node.js + Express + MySQL
==================================================

FOLDER MAP (where each file lives)
  server.js            Backend: all REST API routes, sessions, bcryptjs login
  package.json         Dependencies and start command
  database.sql         Full MySQL script (database, tables, relationships)
  seed-data.json       Sample electronics suppliers and products
  .env.example         Copy to .env and fill in (never upload .env)
  public/home.html     Home page         public/about.html    About page
  public/contact.html  Contact page      public/site.css      Styles for public pages
  public/app.html      Login, Register, Dashboard, Products, Suppliers, History, Profile, Team
  public/uploads/      Product photos you upload (created automatically)

RUN ON YOUR LAPTOP
  1. Install Node.js LTS (nodejs.org), MySQL Community Server + Workbench (dev.mysql.com), VS Code.
  2. Open this folder in VS Code (File > Open Folder), then Terminal > New Terminal.
  3. Run:   npm install
  4. Create the database: open MySQL Workbench, connect, File > Open SQL Script > database.sql, click the lightning bolt.
  5. Copy .env.example to .env (Windows: copy .env.example .env). Set DB_PASSWORD to your MySQL root password
     and SESSION_SECRET to any long random text.
  6. Run:   npm start
  7. Open http://localhost:3000 . Click Sign in / Register. The FIRST account you register becomes the admin.

COMMON ERRORS
  "npm is not recognized"        Node.js not installed; install it and reopen VS Code.
  "ECONNREFUSED" / "Access denied"  MySQL not running, or wrong DB_PASSWORD in .env.
  "Unknown database"             Step 4 was skipped; run database.sql.
  "Port 3000 in use"             Set PORT=3001 in .env.
  Page not loading from file     Never double-click the HTML files; always use http://localhost:3000.

OPTIONAL
  PEXELS_API_KEY in .env  -> automatic product photos (free key at pexels.com/api).
  SEED_SAMPLE_DATA=false  -> start with no sample data.
Sample names, emails, phone numbers and GST numbers are made-up.
