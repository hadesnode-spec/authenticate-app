require("dotenv").config();

const express = require("express");
const session = require("express-session");
const MySQLStoreFactory = require("express-mysql-session");
const mysql = require("mysql2/promise");
const mysqlCallback = require("mysql2");
const bcrypt = require("bcryptjs");
const helmet = require("helmet");
const rateLimit = require("express-rate-limit");
const path = require("path");
const fs = require("fs");
const crypto = require("crypto");
const UPLOAD_DIR = path.join(__dirname, "public", "uploads");
fs.mkdirSync(UPLOAD_DIR, { recursive: true });

const app = express();
const PORT = Number(process.env.PORT || 3000);

if (!process.env.SESSION_SECRET || process.env.SESSION_SECRET.length < 32) {
  console.error("Set SESSION_SECRET in your .env file to a long random string (at least 32 characters).");
  process.exit(1);
}

const dbConfig = {
  host: process.env.DB_HOST || "localhost",
  port: Number(process.env.DB_PORT || 3306),
  user: process.env.DB_USER || "root",
  password: process.env.DB_PASSWORD || "",
  database: process.env.DB_NAME || "stockflow"
};
const pool = mysql.createPool({ ...dbConfig, waitForConnections: true, connectionLimit: 10, queueLimit: 0 });
const MySQLStore = MySQLStoreFactory(session);
// express-mysql-session expects the callback-style mysql2 pool.
const sessionConnection = mysqlCallback.createPool(dbConfig);
const sessionStore = new MySQLStore({}, sessionConnection);

app.use(helmet({ contentSecurityPolicy: false }));
app.use(express.json({ limit: "3mb" }));
app.use(express.urlencoded({ extended: false }));
app.use(session({
  name: "stockflow.sid",
  secret: process.env.SESSION_SECRET,
  store: sessionStore,
  resave: false,
  saveUninitialized: false,
  cookie: {
    httpOnly: true,
    sameSite: "lax",
    secure: process.env.NODE_ENV === "production",
    maxAge: 1000 * 60 * 60 * 2
  }
}));

const authLimiter = rateLimit({
  windowMs: 15 * 60 * 1000,
  limit: 10,
  standardHeaders: "draft-7",
  legacyHeaders: false,
  message: { error: "Too many login or registration attempts. Please try again later." }
});

// CSRF defence: state-changing API calls must carry a custom header (browsers block cross-site use of it).
app.use("/api", (req, res, next) => {
  if (["POST","PUT","PATCH","DELETE"].includes(req.method) && req.get("x-requested-with") !== "stockflow")
    return res.status(403).json({ error: "Blocked request." });
  next();
});
app.use(express.static(path.join(__dirname, "public"), { index: false }));

function requireAuth(req, res, next) {
  if (!req.session.user) return res.status(401).json({ error: "Please sign in to continue." });
  next();
}
function requireAdmin(req, res, next) {
  if (!req.session.user) return res.status(401).json({ error: "Please sign in to continue." });
  if (req.session.user.role !== "admin") return res.status(403).json({ error: "Admin access is required." });
  next();
}
function validEmail(email) {
  return /^[^\s@]+@[^\s@]+\.[^\s@]+$/.test(email);
}

app.get("/api/me", (req, res) => {
  res.json({ user: req.session.user || null });
});

app.post("/api/register", authLimiter, async (req, res) => {
  try {
    const name = String(req.body.name || "").trim();
    const email = String(req.body.email || "").trim().toLowerCase();
    const password = String(req.body.password || "");
    if (name.length < 2 || name.length > 100) return res.status(400).json({ error: "Enter a name between 2 and 100 characters." });
    if (!validEmail(email) || email.length > 190) return res.status(400).json({ error: "Enter a valid email address." });
    if (password.length < 10 || password.length > 72) return res.status(400).json({ error: "Password must be 10–72 characters long." });

    const [existing] = await pool.execute("SELECT id FROM users WHERE email = ?", [email]);
    if (existing.length) return res.status(409).json({ error: "An account with this email already exists." });

    const passwordHash = await bcrypt.hash(password, 12);
    const [userCountRows] = await pool.execute("SELECT COUNT(*) AS count FROM users");
    const role = Number(userCountRows[0].count) === 0 ? "admin" : "staff";
    const [result] = await pool.execute(
      "INSERT INTO users (name, email, password_hash, role) VALUES (?, ?, ?, ?)",
      [name, email, passwordHash, role]
    );
    req.session.regenerate(err => {
      if (err) return res.status(500).json({ error: "Could not start a secure session." });
      req.session.user = { id: result.insertId, name, email, role };
      req.session.save(err2 => {
        if (err2) return res.status(500).json({ error: "Could not save your session." });
        res.status(201).json({ user: req.session.user });
      });
    });
  } catch (err) {
    console.error(err);
    res.status(500).json({ error: "Registration failed. Check that MySQL is running and configured." });
  }
});

app.post("/api/login", authLimiter, async (req, res) => {
  try {
    const email = String(req.body.email || "").trim().toLowerCase();
    const password = String(req.body.password || "");
    if (!validEmail(email) || !password) return res.status(400).json({ error: "Enter your email and password." });

    const [rows] = await pool.execute(
      "SELECT id, name, email, password_hash, role FROM users WHERE email = ?",
      [email]
    );
    if (!rows.length || !(await bcrypt.compare(password, rows[0].password_hash))) {
      return res.status(401).json({ error: "Incorrect email or password." });
    }

    const user = { id: rows[0].id, name: rows[0].name, email: rows[0].email, role: rows[0].role };
    req.session.regenerate(err => {
      if (err) return res.status(500).json({ error: "Could not start a secure session." });
      req.session.user = user;
      req.session.save(err2 => {
        if (err2) return res.status(500).json({ error: "Could not save your session." });
        res.json({ user });
      });
    });
  } catch (err) {
    console.error(err);
    res.status(500).json({ error: "Login failed. Check that MySQL is running and configured." });
  }
});

app.post("/api/logout", (req, res) => {
  req.session.destroy(err => {
    if (err) return res.status(500).json({ error: "Could not sign out." });
    res.clearCookie("stockflow.sid", { httpOnly: true, sameSite: "lax", secure: process.env.NODE_ENV === "production" });
    res.json({ ok: true });
  });
});

app.get("/api/products", requireAuth, async (req, res) => {
  try {
    const [rows] = await pool.execute("SELECT p.id,p.name,p.sku,p.category,p.quantity,p.min_stock,p.unit_cost,p.expiry_date,p.supplier,p.image_url,(SELECT COUNT(*) FROM product_dealers d WHERE d.product_id=p.id) AS dealer_count,(SELECT MIN(d.price) FROM product_dealers d WHERE d.product_id=p.id) AS best_price FROM products p ORDER BY p.updated_at DESC");
    res.json({ products: rows });
  } catch (err) { console.error(err); res.status(500).json({ error: "Could not load products." }); }
});

// Accepts an uploaded image (data URL, saved to public/uploads) or an https image link.
async function resolveImage(body) {
  if (body.image_data) {
    const m = /^data:image\/(jpeg|png|webp);base64,([A-Za-z0-9+/=]+)$/.exec(String(body.image_data));
    if (!m) throw Object.assign(new Error("bad image"), { status: 400, publicMessage: "Use a JPG, PNG or WebP image." });
    const buf = Buffer.from(m[2], "base64");
    if (buf.length > 2 * 1024 * 1024) throw Object.assign(new Error("big"), { status: 400, publicMessage: "Image must be under 2 MB." });
    const file = crypto.randomBytes(12).toString("hex") + "." + (m[1] === "jpeg" ? "jpg" : m[1]);
    await fs.promises.writeFile(path.join(UPLOAD_DIR, file), buf);
    return "/uploads/" + file;
  }
  const url = String(body.image_url || "").trim();
  if (!url) return null;
  if (!/^https:\/\/[^\s"'<>]{4,480}$/.test(url)) throw Object.assign(new Error("bad url"), { status: 400, publicMessage: "Image link must start with https://" });
  return url;
}
app.post("/api/products", requireAuth, async (req, res) => {
  try {
    const { name, sku, category, quantity, min_stock, unit_cost, expiry_date, supplier } = req.body;
    let image = await resolveImage(req.body);
    if (!image) image = await findImage(String(name || "").trim(), String(sku || "").trim());
    const q = Number(quantity), min = Number(min_stock), cost = Number(unit_cost);
    if (!String(name || "").trim() || !String(sku || "").trim() || !String(category || "").trim()) return res.status(400).json({ error: "Name, SKU and category are required." });
    if (!Number.isInteger(q) || q < 0 || !Number.isInteger(min) || min < 0 || !Number.isFinite(cost) || cost < 0) return res.status(400).json({ error: "Enter valid stock quantities and cost." });
    const [result] = await pool.execute(
      "INSERT INTO products (name,sku,category,quantity,min_stock,unit_cost,expiry_date,supplier,image_url) VALUES (?,?,?,?,?,?,?,?,?)",
      [String(name).trim(), String(sku).trim(), String(category).trim(), q, min, cost, expiry_date || null, supplier || null, image]
    );
    await pool.execute("INSERT INTO stock_history (user_id,action,details) VALUES (?,?,?)", [req.session.user.id, "Product added", `${name} (${sku}) added with quantity ${q}.`]);
    res.status(201).json({ id: result.insertId, message: "Product added." });
  } catch (err) {
    if (err.publicMessage) return res.status(err.status || 400).json({ error: err.publicMessage });
    if (err.code === "ER_DUP_ENTRY") return res.status(409).json({ error: "That SKU already exists." });
    console.error(err); res.status(500).json({ error: "Could not add product." });
  }
});

app.get("/api/history", requireAuth, async (req, res) => {
  try {
    const [rows] = await pool.execute(
      "SELECT h.id,h.action,h.details,h.created_at,u.name AS user_name FROM stock_history h LEFT JOIN users u ON u.id=h.user_id ORDER BY h.created_at DESC LIMIT 100"
    );
    res.json({ history: rows });
  } catch (err) { console.error(err); res.status(500).json({ error: "Could not load history." }); }
});

// The first registered user becomes admin. Later registrations are staff accounts.
app.get("/api/health", async (req, res) => {
  try { await pool.query("SELECT 1"); res.json({ ok: true, database: "connected" }); }
  catch { res.status(503).json({ ok: false, database: "not connected" }); }
});

const log = (uid, action, details) => pool.execute("INSERT INTO stock_history (user_id,action,details) VALUES (?,?,?)", [uid, action, String(details).slice(0, 500)]);
const fail = (res, err, msg) => { console.error(err); res.status(500).json({ error: msg }); };

app.post("/api/products/:id/adjust", requireAuth, async (req, res) => {
  try {
    const delta = Number(req.body.delta);
    if (!Number.isInteger(delta) || delta === 0 || Math.abs(delta) > 100000) return res.status(400).json({ error: "Enter a valid quantity." });
    const [r] = await pool.execute("UPDATE products SET quantity = quantity + ? WHERE id = ? AND quantity + ? >= 0", [delta, req.params.id, delta]);
    if (!r.affectedRows) return res.status(400).json({ error: "Product not found or not enough stock." });
    const [[p]] = await pool.execute("SELECT name, sku, quantity FROM products WHERE id = ?", [req.params.id]);
    await log(req.session.user.id, delta > 0 ? "Stock in" : "Stock out", `${p.name} (${p.sku}) ${delta > 0 ? "+" : ""}${delta}, now ${p.quantity}.`);
    res.json({ quantity: p.quantity });
  } catch (err) { fail(res, err, "Could not adjust stock."); }
});

app.delete("/api/products/:id", requireAdmin, async (req, res) => {
  try {
    const [[p]] = await pool.execute("SELECT name, sku FROM products WHERE id = ?", [req.params.id]);
    if (!p) return res.status(404).json({ error: "Product not found." });
    await pool.execute("DELETE FROM products WHERE id = ?", [req.params.id]);
    await log(req.session.user.id, "Product deleted", `${p.name} (${p.sku}) was deleted.`);
    res.json({ ok: true });
  } catch (err) { fail(res, err, "Could not delete product."); }
});

app.put("/api/products/:id", requireAuth, async (req, res) => {
  try {
    const b = req.body, q = Number(b.quantity), min = Number(b.min_stock), cost = Number(b.unit_cost);
    if (!String(b.name || "").trim() || !String(b.category || "").trim()) return res.status(400).json({ error: "Name and category are required." });
    if (!Number.isInteger(q) || q < 0 || !Number.isInteger(min) || min < 0 || !Number.isFinite(cost) || cost < 0) return res.status(400).json({ error: "Enter valid stock quantities and cost." });
    const image = (b.image_data || b.image_url) ? await resolveImage(b) : undefined;
    const sets = ["name=?","category=?","quantity=?","min_stock=?","unit_cost=?","supplier=?"], vals = [String(b.name).trim(), String(b.category).trim(), q, min, cost, b.supplier || null];
    if (image !== undefined) { sets.push("image_url=?"); vals.push(image); }
    const [r] = await pool.execute(`UPDATE products SET ${sets.join(",")} WHERE id=?`, [...vals, req.params.id]);
    if (!r.affectedRows) return res.status(404).json({ error: "Product not found." });
    await log(req.session.user.id, "Product edited", `${b.name} was updated.`);
    res.json({ ok: true });
  } catch (err) { if (err.publicMessage) return res.status(err.status || 400).json({ error: err.publicMessage }); fail(res, err, "Could not update product."); }
});

app.get("/api/products/:id/dealers", requireAuth, async (req, res) => {
  try { const [rows] = await pool.execute("SELECT id, dealer_name, url, price FROM product_dealers WHERE product_id = ? ORDER BY price IS NULL, price", [req.params.id]); res.json({ dealers: rows }); }
  catch (err) { fail(res, err, "Could not load dealers."); }
});
app.post("/api/products/:id/dealers", requireAuth, async (req, res) => {
  try {
    const name = String(req.body.dealer_name || "").trim().slice(0, 150), url = String(req.body.url || "").trim();
    const price = req.body.price === "" || req.body.price == null ? null : Number(req.body.price);
    if (!name || !/^https?:\/\/[^\s"'<>]{4,480}$/.test(url)) return res.status(400).json({ error: "Enter the dealer name and a link starting with http:// or https://" });
    if (price !== null && (!Number.isFinite(price) || price < 0)) return res.status(400).json({ error: "Enter a valid price." });
    await pool.execute("INSERT INTO product_dealers (product_id, dealer_name, url, price) VALUES (?,?,?,?)", [req.params.id, name, url, price]);
    await log(req.session.user.id, "Dealer link added", `${name} for product #${req.params.id}`);
    res.status(201).json({ ok: true });
  } catch (err) { fail(res, err, "Could not add dealer link."); }
});
app.delete("/api/dealers/:id", requireAuth, async (req, res) => {
  try { await pool.execute("DELETE FROM product_dealers WHERE id = ?", [req.params.id]); res.json({ ok: true }); }
  catch (err) { fail(res, err, "Could not remove dealer link."); }
});

// ---- Automatic photo lookup (needs internet on the server) ----
const SEED = require("./seed-data.json");
const IMG_HOSTS = ["images.pexels.com", "images.openfoodfacts.org", "static.openfoodfacts.org"];
async function downloadImage(url) {
  const u = new URL(url);
  if (u.protocol !== "https:" || !IMG_HOSTS.includes(u.hostname)) return null;
  const r = await fetch(url, { signal: AbortSignal.timeout(8000) });
  if (!r.ok) return null;
  const ext = { "image/jpeg": "jpg", "image/png": "png", "image/webp": "webp" }[(r.headers.get("content-type") || "").split(";")[0]];
  if (!ext) return null;
  const buf = Buffer.from(await r.arrayBuffer());
  if (buf.length > 2 * 1024 * 1024) return null;
  const file = crypto.randomBytes(12).toString("hex") + "." + ext;
  await fs.promises.writeFile(path.join(UPLOAD_DIR, file), buf);
  return "/uploads/" + file;
}
// 1) Barcode (SKU of 8-14 digits) -> Open Food Facts pack photo.  2) Product name -> Pexels stock photo (needs PEXELS_API_KEY).
async function findImage(name, sku) {
  try {
    if (/^\d{8,14}$/.test(sku)) {
      const r = await fetch(`https://world.openfoodfacts.org/api/v2/product/${sku}.json?fields=image_front_url`, { headers: { "User-Agent": "StockFlow/1.0" }, signal: AbortSignal.timeout(8000) });
      const j = await r.json(), u = j.product && j.product.image_front_url;
      const saved = u && await downloadImage(u);
      if (saved) return saved;
    }
    if (process.env.PEXELS_API_KEY && name) {
      const r = await fetch("https://api.pexels.com/v1/search?per_page=1&query=" + encodeURIComponent(name), { headers: { Authorization: process.env.PEXELS_API_KEY }, signal: AbortSignal.timeout(8000) });
      const j = await r.json(), u = j.photos && j.photos[0] && j.photos[0].src && j.photos[0].src.medium;
      if (u) return await downloadImage(u);
    }
  } catch (err) { console.warn("Photo lookup failed:", err.message); }
  return null;
}

// Adds sample suppliers, products and marketplace links on a brand-new (empty) database. Set SEED_SAMPLE_DATA=false to skip.
async function seedSample() {
  if (process.env.SEED_SAMPLE_DATA === "false") return;
  const [[c]] = await pool.query("SELECT (SELECT COUNT(*) FROM suppliers) AS s, (SELECT COUNT(*) FROM products) AS p");
  if (c.s || c.p) return;
  for (const x of SEED.suppliers) await pool.execute("INSERT INTO suppliers (company, contact_name, email, phone, address, city, gst) VALUES (?,?,?,?,?,?,?)", [x.company, x.contact_name, x.email, x.phone, x.address, x.city, x.gst]);
  const links = [["Amazon.in", "https://www.amazon.in/s?k="], ["Flipkart", "https://www.flipkart.com/search?q="]];
  for (const p of SEED.products) {
    const [r] = await pool.execute("INSERT INTO products (name,sku,category,quantity,min_stock,unit_cost,supplier) VALUES (?,?,?,?,?,?,?)", [p.name, p.sku, p.category, p.quantity, p.min_stock, p.unit_cost, p.supplier]);
    for (const [n, base] of links) await pool.execute("INSERT INTO product_dealers (product_id, dealer_name, url, price) VALUES (?,?,?,NULL)", [r.insertId, n, base + encodeURIComponent(p.name)]);
  }
  console.log("Sample suppliers and products added.");
  (async () => { for (const p of SEED.products) { const img = await findImage(p.name, p.sku); if (img) await pool.execute("UPDATE products SET image_url = ? WHERE sku = ?", [img, p.sku]); } })();
}
app.post("/api/products/:id/find-image", requireAuth, async (req, res) => {
  try {
    const [[p]] = await pool.execute("SELECT name, sku FROM products WHERE id = ?", [req.params.id]);
    if (!p) return res.status(404).json({ error: "Product not found." });
    const image = await findImage(p.name, p.sku);
    if (!image) return res.status(404).json({ error: "No photo found. Use a barcode as the SKU, add PEXELS_API_KEY to .env, or upload one yourself." });
    await pool.execute("UPDATE products SET image_url = ? WHERE id = ?", [image, req.params.id]);
    res.json({ image_url: image });
  } catch (err) { fail(res, err, "Photo search failed."); }
});

// ---- Profile and contact ----
app.get("/api/profile", requireAuth, async (req, res) => {
  try { const [[u]] = await pool.execute("SELECT id, name, email, role, created_at FROM users WHERE id = ?", [req.session.user.id]); res.json({ user: u }); }
  catch (err) { fail(res, err, "Could not load profile."); }
});
app.put("/api/profile", requireAuth, async (req, res) => {
  try {
    const name = String(req.body.name || "").trim();
    if (name.length < 2 || name.length > 100) return res.status(400).json({ error: "Name must be 2 to 100 characters." });
    await pool.execute("UPDATE users SET name = ? WHERE id = ?", [name, req.session.user.id]);
    req.session.user.name = name;
    res.json({ user: req.session.user });
  } catch (err) { fail(res, err, "Could not update profile."); }
});
app.put("/api/profile/password", authLimiter, requireAuth, async (req, res) => {
  try {
    const { current, next } = req.body;
    if (typeof next !== "string" || next.length < 10 || next.length > 100) return res.status(400).json({ error: "New password must be 10 to 100 characters." });
    const [[u]] = await pool.execute("SELECT password_hash FROM users WHERE id = ?", [req.session.user.id]);
    if (!(await bcrypt.compare(String(current || ""), u.password_hash))) return res.status(400).json({ error: "Current password is incorrect." });
    await pool.execute("UPDATE users SET password_hash = ? WHERE id = ?", [await bcrypt.hash(next, 12), req.session.user.id]);
    await log(req.session.user.id, "Password changed", "Account password was changed.");
    res.json({ ok: true });
  } catch (err) { fail(res, err, "Could not change password."); }
});
app.post("/api/contact", authLimiter, async (req, res) => {
  try {
    const name = String(req.body.name || "").trim(), email = String(req.body.email || "").trim().toLowerCase(), message = String(req.body.message || "").trim();
    if (name.length < 2 || !validEmail(email) || message.length < 10 || message.length > 2000) return res.status(400).json({ error: "Enter your name, a valid email and a message of 10 to 2000 characters." });
    await pool.execute("INSERT INTO contact_messages (name, email, message) VALUES (?,?,?)", [name.slice(0, 100), email.slice(0, 190), message]);
    res.status(201).json({ ok: true });
  } catch (err) { fail(res, err, "Could not send your message."); }
});
app.get("/api/messages", requireAdmin, async (req, res) => {
  try { const [rows] = await pool.execute("SELECT id, name, email, message, created_at FROM contact_messages ORDER BY id DESC LIMIT 50"); res.json({ messages: rows }); }
  catch (err) { fail(res, err, "Could not load messages."); }
});

app.get("/api/suppliers", requireAuth, async (req, res) => {
  try { const [rows] = await pool.execute("SELECT id, company, contact_name, email, phone, address, city, gst FROM suppliers ORDER BY company"); res.json({ suppliers: rows }); }
  catch (err) { fail(res, err, "Could not load suppliers."); }
});
app.post("/api/suppliers", requireAuth, async (req, res) => {
  try {
    const f = k => String(req.body[k] || "").trim();
    const [company, contact, email, phone] = [f("company"), f("contact_name"), f("email").toLowerCase(), f("phone")];
    if (!company || !contact || !validEmail(email) || !phone) return res.status(400).json({ error: "Fill in company, contact, a valid email and phone." });
    await pool.execute("INSERT INTO suppliers (company, contact_name, email, phone, address, city, gst) VALUES (?,?,?,?,?,?,?)", [company.slice(0,150), contact.slice(0,100), email.slice(0,190), phone.slice(0,40), f("address").slice(0,255) || null, f("city").slice(0,100) || null, f("gst").toUpperCase().slice(0,20) || null]);
    await log(req.session.user.id, "Supplier added", company);
    res.status(201).json({ ok: true });
  } catch (err) { fail(res, err, "Could not add supplier."); }
});
app.delete("/api/suppliers/:id", requireAdmin, async (req, res) => {
  try { await pool.execute("DELETE FROM suppliers WHERE id = ?", [req.params.id]); await log(req.session.user.id, "Supplier deleted", `Supplier #${req.params.id}`); res.json({ ok: true }); }
  catch (err) { fail(res, err, "Could not delete supplier."); }
});

app.get("/api/users", requireAdmin, async (req, res) => {
  try { const [rows] = await pool.execute("SELECT id, name, email, role, created_at FROM users ORDER BY id"); res.json({ users: rows }); }
  catch (err) { fail(res, err, "Could not load users."); }
});
app.patch("/api/users/:id/role", requireAdmin, async (req, res) => {
  try {
    const role = req.body.role;
    if (!["admin","staff"].includes(role)) return res.status(400).json({ error: "Invalid role." });
    if (Number(req.params.id) === req.session.user.id) return res.status(400).json({ error: "You cannot change your own role." });
    await pool.execute("UPDATE users SET role = ? WHERE id = ?", [role, req.params.id]);
    await log(req.session.user.id, "Role changed", `User #${req.params.id} is now ${role}.`);
    res.json({ ok: true });
  } catch (err) { fail(res, err, "Could not update role."); }
});

app.get("/api/stats/movement", requireAuth, async (req, res) => {
  try {
    const [rows] = await pool.execute("SELECT action, details, DATE_FORMAT(created_at,'%Y-%m') AS ym FROM stock_history WHERE action IN ('Stock in','Stock out') AND created_at >= DATE_FORMAT(DATE_SUB(CURDATE(), INTERVAL 5 MONTH),'%Y-%m-01')");
    const months = [], now = new Date();
    for (let i = 5; i >= 0; i--) { const d = new Date(now.getFullYear(), now.getMonth() - i, 1); months.push({ ym: d.getFullYear() + "-" + String(d.getMonth() + 1).padStart(2, "0"), label: d.toLocaleString("en", { month: "short" }), in: 0, out: 0 }); }
    for (const r of rows) { const m = months.find(x => x.ym === r.ym), n = /([+-]?\d+), now/.exec(r.details); if (m && n) m[Number(n[1]) > 0 ? "in" : "out"] += Math.abs(Number(n[1])); }
    res.json({ months });
  } catch (err) { fail(res, err, "Could not load movement."); }
});

const page = f => (req, res) => res.sendFile(path.join(__dirname, "public", f));
app.get("/", page("home.html"));
app.get("/about", page("about.html"));
app.get("/contact", page("contact.html"));
app.get("/app", page("app.html"));
app.use((req, res) => res.status(404).sendFile(path.join(__dirname, "public", "home.html")));

async function start() {
  try {
    await pool.query("SELECT 1");
    const [col] = await pool.execute("SELECT 1 FROM information_schema.columns WHERE table_schema=DATABASE() AND table_name='products' AND column_name='image_url'");
    if (!col.length) await pool.query("ALTER TABLE products ADD COLUMN image_url VARCHAR(500) NULL");
    await pool.query("CREATE TABLE IF NOT EXISTS product_dealers (id INT AUTO_INCREMENT PRIMARY KEY, product_id INT NOT NULL, dealer_name VARCHAR(150) NOT NULL, url VARCHAR(500) NOT NULL, price DECIMAL(12,2) NULL, created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP, CONSTRAINT fk_dealer_product FOREIGN KEY (product_id) REFERENCES products(id) ON DELETE CASCADE)");
    for (const [col, def] of [["address","VARCHAR(255) NULL"],["city","VARCHAR(100) NULL"],["gst","VARCHAR(20) NULL"]]) {
      const [has] = await pool.execute("SELECT 1 FROM information_schema.columns WHERE table_schema=DATABASE() AND table_name='suppliers' AND column_name=?", [col]);
      if (!has.length) await pool.query(`ALTER TABLE suppliers ADD COLUMN ${col} ${def}`);
    }
    await pool.query("CREATE TABLE IF NOT EXISTS contact_messages (id INT AUTO_INCREMENT PRIMARY KEY, name VARCHAR(100) NOT NULL, email VARCHAR(190) NOT NULL, message TEXT NOT NULL, created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP)");
    await seedSample();
    const [rows] = await pool.execute("SELECT COUNT(*) AS count FROM users");
    // Mark the first account as admin if no admin exists yet.
    const [admins] = await pool.execute("SELECT id FROM users WHERE role='admin' LIMIT 1");
    if (!admins.length && rows[0].count > 0) {
      const [first] = await pool.execute("SELECT id FROM users ORDER BY id ASC LIMIT 1");
      if (first.length) await pool.execute("UPDATE users SET role='admin' WHERE id=?", [first[0].id]);
    }
    app.listen(PORT, () => console.log(`StockFlow running at http://localhost:${PORT}`));
  } catch (err) {
    console.error("Could not connect to MySQL. Import database.sql and check .env settings.", err.message);
    process.exit(1);
  }
}
start();
