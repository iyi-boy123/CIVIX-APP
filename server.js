'use strict';
require('dotenv').config();
const express = require('express');
const mysql = require('mysql2/promise');
const bcrypt = require('bcryptjs');
const jwt = require('jsonwebtoken');
const multer = require('multer');
const path = require('path');
const fs = require('fs');
const crypto = require('crypto');

const app = express();
const PORT = Number(process.env.PORT || 3000);
const JWT_SECRET = process.env.JWT_SECRET;
if (!JWT_SECRET || JWT_SECRET.length < 32) {
  console.error('CIVIX setup error: set JWT_SECRET in .env to a random string at least 32 characters long.');
  process.exit(1);
}
const pool = mysql.createPool({
  host: process.env.DB_HOST || '127.0.0.1',
  port: Number(process.env.DB_PORT || 3306),
  user: process.env.DB_USER || 'root',
  password: process.env.DB_PASSWORD || '',
  database: process.env.DB_NAME || 'civix',
  waitForConnections: true,
  connectionLimit: 10,
  charset: 'utf8mb4'
});
app.use(express.json({ limit: '1mb' }));
app.use(express.urlencoded({ extended: true }));
const uploadsDir = path.join(__dirname, 'public', 'uploads');
fs.mkdirSync(uploadsDir, { recursive: true });
const storage = multer.diskStorage({
  destination: (_req, _file, cb) => cb(null, uploadsDir),
  filename: (_req, file, cb) => {
    const ext = path.extname(file.originalname).toLowerCase().replace(/[^.a-z0-9]/g, '').slice(0, 10);
    cb(null, Date.now() + '-' + crypto.randomBytes(6).toString('hex') + ext);
  }
});
const upload = multer({ storage, limits: { fileSize: 5 * 1024 * 1024 }, fileFilter: (_req, file, cb) => {
  if (!file.mimetype || !file.mimetype.startsWith('image/')) return cb(new Error('Please upload an image file.'));
  cb(null, true);
} });
function tokenFor(user) { return jwt.sign({ id: user.id, email: user.email, role: user.role || 'citizen', full_name: user.full_name }, JWT_SECRET, { expiresIn: '7d' }); }
function auth(req, res, next) {
  const header = req.headers.authorization || '';
  if (!header.startsWith('Bearer ')) return res.status(401).json({ error: 'Please log in first.' });
  try { req.user = jwt.verify(header.slice(7), JWT_SECRET); next(); }
  catch (_e) { return res.status(401).json({ error: 'Your session expired. Please log in again.' }); }
}
function admin(req, res, next) { if (req.user.role !== 'admin') return res.status(403).json({ error: 'Administrator access required.' }); next(); }
const userShape = u => ({ id: u.id, name: u.full_name, full_name: u.full_name, email: u.email, role: u.role || 'citizen' });
const issueSelect = `SELECT i.id, i.reference_code, i.reported_by AS user_id, i.category, i.description,
  i.photo_url, i.created_at, COALESCE(NULLIF(SUBSTRING_INDEX(i.description, '\\n', 1), ''), CONCAT('Community issue #', i.id)) AS title,
  COALESCE(l.address_text, 'Location not provided') AS location, l.latitude, l.longitude,
  COALESCE(s.status, 'Pending') AS status, COALESCE(s.priority, 'Medium') AS priority,
  d.name AS department, u.full_name AS reporter
  FROM issues i JOIN users u ON u.id=i.reported_by
  LEFT JOIN issue_locations l ON l.issue_id=i.id
  LEFT JOIN issue_status s ON s.issue_id=i.id
  LEFT JOIN departments d ON d.id=s.department_id`;
function normalizedStatus(s) { return ({ 'in progress':'In progress', 'in_progress':'In progress', 'pending':'Pending', 'resolved':'Resolved', 'reopened':'Reopened' })[String(s || '').toLowerCase()] || null; }
function departmentFor(category) { const map = { Pothole: 1, Electricity: 2, Water: 3, Sanitation: 4, Other: 1 }; return map[category] || 1; }
app.get('/api/health', async (_req, res) => {
  try { await pool.query('SELECT 1'); const [tables] = await pool.query("SHOW TABLES LIKE 'issues'"); if (!tables.length) return res.status(503).json({ ok: false, database: 'connected but CIVIX issues table is missing' }); res.json({ ok: true, service: 'CIVIX API', database: 'connected' }); }
  catch (e) { res.status(503).json({ ok: false, database: 'disconnected', error: e.message }); }
});
app.post('/api/register', async (req, res) => {
  try {
    const fullName = String(req.body.name || req.body.full_name || '').trim();
    const email = String(req.body.email || '').trim().toLowerCase();
    const password = String(req.body.password || '');
    if (fullName.length < 2 || !/^\S+@\S+\.\S+$/.test(email) || password.length < 6) return res.status(400).json({ error: 'Enter your name, a valid email and a password of at least 6 characters.' });
    const [existing] = await pool.query('SELECT id FROM users WHERE email=?', [email]);
    if (existing.length) return res.status(409).json({ error: 'That email is already registered. Please log in.' });
    const hash = await bcrypt.hash(password, 12);
    const [result] = await pool.query('INSERT INTO users(full_name,email,password_hash) VALUES(?,?,?)', [fullName, email, hash]);
    const user = { id: result.insertId, full_name: fullName, email, role: 'citizen' };
    res.status(201).json({ user: userShape(user), token: tokenFor(user) });
  } catch (e) { console.error('Register error:', e.message); res.status(500).json({ error: 'Registration failed. Check the CIVIX database connection.' }); }
});
app.post('/api/login', async (req, res) => {
  try {
    const email = String(req.body.email || '').trim().toLowerCase(); const password = String(req.body.password || '');
    const [rows] = await pool.query('SELECT id,full_name,email,password_hash FROM users WHERE email=?', [email]);
    if (!rows.length || !(await bcrypt.compare(password, rows[0].password_hash))) return res.status(401).json({ error: 'Invalid email or password.' });
    const [adminRows] = await pool.query('SELECT id FROM users WHERE id=?', [rows[0].id]);
    const isAdmin = email === String(process.env.ADMIN_EMAIL || '').toLowerCase() && password === String(process.env.ADMIN_PASSWORD || '') && adminRows.length > 0;
    const user = { ...rows[0], role: isAdmin ? 'admin' : 'citizen' };
    res.json({ user: userShape(user), token: tokenFor(user) });
  } catch (e) { console.error('Login error:', e.message); res.status(500).json({ error: 'Login failed. Check the CIVIX database connection.' }); }
});
app.post('/api/admin/login', async (req, res) => {
  try {
    const email = String(req.body.email || '').trim().toLowerCase(); const password = String(req.body.password || '');
    if (!process.env.ADMIN_EMAIL || !process.env.ADMIN_PASSWORD || email !== process.env.ADMIN_EMAIL.toLowerCase() || password !== process.env.ADMIN_PASSWORD) return res.status(401).json({ error: 'Invalid administrator credentials.' });
    const [rows] = await pool.query('SELECT id,full_name,email,password_hash FROM users WHERE email=?', [email]);
    let user;
    if (rows.length) {
      if (!(await bcrypt.compare(password, rows[0].password_hash))) {
        const hash = await bcrypt.hash(password, 12); await pool.query('UPDATE users SET password_hash=? WHERE id=?', [hash, rows[0].id]);
      }
      user = { id: rows[0].id, full_name: rows[0].full_name, email, role: 'admin' };
    } else {
      const hash = await bcrypt.hash(password, 12); const [r] = await pool.query('INSERT INTO users(full_name,email,password_hash) VALUES(?,?,?)', ['CIVIX Administrator', email, hash]);
      user = { id: r.insertId, full_name: 'CIVIX Administrator', email, role: 'admin' };
    }
    res.json({ user: userShape(user), token: tokenFor(user) });
  } catch (e) { console.error('Admin login error:', e.message); res.status(500).json({ error: 'Administrator login failed.' }); }
});
app.get('/api/categories', async (_req, res) => { res.json(['Pothole', 'Electricity', 'Water', 'Sanitation', 'Other'].map((name, i) => ({ id: i + 1, name }))); });
app.get('/api/agencies', async (_req, res) => { try { const [rows] = await pool.query('SELECT id,name,short_name,category_handled FROM departments ORDER BY name'); res.json(rows); } catch (e) { res.status(500).json({ error: e.message }); } });
app.get('/api/reports', async (req, res) => {
  try { const params = []; let sql = issueSelect; const filters = [];
    const status = req.query.status ? normalizedStatus(req.query.status) : null; if (req.query.status && !status) return res.status(400).json({ error: 'Invalid status filter.' });
    if (status) { filters.push('s.status=?'); params.push(status); }
    if (req.query.category && ['Pothole','Electricity','Water','Sanitation','Other'].includes(req.query.category)) { filters.push('i.category=?'); params.push(req.query.category); }
    if (filters.length) sql += ' WHERE ' + filters.join(' AND ');
    sql += ' ORDER BY i.created_at DESC'; const [rows] = await pool.query(sql, params); res.json(rows);
  } catch (e) { console.error('Reports error:', e.message); res.status(500).json({ error: 'Could not load community reports.' }); }
});
app.get('/api/reports/:id', async (req, res) => {
  try { const [rows] = await pool.query(issueSelect + ' WHERE i.id=?', [req.params.id]); if (!rows.length) return res.status(404).json({ error: 'Issue not found.' });
    const [history] = await pool.query('SELECT id,issue_id,status,priority,updated_at FROM issue_status WHERE issue_id=?', [req.params.id]);
    const [comments] = await pool.query('SELECT f.id,f.issue_id,f.submitted_by,f.satisfied,f.rating,f.comment,f.created_at,u.full_name AS name FROM issue_feedback f JOIN users u ON u.id=f.submitted_by WHERE f.issue_id=? ORDER BY f.created_at', [req.params.id]);
    const [assignments] = await pool.query('SELECT a.id,a.assigned_officer,a.assigned_at,u.full_name AS officer FROM issue_assignments a JOIN users u ON u.id=a.assigned_officer WHERE a.issue_id=?', [req.params.id]);
    res.json({ ...rows[0], history, comments, assignments });
  } catch (e) { console.error('Issue detail error:', e.message); res.status(500).json({ error: 'Could not load this issue.' }); }
});
app.post('/api/reports', auth, upload.single('photo'), async (req, res) => {
  let connection;
  try {
    const title = String(req.body.title || '').trim(); const description = String(req.body.description || '').trim();
    const location = String(req.body.location || req.body.address_text || '').trim();
    let category = String(req.body.category || '').trim();
    if (!category && req.body.category_id) category = ({ '1':'Pothole', '2':'Electricity', '3':'Water', '4':'Sanitation', '5':'Other' })[String(req.body.category_id)] || '';
    if (!title || !description || !location || !['Pothole','Electricity','Water','Sanitation','Other'].includes(category)) return res.status(400).json({ error: 'Title, description, location and a valid category are required.' });
    connection = await pool.getConnection(); await connection.beginTransaction();
    const reference = 'CVX-' + Date.now().toString(36).toUpperCase() + '-' + crypto.randomBytes(2).toString('hex').toUpperCase();
    const photoUrl = req.file ? '/uploads/' + req.file.filename : null;
    const [issue] = await connection.query('INSERT INTO issues(reference_code,reported_by,category,description,photo_url) VALUES(?,?,?,?,?)', [reference, req.user.id, category, title + '\n' + description, photoUrl]);
    await connection.query('INSERT INTO issue_locations(issue_id,address_text,latitude,longitude) VALUES(?,?,?,?)', [issue.insertId, location, req.body.latitude || null, req.body.longitude || null]);
    await connection.query("INSERT INTO issue_status(issue_id,status,priority,department_id) VALUES(?,'Pending',?,?,?)".replace("VALUES(?,'Pending',?,?,?)", "VALUES(?,'Pending',?,?)"), [issue.insertId, ['Low','Medium','High','Critical'].includes(req.body.priority) ? req.body.priority : 'Medium', departmentFor(category)]);
    await connection.query('INSERT INTO notifications(user_id,issue_id,message) VALUES(?,?,?)', [req.user.id, issue.insertId, 'Your CIVIX report ' + reference + ' was submitted successfully.']);
    await connection.commit(); res.status(201).json({ id: issue.insertId, reference_code: reference, message: 'Report submitted successfully.' });
  } catch (e) { if (connection) await connection.rollback(); console.error('Create issue error:', e.message); res.status(500).json({ error: 'Could not submit the report. Please check the server and database.' }); }
  finally { if (connection) connection.release(); }
});
app.get('/api/me/reports', auth, async (req, res) => { try { const [rows] = await pool.query(issueSelect + ' WHERE i.reported_by=? ORDER BY i.created_at DESC', [req.user.id]); res.json(rows); } catch (e) { console.error(e.message); res.status(500).json({ error: 'Could not load your reports.' }); } });
app.post('/api/reports/:id/comments', auth, async (req, res) => {
  try { const comment = String(req.body.comment || req.body.message || '').trim(); if (!comment) return res.status(400).json({ error: 'Please enter a comment.' });
    const [issue] = await pool.query('SELECT id FROM issues WHERE id=?', [req.params.id]); if (!issue.length) return res.status(404).json({ error: 'Issue not found.' });
    await pool.query('INSERT INTO issue_feedback(issue_id,submitted_by,satisfied,rating,comment) VALUES(?,?,0,?,?)', [req.params.id, req.user.id, req.body.rating ? Math.min(5, Math.max(1, Number(req.body.rating))) : null, comment]); res.status(201).json({ message: 'Feedback added.' });
  } catch (e) { console.error(e.message); res.status(500).json({ error: 'Could not save your feedback.' }); }
});
app.put('/api/reports/:id/status', auth, admin, async (req, res) => {
  try { const status = normalizedStatus(req.body.status); if (!status) return res.status(400).json({ error: 'Status must be Pending, In progress, Resolved or Reopened.' });
    const [issue] = await pool.query('SELECT id,reported_by FROM issues WHERE id=?', [req.params.id]); if (!issue.length) return res.status(404).json({ error: 'Issue not found.' });
    const [current] = await pool.query('SELECT id FROM issue_status WHERE issue_id=?', [req.params.id]);
    if (current.length) await pool.query('UPDATE issue_status SET status=?,updated_at=CURRENT_TIMESTAMP WHERE issue_id=?', [status, req.params.id]);
    else await pool.query('INSERT INTO issue_status(issue_id,status,priority,department_id) VALUES(?,?,?,?)', [req.params.id, status, 'Medium', 1]);
    await pool.query('INSERT INTO notifications(user_id,issue_id,message) VALUES(?,?,?)', [issue[0].reported_by, req.params.id, 'Your CIVIX report status changed to ' + status + '.']); res.json({ message: 'Status updated.' });
  } catch (e) { console.error(e.message); res.status(500).json({ error: 'Could not update the issue status.' }); }
});
app.get('/api/notifications', auth, async (req, res) => { try { const [rows] = await pool.query('SELECT id,issue_id,message,is_read,created_at FROM notifications WHERE user_id=? ORDER BY created_at DESC LIMIT 100', [req.user.id]); res.json(rows); } catch (e) { res.status(500).json({ error: 'Could not load notifications.' }); } });
app.put('/api/notifications/:id/read', auth, async (req, res) => { try { const [r] = await pool.query('UPDATE notifications SET is_read=1 WHERE id=? AND user_id=?', [req.params.id, req.user.id]); if (!r.affectedRows) return res.status(404).json({ error: 'Notification not found.' }); res.json({ message: 'Notification marked as read.' }); } catch (e) { res.status(500).json({ error: 'Could not update notification.' }); } });
app.post('/api/reports/:id/upvote', auth, async (req, res) => { try { await pool.query('INSERT IGNORE INTO issue_upvotes(issue_id,upvoted_by) VALUES(?,?)', [req.params.id, req.user.id]); const [rows] = await pool.query('SELECT COUNT(*) AS upvotes FROM issue_upvotes WHERE issue_id=?', [req.params.id]); res.json({ upvotes: rows[0].upvotes }); } catch (e) { res.status(500).json({ error: 'Could not upvote this issue. You may already have upvoted it.' }); } });
app.use('/uploads', express.static(uploadsDir));
app.use(express.static(path.join(__dirname, 'public')));
app.use((err, _req, res, _next) => { console.error('Request error:', err.message); res.status(err.code === 'LIMIT_FILE_SIZE' ? 413 : 400).json({ error: err.code === 'LIMIT_FILE_SIZE' ? 'Image must be 5 MB or smaller.' : (err.message || 'Request failed.') }); });
app.get('*', (req, res) => res.sendFile(path.join(__dirname, 'public', 'index.html')));
async function start() { try { await pool.query('SELECT 1'); console.log('CIVIX database connected.'); app.listen(PORT, () => console.log('CIVIX running at http://localhost:' + PORT)); } catch (e) { console.error('Could not connect to MySQL:', e.message); console.error('Check that XAMPP MySQL is running and .env has the correct DB settings.'); process.exit(1); } }
start();
