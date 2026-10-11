require("dotenv").config();
const express = require("express");
const mysql = require("mysql2/promise");
const bcrypt = require("bcryptjs");
const jwt = require("jsonwebtoken");
const multer = require("multer");
const path = require("path");
const fs = require("fs");

const app = express();
const PORT = process.env.PORT || 3000;

const pool = mysql.createPool({
  host: process.env.DB_HOST || "localhost",
  port: Number(process.env.DB_PORT || 3306),
  user: process.env.DB_USER || "root",
  password: process.env.DB_PASSWORD || "",
  database: process.env.DB_NAME || "civix",
  waitForConnections: true,
  connectionLimit: 10
});

app.use(express.json());
app.use(express.urlencoded({extended:true}));

const uploadsDir = path.join(__dirname, "public", "uploads");
fs.mkdirSync(uploadsDir, {recursive:true});
const storage = multer.diskStorage({
  destination: (_,__,cb)=>cb(null,uploadsDir),
  filename: (_,file,cb)=>cb(null, Date.now()+"-"+file.originalname.replace(/[^a-zA-Z0-9._-]/g,"_"))
});
const upload = multer({storage, limits:{fileSize:5*1024*1024}});

function tokenFor(user){
  return jwt.sign({id:user.id,email:user.email,role:user.role}, process.env.JWT_SECRET || "dev-secret-change-me", {expiresIn:"7d"});
}
function auth(req,res,next){
  const raw=req.headers.authorization||"";
  if(!raw.startsWith("Bearer ")) return res.status(401).json({error:"Authentication required"});
  try { req.user=jwt.verify(raw.slice(7), process.env.JWT_SECRET || "dev-secret-change-me"); next(); }
  catch { return res.status(401).json({error:"Invalid or expired token"}); }
}
function admin(req,res,next){
  if(req.user.role!=="admin") return res.status(403).json({error:"Admin access required"});
  next();
}

app.get("/api/health", async (_,res)=>{
  try { await pool.query("SELECT 1"); res.json({ok:true,service:"CIVIX API",database:"connected"}); }
  catch(e){ res.status(503).json({ok:false,database:"disconnected",error:e.message}); }
});

app.post("/api/register", async (req,res)=>{
  try{
    const {name,email,password}=req.body;
    if(!name||!email||!password||password.length<6) return res.status(400).json({error:"Name, valid email and password (6+ characters) are required"});
    const [exists]=await pool.query("SELECT id FROM users WHERE email=?",[email.toLowerCase()]);
    if(exists.length) return res.status(409).json({error:"Email already registered"});
    const hash=await bcrypt.hash(password,12);
    const [r]=await pool.query("INSERT INTO users(name,email,password_hash) VALUES(?,?,?)",[name,email.toLowerCase(),hash]);
    const user={id:r.insertId,name,email:email.toLowerCase(),role:"citizen"};
    res.status(201).json({user,token:tokenFor(user)});
  }catch(e){res.status(500).json({error:e.message});}
});

app.post("/api/login", async (req,res)=>{
  try{
    const {email,password}=req.body;
    const [rows]=await pool.query("SELECT * FROM users WHERE email=?",[String(email||"").toLowerCase()]);
    if(!rows.length || !(await bcrypt.compare(password||"",rows[0].password_hash))) return res.status(401).json({error:"Invalid email or password"});
    const u=rows[0], user={id:u.id,name:u.name,email:u.email,role:u.role};
    res.json({user,token:tokenFor(user)});
  }catch(e){res.status(500).json({error:e.message});}
});

app.post("/api/admin/login", async (req,res)=>{
  try{
    const {email,password}=req.body;
    if(email!==process.env.ADMIN_EMAIL || password!==process.env.ADMIN_PASSWORD) return res.status(401).json({error:"Invalid admin credentials"});
    let [rows]=await pool.query("SELECT id,name,email,role FROM users WHERE email=?",[email]);
    if(!rows.length){
      const hash=await bcrypt.hash(password,12);
      const [r]=await pool.query("INSERT INTO users(name,email,password_hash,role) VALUES(?,?,?,'admin')",["CIVIX Administrator",email,hash]);
      rows=[{id:r.insertId,name:"CIVIX Administrator",email,role:"admin"}];
    }
    res.json({user:rows[0],token:tokenFor(rows[0])});
  }catch(e){res.status(500).json({error:e.message});}
});

app.get("/api/categories", async (_,res)=>{try{const [r]=await pool.query("SELECT * FROM categories ORDER BY name");res.json(r)}catch(e){res.status(500).json({error:e.message})}});
app.get("/api/agencies", async (_,res)=>{try{const [r]=await pool.query("SELECT * FROM agencies ORDER BY name");res.json(r)}catch(e){res.status(500).json({error:e.message})}});

const reportSelect=`SELECT r.*, c.name category, u.name reporter, a.name agency
FROM reports r JOIN categories c ON c.id=r.category_id JOIN users u ON u.id=r.user_id
LEFT JOIN agencies a ON a.id=r.agency_id`;

app.get("/api/reports", async (req,res)=>{
  try{
    const params=[]; let where="";
    if(req.query.status){where+=" WHERE r.status=?";params.push(req.query.status)}
    const [r]=await pool.query(reportSelect+where+" ORDER BY r.created_at DESC",params);
    res.json(r);
  }catch(e){res.status(500).json({error:e.message})}
});

app.get("/api/reports/:id", async (req,res)=>{
  try{
    const [r]=await pool.query(reportSelect+" WHERE r.id=?",[req.params.id]);
    if(!r.length)return res.status(404).json({error:"Report not found"});
    const [history]=await pool.query("SELECT * FROM status_history WHERE report_id=? ORDER BY created_at",[req.params.id]);
    const [comments]=await pool.query("SELECT c.*,u.name FROM comments c JOIN users u ON u.id=c.user_id WHERE c.report_id=? ORDER BY c.created_at",[req.params.id]);
    const [media]=await pool.query("SELECT * FROM media WHERE report_id=?",[req.params.id]);
    res.json({...r[0],history,comments,media});
  }catch(e){res.status(500).json({error:e.message})}
});

app.post("/api/reports",auth,upload.single("photo"),async(req,res)=>{
  try{
    const {title,description,location,category_id,latitude,longitude}=req.body;
    if(!title||!description||!location||!category_id)return res.status(400).json({error:"Title, description, location and category are required"});
    const [r]=await pool.query("INSERT INTO reports(user_id,category_id,title,description,location,latitude,longitude) VALUES(?,?,?,?,?,?,?)",
      [req.user.id,category_id,title,description,location,latitude||null,longitude||null]);
    await pool.query("INSERT INTO status_history(report_id,status,changed_by,note) VALUES(?,?,?,?)",[r.insertId,"pending",req.user.id,"Report submitted"]);
    if(req.file) await pool.query("INSERT INTO media(report_id,file_url) VALUES(?,?)",[r.insertId,"/uploads/"+req.file.filename]);
    res.status(201).json({id:r.insertId,message:"Report submitted successfully"});
  }catch(e){res.status(500).json({error:e.message})}
});

app.get("/api/me/reports",auth,async(req,res)=>{
  try{const [r]=await pool.query(reportSelect+" WHERE r.user_id=? ORDER BY r.created_at DESC",[req.user.id]);res.json(r)}
  catch(e){res.status(500).json({error:e.message})}
});

app.post("/api/reports/:id/comments",auth,async(req,res)=>{
  try{if(!req.body.comment)return res.status(400).json({error:"Comment required"});
    await pool.query("INSERT INTO comments(report_id,user_id,comment) VALUES(?,?,?)",[req.params.id,req.user.id,req.body.comment]);
    res.status(201).json({message:"Comment added"});
  }catch(e){res.status(500).json({error:e.message})}
});

app.put("/api/reports/:id/status",auth,admin,async(req,res)=>{
  try{
    const allowed=["pending","verified","assigned","in_progress","resolved","rejected"];
    if(!allowed.includes(req.body.status))return res.status(400).json({error:"Invalid status"});
    await pool.query("UPDATE reports SET status=? WHERE id=?",[req.body.status,req.params.id]);
    await pool.query("INSERT INTO status_history(report_id,status,changed_by,note) VALUES(?,?,?,?)",[req.params.id,req.body.status,req.user.id,req.body.note||null]);
    const [owner]=await pool.query("SELECT user_id FROM reports WHERE id=?",[req.params.id]);
    if(owner.length) await pool.query("INSERT INTO notifications(user_id,report_id,message) VALUES(?,?,?)",[owner[0].user_id,req.params.id,"Your CIVIX report status changed to "+req.body.status]);
    res.json({message:"Status updated"});
  }catch(e){res.status(500).json({error:e.message})}
});

app.use(express.static(path.join(__dirname,"public")));
app.get("*",(req,res)=>res.sendFile(path.join(__dirname,"public","index.html")));

app.listen(PORT,()=>console.log(`CIVIX running at http://localhost:${PORT}`));
