// ============================================================================
// Dang nhap / phien lam viec / phan quyen (RBAC)
// ============================================================================
const crypto = require("crypto");
const bcrypt = require("bcryptjs");
const { db } = require("./db.js");

const SESSION_TTL_MS = 30 * 24 * 60 * 60 * 1000; // 30 ngay

const ROLE_LABELS = {
  admin: "Quản trị viên",
  manager: "Quản lý",
  responsible: "Người phụ trách",
  viewer: "Người xem",
};

function findUserByUsername(username) {
  return db.prepare("SELECT * FROM users WHERE username = ?").get(username);
}
function findUserById(id) {
  return db.prepare("SELECT * FROM users WHERE id = ?").get(id);
}

function createSession(userId) {
  const token = crypto.randomBytes(32).toString("hex");
  const now = new Date();
  const expires = new Date(now.getTime() + SESSION_TTL_MS);
  db.prepare("INSERT INTO sessions (token, user_id, created_at, expires_at) VALUES (?,?,?,?)").run(
    token,
    userId,
    now.toISOString(),
    expires.toISOString()
  );
  return { token, expires };
}
function destroySession(token) {
  db.prepare("DELETE FROM sessions WHERE token = ?").run(token);
}
function getSessionUser(token) {
  if (!token) return null;
  const row = db
    .prepare(
      `SELECT u.* FROM sessions s JOIN users u ON u.id = s.user_id
       WHERE s.token = ? AND s.expires_at > ? AND u.active = 1`
    )
    .get(token, new Date().toISOString());
  return row || null;
}

function publicUser(u) {
  if (!u) return null;
  return {
    id: u.id,
    username: u.username,
    display_name: u.display_name,
    role: u.role,
    role_label: ROLE_LABELS[u.role] || u.role,
  };
}

// ---------------------------------------------------------------------------
// Middleware
// ---------------------------------------------------------------------------
function attachUser(req, res, next) {
  const token = req.cookies && req.cookies.sid;
  req.user = getSessionUser(token);
  req.sessionToken = token;
  next();
}
function requireAuth(req, res, next) {
  if (!req.user) return res.status(401).json({ error: "Chưa đăng nhập." });
  next();
}
function requireRole() {
  const allowed = Array.from(arguments);
  return function (req, res, next) {
    if (!req.user) return res.status(401).json({ error: "Chưa đăng nhập." });
    if (!allowed.includes(req.user.role)) {
      return res.status(403).json({ error: "Bạn không có quyền thực hiện thao tác này." });
    }
    next();
  };
}
// Nguoi phu trach chi duoc thao tac tren du an ho duoc gan (project_members);
// admin/manager luon duoc phep.
function canEditProject(user, projectCode) {
  if (!user) return false;
  if (user.role === "admin" || user.role === "manager") return true;
  if (user.role === "responsible") {
    const row = db
      .prepare("SELECT 1 FROM project_members WHERE project_code = ? AND user_id = ?")
      .get(projectCode, user.id);
    return !!row;
  }
  return false;
}

module.exports = {
  ROLE_LABELS,
  findUserByUsername,
  findUserById,
  createSession,
  destroySession,
  getSessionUser,
  publicUser,
  attachUser,
  requireAuth,
  requireRole,
  canEditProject,
  bcrypt,
};
