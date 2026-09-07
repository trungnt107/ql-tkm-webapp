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
      return res.status(403).json({ error: "Bạn không có quyền thực hiện thao tác này.", success: false, code: "FORBIDDEN" });
    }
    next();
  };
}
// [LEGACY / DEPRECATED - KHONG con duoc dung de quyet dinh quyen]
// Ham nay doc bang project_members (co che phan quyen CU). Ke tu khi he
// thong ACL moi (user_project_permissions / user_task_permissions, xem cac
// ham ben duoi) duoc dua vao su dung, KHONG con noi nao trong server.js goi
// ham nay de kiem tra quyen nua - nguon quyen chinh thuc duy nhat bay gio la
// getProjectPermission()/canViewProject()/canUpdateProject()/
// canManageProjectFull()/canDeleteProjectAcl() o duoi day. Ham nay duoc GIU
// LAI nguyen trang (khong xoa) chi de tham khao/doi chieu lich su va tranh
// lam vo bat ky cho nao (neu co) dang import no - KHONG duoc goi ham nay o
// bat ky logic phan quyen moi nao trong tuong lai.
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

// ---------------------------------------------------------------------------
// Phan quyen chi tiet theo TUNG DU AN (ACL) - chi tac dong voi vai tro
// 'responsible' va 'viewer'. admin/manager luon FULL tren moi du an, khong
// doi so voi truoc day (khong pha vo hanh vi dang chay tren production).
// ---------------------------------------------------------------------------
const PERMISSION_RANK = { VIEW: 1, UPDATE: 2, MANAGE: 3, FULL: 4 };
const PERMISSION_LABELS = {
  NONE: "Không có quyền",
  VIEW: "Chỉ xem",
  UPDATE: "Cập nhật tiến độ",
  MANAGE: "Quản lý dự án",
  FULL: "Toàn quyền dự án",
};

// Tra ve 'FULL' (admin/manager), mot trong 4 muc VIEW/UPDATE/MANAGE/FULL neu
// user (vai tro responsible/viewer) duoc cap quyen tren dung du an nay, hoac
// null neu khong duoc cap quyen gi ca (tuc la: khong duoc thay du an nay).
function getProjectPermission(user, projectCode) {
  if (!user) return null;
  if (user.role === "admin" || user.role === "manager") return "FULL";
  const row = db
    .prepare("SELECT permission_level FROM user_project_permissions WHERE user_id = ? AND project_code = ?")
    .get(user.id, projectCode);
  return row ? row.permission_level : null;
}
function hasProjectPermissionAtLeast(user, projectCode, minLevel) {
  const level = getProjectPermission(user, projectCode);
  if (!level) return false;
  return PERMISSION_RANK[level] >= PERMISSION_RANK[minLevel];
}
function canViewProject(user, projectCode) {
  return hasProjectPermissionAtLeast(user, projectCode, "VIEW");
}
function canUpdateProject(user, projectCode) {
  // Duoc sua tien do/trang thai/vuong mac.
  return hasProjectPermissionAtLeast(user, projectCode, "UPDATE");
}
function canManageProjectFull(user, projectCode) {
  // Duoc sua thong tin quan trong, quan ly cong viec, quan ly vat tu.
  return hasProjectPermissionAtLeast(user, projectCode, "MANAGE");
}
function canDeleteProjectAcl(user, projectCode) {
  return hasProjectPermissionAtLeast(user, projectCode, "FULL");
}
// Danh sach ma du an ma user duoc THAY (VIEW tro len). admin/manager: null
// nghia la "tat ca" (khong loc).
function visibleProjectCodesFor(user) {
  if (!user) return [];
  if (user.role === "admin" || user.role === "manager") return null;
  const rows = db.prepare("SELECT project_code FROM user_project_permissions WHERE user_id = ?").all(user.id);
  return rows.map((r) => r.project_code);
}

// ---------------------------------------------------------------------------
// Giai doan 1 - Phan quyen chi tiet theo TUNG CONG VIEC/TASK ben trong 1 du
// an (bang user_task_permissions - xem chu thich trong db.js). Day la lop
// GIOI HAN THEM tren nen quyen du an da co o tren: KHONG anh huong gi neu
// admin chua tung gioi han task cho ai (hanh vi giu nguyen 100% nhu truoc -
// ai co UPDATE/MANAGE/FULL tren du an van sua duoc MOI task nhu cu).
// ---------------------------------------------------------------------------
function getUserTaskPermissionRows(userId, projectCode) {
  return db
    .prepare("SELECT task_id, permission_level FROM user_task_permissions WHERE user_id = ? AND project_code = ?")
    .all(userId, projectCode);
}
// Tra ve muc quyen HIEU LUC (VIEW/UPDATE/MANAGE/FULL) cua user tren 1 task cu
// the, hoac null neu khong duoc thay task (khong du quyen tren ca du an).
// Logic:
//  - admin/manager: luon FULL.
//  - Khong co quyen gi tren du an (getProjectPermission null): null.
//  - Du an chi co VIEW: task cung chi VIEW (pham vi task khong lien quan).
//  - Du an co UPDATE/MANAGE/FULL nhung CHUA tung bi gioi han task nao (khong
//    co dong nao trong user_task_permissions cho cap user+project nay): tra
//    nguyen muc quyen du an cho MOI task - dung hanh vi dang chay truoc day.
//  - Da bi gioi han (co it nhat 1 dong): task KHONG nam trong danh sach ->
//    chi VIEW; task CO trong danh sach -> muc quyen cua dong do, nhung KHONG
//    DUOC VUOT qua muc quyen du an hien tai (phong truong hop du lieu cu con
//    sot lai sau khi admin ha quyen du an - luon lay muc THAP HON giua 2 ben).
function getEffectiveTaskPermission(user, projectCode, taskId) {
  if (!user) return null;
  if (user.role === "admin" || user.role === "manager") return "FULL";
  const projectLevel = getProjectPermission(user, projectCode);
  if (!projectLevel) return null;
  if (projectLevel === "VIEW") return "VIEW";
  const rows = getUserTaskPermissionRows(user.id, projectCode);
  if (!rows.length) return projectLevel;
  const row = rows.find((r) => r.task_id === taskId);
  if (!row) return "VIEW";
  return PERMISSION_RANK[row.permission_level] <= PERMISSION_RANK[projectLevel] ? row.permission_level : projectLevel;
}
function canViewTask(user, projectCode, taskId) {
  return !!getEffectiveTaskPermission(user, projectCode, taskId);
}
function canUpdateTaskRow(user, projectCode, taskId) {
  const level = getEffectiveTaskPermission(user, projectCode, taskId);
  return !!level && PERMISSION_RANK[level] >= PERMISSION_RANK.UPDATE;
}
function canManageTaskRow(user, projectCode, taskId) {
  const level = getEffectiveTaskPermission(user, projectCode, taskId);
  return !!level && PERMISSION_RANK[level] >= PERMISSION_RANK.MANAGE;
}
// Dung cho giao dien (khoa input) va man hinh quan tri ("x/y task"): tra ve
// null neu KHONG bi gioi han (tat ca task cua du an nay deu sua duoc dung
// muc quyen du an), hoac mot Set<task_id> neu CO gioi han - chi cac task
// trong Set moi duoc SUA (cap UPDATE tro len); cac task khac trong cung du
// an van XEM duoc (do van con quyen VIEW tren ca du an) nhung khong sua duoc.
function restrictedTaskIdsFor(user, projectCode) {
  if (!user || user.role === "admin" || user.role === "manager") return null;
  const projectLevel = getProjectPermission(user, projectCode);
  if (!projectLevel || projectLevel === "VIEW") return null;
  const rows = getUserTaskPermissionRows(user.id, projectCode);
  if (!rows.length) return null;
  return new Set(
    rows
      .filter((r) => PERMISSION_RANK[r.permission_level] >= PERMISSION_RANK.UPDATE)
      .map((r) => r.task_id)
  );
}

module.exports = {
  ROLE_LABELS,
  PERMISSION_RANK,
  PERMISSION_LABELS,
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
  getProjectPermission,
  hasProjectPermissionAtLeast,
  canViewProject,
  canUpdateProject,
  canManageProjectFull,
  canDeleteProjectAcl,
  visibleProjectCodesFor,
  getUserTaskPermissionRows,
  getEffectiveTaskPermission,
  canViewTask,
  canUpdateTaskRow,
  canManageTaskRow,
  restrictedTaskIdsFor,
  bcrypt,
};
