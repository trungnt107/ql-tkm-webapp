// ============================================================================
// QL Tien do Du an TKM - Web App quan ly du an dung chung (Node 22+, SQLite)
// Dang nhap, phan quyen (RBAC), luu CSDL that, lich su thay doi, canh bao
// xung dot khi luu (optimistic concurrency), thong bao du lieu moi (SSE).
// ============================================================================
const express = require("express");
const cookieParser = require("cookie-parser");
const path = require("path");
const fs = require("fs");
const { db } = require("./db.js");
const {
  ROLE_LABELS,
  PERMISSION_LABELS,
  findUserByUsername,
  findUserById,
  createSession,
  destroySession,
  publicUser,
  attachUser,
  requireAuth,
  requireRole,
  canEditProject,
  getProjectPermission,
  canViewProject,
  canUpdateProject,
  canManageProjectFull,
  canDeleteProjectAcl,
  visibleProjectCodesFor,
  bcrypt,
} = require("./auth.js");

const PORT = process.env.PORT || 3000;
// Railway (va cac host tuong tu) chay ung dung sau 1 lop reverse proxy dam
// nhiem TLS: nhan dien qua bien moi truong RAILWAY_ENVIRONMENT do Railway tu
// cap, hoac NODE_ENV=production duoc cau hinh thu cong.
const IS_PROD = !!(process.env.RAILWAY_ENVIRONMENT || process.env.NODE_ENV === "production");
const PUBLIC_HTML = path.join(__dirname, "public_index.html");
const ADMIN_HTML = path.join(__dirname, "admin-users.html");
const SEED_META = JSON.parse(fs.readFileSync(path.join(__dirname, "data", "seed_data.json"), "utf8"));

const app = express();
if (IS_PROD) app.set("trust proxy", 1);
app.use(express.json({ limit: "20mb" }));
app.use(cookieParser());
app.use(attachUser);

// ---------------------------------------------------------------------------
// Chong do vet mat khau: gioi han so lan dang nhap sai theo tung
// username+IP (bo nho tam trong tien trinh - du dung cho 1 instance Railway).
// ---------------------------------------------------------------------------
const LOGIN_MAX_ATTEMPTS = 8;
const LOGIN_WINDOW_MS = 10 * 60 * 1000;
const loginAttempts = new Map(); // key -> { count, firstAt }
function loginRateKey(req, username) {
  return (req.ip || "unknown") + "|" + String(username || "").toLowerCase();
}
function isLoginRateLimited(key) {
  const rec = loginAttempts.get(key);
  if (!rec) return false;
  if (Date.now() - rec.firstAt > LOGIN_WINDOW_MS) {
    loginAttempts.delete(key);
    return false;
  }
  return rec.count >= LOGIN_MAX_ATTEMPTS;
}
function registerLoginFailure(key) {
  const rec = loginAttempts.get(key);
  if (!rec || Date.now() - rec.firstAt > LOGIN_WINDOW_MS) {
    loginAttempts.set(key, { count: 1, firstAt: Date.now() });
  } else {
    rec.count += 1;
  }
}
function clearLoginFailures(key) {
  loginAttempts.delete(key);
}

function now() {
  return new Date().toISOString();
}
function err(res, status, message) {
  return res.status(status).json({ error: message });
}

// ---------------------------------------------------------------------------
// Server-Sent Events: bao cho cac trinh duyet dang mo biet "co du lieu moi"
// ---------------------------------------------------------------------------
let sseClients = [];
function broadcastChange(info) {
  const payload = `data: ${JSON.stringify({ type: "changed", ...info })}\n\n`;
  sseClients.forEach((res) => res.write(payload));
}
app.get("/api/events", requireAuth, (req, res) => {
  res.set({
    "Content-Type": "text/event-stream",
    "Cache-Control": "no-cache",
    Connection: "keep-alive",
  });
  res.flushHeaders();
  res.write(": ok\n\n");
  sseClients.push(res);
  req.on("close", () => {
    sseClients = sseClients.filter((r) => r !== res);
  });
});

// ---------------------------------------------------------------------------
// Auth
// ---------------------------------------------------------------------------
app.post("/api/auth/login", (req, res) => {
  const { username, password } = req.body || {};
  const rateKey = loginRateKey(req, username);
  if (isLoginRateLimited(rateKey)) {
    return err(res, 429, "Bạn đã nhập sai quá nhiều lần. Vui lòng thử lại sau ít phút.");
  }
  const u = findUserByUsername(String(username || "").trim());
  if (!u || !u.active) {
    registerLoginFailure(rateKey);
    return err(res, 401, "Sai tên đăng nhập hoặc mật khẩu.");
  }
  if (!bcrypt.compareSync(String(password || ""), u.password_hash)) {
    registerLoginFailure(rateKey);
    return err(res, 401, "Sai tên đăng nhập hoặc mật khẩu.");
  }
  clearLoginFailures(rateKey);
  const { token, expires } = createSession(u.id);
  res.cookie("sid", token, {
    httpOnly: true,
    sameSite: "lax",
    secure: IS_PROD,
    expires,
  });
  res.json({ user: publicUser(u) });
});
app.post("/api/auth/logout", (req, res) => {
  if (req.sessionToken) destroySession(req.sessionToken);
  res.clearCookie("sid");
  res.json({ ok: true });
});
app.get("/api/auth/me", (req, res) => {
  res.json({ user: publicUser(req.user) });
});
app.post("/api/auth/change-password", requireAuth, (req, res) => {
  const { old_password, new_password } = req.body || {};
  if (!bcrypt.compareSync(String(old_password || ""), req.user.password_hash)) {
    return err(res, 400, "Mật khẩu hiện tại không đúng.");
  }
  if (!new_password || String(new_password).length < 6) {
    return err(res, 400, "Mật khẩu mới phải từ 6 ký tự trở lên.");
  }
  const hash = bcrypt.hashSync(String(new_password), 10);
  db.prepare("UPDATE users SET password_hash = ? WHERE id = ?").run(hash, req.user.id);
  res.json({ ok: true });
});

// ---------------------------------------------------------------------------
// Quan ly nguoi dung (chi admin)
// ---------------------------------------------------------------------------
app.get("/api/users", requireRole("admin"), (req, res) => {
  const rows = db.prepare("SELECT id, username, display_name, role, active, created_at FROM users ORDER BY id").all();
  res.json({ users: rows.map((u) => ({ ...u, role_label: ROLE_LABELS[u.role] || u.role })) });
});
app.post("/api/users", requireRole("admin"), (req, res) => {
  const { username, password, display_name, role } = req.body || {};
  if (!username || !password || !display_name || !role) return err(res, 400, "Thiếu thông tin bắt buộc.");
  if (!ROLE_LABELS[role]) return err(res, 400, "Vai trò không hợp lệ.");
  if (String(password).length < 6) return err(res, 400, "Mật khẩu phải từ 6 ký tự trở lên.");
  if (findUserByUsername(username)) return err(res, 400, "Tên đăng nhập đã tồn tại.");
  const hash = bcrypt.hashSync(String(password), 10);
  const info = db
    .prepare("INSERT INTO users (username, password_hash, display_name, role, active, created_at) VALUES (?,?,?,?,1,?)")
    .run(username, hash, display_name, role, now());
  res.json({ ok: true, id: info.lastInsertRowid });
});
app.put("/api/users/:id", requireRole("admin"), (req, res) => {
  const id = Number(req.params.id);
  const u = findUserById(id);
  if (!u) return err(res, 404, "Không tìm thấy người dùng.");
  const { display_name, role, active, password } = req.body || {};
  if (role && !ROLE_LABELS[role]) return err(res, 400, "Vai trò không hợp lệ.");
  db.prepare(
    "UPDATE users SET display_name = COALESCE(?,display_name), role = COALESCE(?,role), active = COALESCE(?,active) WHERE id = ?"
  ).run(display_name ?? null, role ?? null, active == null ? null : active ? 1 : 0, id);
  if (password) {
    if (String(password).length < 6) return err(res, 400, "Mật khẩu phải từ 6 ký tự trở lên.");
    db.prepare("UPDATE users SET password_hash = ? WHERE id = ?").run(bcrypt.hashSync(String(password), 10), id);
  }
  res.json({ ok: true });
});
app.get("/api/projects-list-for-assignment", requireRole("admin", "manager"), (req, res) => {
  const rows = db
    .prepare("SELECT code, name, parent_code FROM projects WHERE deleted_at IS NULL ORDER BY code")
    .all();
  res.json({ projects: rows });
});
app.get("/api/auth/my-assignments", requireAuth, (req, res) => {
  // Tuong thich nguoc: danh sach ma du an ma nguoi dung hien tai duoc SUA
  // (tuc muc quyen UPDATE tro len trong bang phan quyen chi tiet moi).
  const rows = db
    .prepare("SELECT project_code FROM user_project_permissions WHERE user_id = ? AND permission_level != 'VIEW'")
    .all(req.user.id);
  res.json({ project_codes: rows.map((r) => r.project_code) });
});
app.get("/api/auth/my-permissions", requireAuth, (req, res) => {
  if (req.user.role === "admin" || req.user.role === "manager") {
    return res.json({ full_access: true, permissions: {} });
  }
  const rows = db
    .prepare("SELECT project_code, permission_level FROM user_project_permissions WHERE user_id = ?")
    .all(req.user.id);
  const permissions = {};
  rows.forEach((r) => (permissions[r.project_code] = r.permission_level));
  res.json({ full_access: false, permissions });
});
app.get("/api/members/:userId", requireRole("admin", "manager"), (req, res) => {
  const rows = db.prepare("SELECT project_code FROM project_members WHERE user_id = ?").all(Number(req.params.userId));
  res.json({ project_codes: rows.map((r) => r.project_code) });
});
app.put("/api/members/:userId", requireRole("admin", "manager"), (req, res) => {
  const userId = Number(req.params.userId);
  const codes = Array.isArray(req.body && req.body.project_codes) ? req.body.project_codes : [];
  db.exec("BEGIN");
  try {
    db.prepare("DELETE FROM project_members WHERE user_id = ?").run(userId);
    const ins = db.prepare("INSERT OR IGNORE INTO project_members (project_code, user_id) VALUES (?,?)");
    codes.forEach((c) => ins.run(c, userId));
    db.exec("COMMIT");
  } catch (e) {
    db.exec("ROLLBACK");
    return err(res, 500, "Lưu phân công thất bại.");
  }
  res.json({ ok: true });
});

// ---------------------------------------------------------------------------
// Phan quyen chi tiet theo TUNG DU AN (ACL: VIEW / UPDATE / MANAGE / FULL)
// Chi admin duoc xem/sua - day la kenh chinh de gan quyen cho vai tro
// 'responsible' va 'viewer'. (Xem auth.js: admin/manager luon FULL moi du an
// nen khong can - va khong bi anh huong boi - bang nay.)
// ---------------------------------------------------------------------------
const VALID_PERMISSION_LEVELS = ["VIEW", "UPDATE", "MANAGE", "FULL"];
app.get("/api/users/:userId/projects", requireRole("admin"), (req, res) => {
  const userId = Number(req.params.userId);
  const rows = db
    .prepare(
      `SELECT upp.project_code, upp.permission_level, p.name AS project_name, p.parent_code
       FROM user_project_permissions upp
       JOIN projects p ON p.code = upp.project_code
       WHERE upp.user_id = ?
       ORDER BY upp.project_code`
    )
    .all(userId);
  res.json({
    projects: rows.map((r) => ({
      project_id: r.project_code,
      project_code: r.project_code,
      project_name: r.project_name,
      parent_code: r.parent_code,
      permission: r.permission_level,
      permission_label: PERMISSION_LABELS[r.permission_level] || r.permission_level,
    })),
  });
});
app.put("/api/users/:userId/project-permissions", requireRole("admin"), (req, res) => {
  const userId = Number(req.params.userId);
  const u = findUserById(userId);
  if (!u) return err(res, 404, "Không tìm thấy người dùng.");
  const rawList = Array.isArray(req.body)
    ? req.body
    : req.body && Array.isArray(req.body.permissions)
    ? req.body.permissions
    : null;
  if (!rawList) return err(res, 400, 'Dữ liệu không hợp lệ - cần một mảng [{ "project_id": "...", "permission": "VIEW|UPDATE|MANAGE|FULL" }].');

  const clean = [];
  for (const item of rawList) {
    const code = item && (item.project_id || item.project_code);
    const level = String((item && (item.permission || item.permission_level)) || "").toUpperCase();
    if (!code) continue;
    if (!VALID_PERMISSION_LEVELS.includes(level)) {
      return err(res, 400, `Mức quyền không hợp lệ cho dự án "${code}": "${item.permission}".`);
    }
    clean.push({ code, level });
  }

  const ts = now();
  db.exec("BEGIN");
  try {
    db.prepare("DELETE FROM user_project_permissions WHERE user_id = ?").run(userId);
    const ins = db.prepare(
      `INSERT INTO user_project_permissions (user_id, project_code, permission_level, created_at, updated_at)
       VALUES (?,?,?,?,?)
       ON CONFLICT(user_id, project_code) DO UPDATE SET permission_level = excluded.permission_level, updated_at = excluded.updated_at`
    );
    clean.forEach((it) => ins.run(userId, it.code, it.level, ts, ts));
    db.exec("COMMIT");
  } catch (e) {
    db.exec("ROLLBACK");
    return err(res, 500, "Lưu phân quyền dự án thất bại: " + e.message);
  }
  res.json({ ok: true, count: clean.length });
});

// ---------------------------------------------------------------------------
// Helpers: doc du lieu tinh (excel goc) va dung chung
// ---------------------------------------------------------------------------
function getCategories() {
  const rows = db.prepare("SELECT cat_key, value FROM categories ORDER BY id").all();
  const cats = {};
  for (const r of rows) {
    if (!cats[r.cat_key]) cats[r.cat_key] = [];
    cats[r.cat_key].push(r.value);
  }
  return cats;
}
function taskRowsFor(code) {  return db
    .prepare("SELECT * FROM project_tasks WHERE project_code = ? ORDER BY sort_order, id")
    .all(code)
    .map((t) => ({
      task_name: t.task_name,
      responsible_person: t.responsible_person,
      start_date: t.start_date,
      due_date: t.due_date,
      pct_done: t.pct_done,
      status: t.status,
      note: t.note,
    }));
}
function rowToOverride(row) {
  return {
    child_code: row.code,
    parent_code: row.parent_code,
    child_name: row.name,
    category: row.category,
    region: row.region,
    design_type: row.design_type,
    contractor: row.contractor,
    exec_year: row.exec_year,
    responsible_unit: row.responsible_unit,
    responsible_person: row.responsible_person,
    priority_level: row.priority_level,
    status: row.status,
    planned_km_or_station: row.planned_km_or_station,
    budget_value: row.budget_value,
    contract_value: row.contract_value,
    settlement_value: row.settlement_value,
    planned_start_date: row.planned_start_date,
    planned_end_date: row.planned_end_date,
    actual_start_date: row.actual_start_date,
    actual_end_date: row.actual_end_date,
    volume_done: row.volume_done,
    progress: row.progress,
    cancel_flag: row.cancel_flag,
    tasks: taskRowsFor(row.code),
    _version: row.version,
  };
}
function rowToAddedChild(row) {
  return rowToOverride(row); // cung shape voi override, du du de day thang vao addedChildren
}

function buildBootstrap(user) {
  let projectRows = db.prepare("SELECT * FROM projects WHERE deleted_at IS NULL").all();

  // Loc theo quyen: admin/manager thay tat ca (visibleCodes === null). Voi
  // 'responsible'/'viewer', chi thay du an CHI TIET duoc cap quyen (VIEW tro
  // len) - va du an TONG (cha) cua no de cay khong bi "mo coi" tren giao dien
  // (khong lo them cac du an chi tiet anh em khac chua duoc cap quyen).
  const visibleCodes = visibleProjectCodesFor(user);
  if (visibleCodes !== null) {
    const visibleSet = new Set(visibleCodes);
    const parentCodesNeeded = new Set();
    projectRows.forEach((r) => {
      if (r.parent_code && visibleSet.has(r.code)) parentCodesNeeded.add(r.parent_code);
    });
    projectRows = projectRows.filter((r) => visibleSet.has(r.code) || (!r.parent_code && parentCodesNeeded.has(r.code)));
  }
  const visibleFinalSet = new Set(projectRows.map((r) => r.code));

  const byCode = {};
  projectRows.forEach((r) => (byCode[r.code] = r));

  const parents = [];
  const addedParents = [];
  const children = [];
  const addedChildren = [];
  const overrides = {};

  for (const r of projectRows) {
    const isParent = !r.parent_code;
    if (isParent) {
      if (r.source === "excel") {
        parents.push(JSON.parse(r.raw_excel_json));
      } else {
        addedParents.push({ parent_code: r.code, parent_name: r.name });
      }
    } else {
      if (r.source === "excel") {
        const rawChild = JSON.parse(r.raw_excel_json);
        rawChild._version = r.version;
        children.push(rawChild);
        if (r.version > 1) {
          overrides[r.code] = rowToOverride(r);
        }
      } else {
        addedChildren.push(rowToAddedChild(r));
      }
    }
  }

  const issuesUser = db
    .prepare(
      `SELECT i.*, p.parent_code as p_parent_code FROM project_issues i
       JOIN projects p ON p.code = i.project_code
       WHERE p.deleted_at IS NULL ORDER BY i.id`
    )
    .all()
    .filter((i) => visibleFinalSet.has(i.project_code))
    .map((i) => ({
      issue_id: "ISS-USR-" + i.id,
      parent_code: i.p_parent_code,
      child_code: i.project_code,
      content: i.content,
      cause: i.cause,
      severity: i.severity,
      responsible_unit: i.responsible_unit,
      responsible_person: i.responsible_person,
      due_date: i.due_date,
      status: i.status,
      note: i.note,
      created_at: i.created_at,
      source: i.source,
    }));

  const materialsUser = db
    .prepare(
      `SELECT m.* FROM project_materials m
       JOIN projects p ON p.code = m.project_code
       WHERE p.deleted_at IS NULL ORDER BY m.id`
    )
    .all()
    .filter((m) => visibleFinalSet.has(m.project_code))
    .map((m) => ({
      child_code: m.project_code,
      material_name: m.material_name,
      material_code: m.material_code,
      unit: m.unit,
      planned_qty: m.planned_qty,
      received_qty: m.received_qty,
      used_qty: m.used_qty,
      note: m.note,
    }));

  return {
    meta: SEED_META.meta,
    parents,
    children,
    real_issue_flags: SEED_META.real_issue_flags,
    rule_based_flags: SEED_META.rule_based_flags,
    materials: null,
    addedParents,
    addedChildren,
    issuesUser,
    materialsUser,
    overrides,
    categories: getCategories(),
  };
}

// ---------------------------------------------------------------------------
// Lich su thay doi (diff tung truong)
// ---------------------------------------------------------------------------
const HISTORY_FIELD_LABELS = {
  name: "Tên dự án",
  status: "Trạng thái",
  progress: "Tiến độ",
  responsible_person: "Người phụ trách",
  responsible_unit: "Đơn vị phụ trách",
  planned_start_date: "Ngày bắt đầu kế hoạch",
  planned_end_date: "Ngày kết thúc kế hoạch",
  actual_start_date: "Ngày bắt đầu thực tế",
  actual_end_date: "Ngày kết thúc thực tế",
  priority_level: "Mức độ ưu tiên",
  category: "Loại dự án",
};
function fmtHistoryValue(field, v) {
  if (v == null || v === "") return "(trống)";
  if (field === "progress") return Math.round(Number(v) * 100) + "%";
  return String(v);
}
function logHistory(projectCode, userName, action, oldRow, newFields) {
  const insert = db.prepare(
    "INSERT INTO project_history (project_code, user_name, action, field_changed, old_value, new_value, created_at) VALUES (?,?,?,?,?,?,?)"
  );
  const ts = now();
  if (action !== "update" || !oldRow) {
    insert.run(projectCode, userName, action, null, null, null, ts);
    return;
  }
  let any = false;
  for (const field of Object.keys(HISTORY_FIELD_LABELS)) {
    if (!(field in newFields)) continue;
    const oldV = oldRow[field];
    const newV = newFields[field];
    const oldCmp = oldV == null ? "" : String(oldV);
    const newCmp = newV == null ? "" : String(newV);
    if (oldCmp !== newCmp) {
      any = true;
      insert.run(
        projectCode,
        userName,
        "update",
        HISTORY_FIELD_LABELS[field],
        fmtHistoryValue(field, oldV),
        fmtHistoryValue(field, newV),
        ts
      );
    }
  }
  if (!any) insert.run(projectCode, userName, "update", null, null, null, ts);
}

// ---------------------------------------------------------------------------
// Sinh ma tu dong
// ---------------------------------------------------------------------------
function nextParentCode() {
  const rows = db.prepare("SELECT code FROM projects WHERE parent_code IS NULL").all();
  let max = 0;
  rows.forEach((r) => {
    const m = /^DA(\d+)$/.exec(r.code || "");
    if (m) max = Math.max(max, parseInt(m[1], 10));
  });
  return "DA" + String(max + 1).padStart(3, "0");
}
function categoryPrefix(category) {
  return category === "Mua sắm" ? "MS" : "XL";
}
function nextChildCode(parentCode, category) {
  const prefix = categoryPrefix(category);
  const re = new RegExp("^" + parentCode + "[-_]" + prefix + "(\\d+)$");
  const rows = db.prepare("SELECT code FROM projects WHERE parent_code = ?").all(parentCode);
  let max = 0;
  rows.forEach((r) => {
    const m = re.exec(r.code || "");
    if (m) max = Math.max(max, parseInt(m[1], 10));
  });
  return parentCode + "_" + prefix + String(max + 1).padStart(3, "0");
}

// ---------------------------------------------------------------------------
// API du lieu chinh
// ---------------------------------------------------------------------------
app.get("/api/bootstrap", requireAuth, (req, res) => {
  res.json(buildBootstrap(req.user));
});

app.get("/api/next-code", requireAuth, (req, res) => {
  const { mode, parentCode, category } = req.query;
  if (mode === "parent") return res.json({ code: nextParentCode() });
  if (mode === "child") {
    if (!parentCode) return err(res, 400, "Thiếu parentCode");
    return res.json({ code: nextChildCode(String(parentCode), String(category || "")) });
  }
  return err(res, 400, "mode không hợp lệ");
});

app.post("/api/check-duplicate", requireAuth, (req, res) => {
  const { child_name, parent_code } = req.body || {};
  const name = (child_name || "").trim().toLowerCase();
  if (!name) return res.json({ matches: [] });
  const rows = db.prepare("SELECT code, name, parent_code FROM projects WHERE parent_code IS NOT NULL AND deleted_at IS NULL").all();
  const matches = rows
    .filter((c) => {
      const cn = (c.name || "").trim().toLowerCase();
      if (!cn) return false;
      const sameParent = !parent_code || c.parent_code === parent_code;
      return sameParent && (cn === name || cn.includes(name) || name.includes(cn));
    })
    .map((c) => ({ child_code: c.code, child_name: c.name, parent_code: c.parent_code }));
  res.json({ matches });
});

app.post("/api/categories/:cat", requireRole("admin", "manager", "responsible"), (req, res) => {
  const cat = req.params.cat;
  const value = ((req.body && req.body.value) || "").trim();
  if (!value) return err(res, 400, "Thiếu value");
  db.prepare("INSERT OR IGNORE INTO categories (cat_key, value) VALUES (?,?)").run(cat, value);
  const rows = db.prepare("SELECT value FROM categories WHERE cat_key = ? ORDER BY id").all(cat);
  res.json({ categories: { [cat]: rows.map((r) => r.value) } });
});

function payloadToFields(payload) {
  return {
    name: payload.child_name,
    category: payload.category || null,
    region: payload.region || null,
    design_type: payload.design_type || null,
    contractor: payload.contractor || null,
    exec_year: payload.exec_year || null,
    responsible_unit: payload.responsible_unit || null,
    responsible_person: payload.responsible_person || null,
    priority_level: payload.priority_level || null,
    status: payload.status || "Chưa thực hiện",
    planned_km_or_station: payload.planned_km_or_station === "" || payload.planned_km_or_station == null ? null : Number(payload.planned_km_or_station),
    budget_value: payload.budget_value === "" || payload.budget_value == null ? null : Number(payload.budget_value),
    contract_value: payload.contract_value === "" || payload.contract_value == null ? null : Number(payload.contract_value),
    settlement_value: payload.settlement_value === "" || payload.settlement_value == null ? null : Number(payload.settlement_value),
    planned_start_date: payload.planned_start_date || null,
    planned_end_date: payload.planned_end_date || null,
    actual_start_date: payload.actual_start_date || null,
    actual_end_date: payload.actual_end_date || null,
    volume_done: payload.volume_done === "" || payload.volume_done == null ? null : Number(payload.volume_done),
    progress: typeof payload.progress === "number" ? payload.progress : 0,
    cancel_flag: payload.status === "Không thực hiện/Hủy DA" ? "Có" : "Không",
  };
}
// Ep ve mang [] neu client gui sai kieu (vd chuoi/so/null) - tranh 500 loi
// "X.forEach is not a function" khi payload khong dung dang mong doi.
function asArray(v) {
  return Array.isArray(v) ? v : [];
}
function replaceTasks(code, tasks) {
  db.prepare("DELETE FROM project_tasks WHERE project_code = ?").run(code);
  const ins = db.prepare(
    "INSERT INTO project_tasks (project_code, task_name, responsible_person, start_date, due_date, pct_done, status, note, sort_order, created_at, updated_at) VALUES (?,?,?,?,?,?,?,?,?,?,?)"
  );
  asArray(tasks).forEach((t, idx) => {
    ins.run(code, t.task_name || "", t.responsible_person || null, t.start_date || null, t.due_date || null, t.pct_done ?? 0, t.status || "Chưa thực hiện", t.note || null, idx, now(), now());
  });
}
function replaceIssues(code, issues, userName) {
  db.prepare("DELETE FROM project_issues WHERE project_code = ?").run(code);
  const ins = db.prepare(
    "INSERT INTO project_issues (project_code, content, cause, severity, responsible_unit, responsible_person, due_date, status, note, source, created_at, updated_at, created_by) VALUES (?,?,?,?,?,?,?,?,?,?,?,?,?)"
  );
  asArray(issues).forEach((it) => {
    ins.run(
      code, it.content || "", it.cause || null, it.severity || "Trung bình",
      it.coordination_unit || null, it.responsible_person || null, it.due_date || null,
      it.status || "Chưa xử lý", it.note || null, "Nhập tay qua Form", now(), now(), userName
    );
  });
}
function replaceMaterials(code, materials, userName) {
  db.prepare("DELETE FROM project_materials WHERE project_code = ?").run(code);
  const ins = db.prepare(
    "INSERT INTO project_materials (project_code, material_code, material_name, unit, planned_qty, received_qty, used_qty, note, updated_at, updated_by) VALUES (?,?,?,?,?,?,?,?,?,?)"
  );
  asArray(materials).forEach((mt) => {
    ins.run(
      code, mt.material_code || null, mt.material_name || "", mt.unit || null,
      mt.planned_qty === "" || mt.planned_qty == null ? null : Number(mt.planned_qty),
      mt.received_qty === "" || mt.received_qty == null ? null : Number(mt.received_qty),      mt.used_qty === "" || mt.used_qty == null ? null : Number(mt.used_qty),
      mt.note || null, now(), userName
    );
  });
}

app.post("/api/projects", requireRole("admin", "manager"), (req, res) => {
  const payload = req.body || {};
  if (!payload.child_name || !String(payload.child_name).trim()) return err(res, 400, "Thiếu Tên dự án");

  let parentCode = payload.parent_code;
  db.exec("BEGIN");
  try {
    if (payload.isNewParent) {
      if (!payload.newParentName || !String(payload.newParentName).trim()) {
        db.exec("ROLLBACK");
        return err(res, 400, "Thiếu Tên dự án tổng mới");
      }
      parentCode = nextParentCode();
      db.prepare(
        "INSERT INTO projects (code, parent_code, name, source, version, created_at, updated_at, updated_by) VALUES (?,NULL,?,'form',1,?,?,?)"
      ).run(parentCode, payload.newParentName, now(), now(), req.user.display_name);
      logHistory(parentCode, req.user.display_name, "create", null, {});
    }
    if (!parentCode) {
      db.exec("ROLLBACK");
      return err(res, 400, "Thiếu Dự án tổng");
    }
    const childCode = nextChildCode(parentCode, payload.category);
    const f = payloadToFields(payload);
    db.prepare(
      `INSERT INTO projects (code, parent_code, name, category, region, design_type, contractor, exec_year,
        responsible_unit, responsible_person, priority_level, status, planned_km_or_station, budget_value,
        contract_value, settlement_value, planned_start_date, planned_end_date, actual_start_date, actual_end_date,
        volume_done, progress, cancel_flag, source, version, created_at, updated_at, updated_by)
       VALUES (?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,'form',1,?,?,?)`
    ).run(
      childCode, parentCode, f.name, f.category, f.region, f.design_type, f.contractor, f.exec_year,
      f.responsible_unit, f.responsible_person, f.priority_level, f.status, f.planned_km_or_station, f.budget_value,
      f.contract_value, f.settlement_value, f.planned_start_date, f.planned_end_date, f.actual_start_date, f.actual_end_date,
      f.volume_done, f.progress, f.cancel_flag, now(), now(), req.user.display_name
    );
    replaceTasks(childCode, payload.tasks);
    replaceIssues(childCode, payload.issues, req.user.display_name);
    replaceMaterials(childCode, payload.materials, req.user.display_name);
    logHistory(childCode, req.user.display_name, "create", null, {});
    db.exec("COMMIT");
    broadcastChange({ code: childCode, action: "create", by: req.user.display_name });
    res.json({ ok: true, child_code: childCode, parent_code: parentCode });
  } catch (e) {
    db.exec("ROLLBACK");
    err(res, 500, "Tạo dự án thất bại: " + e.message);
  }
});

// Cac truong "quan trong" cua du an - chi sua duoc khi la admin/manager hoac
// duoc cap quyen MANAGE/FULL tren du an do. Muc UPDATE chi duoc dong vao tien
// do/trang thai/cac truong con lai (xem applyPermissionTierToFields).
const PROJECT_CORE_FIELDS = [
  "name", "category", "region", "design_type", "contractor", "exec_year",
  "responsible_unit", "responsible_person", "priority_level",
  "planned_km_or_station", "budget_value", "contract_value", "settlement_value",
  "planned_start_date", "planned_end_date",
];
// Neu nguoi sua chi co quyen UPDATE (khong phai admin/manager/MANAGE/FULL):
// giu nguyen cac truong "quan trong" nhu du lieu cu, chi cho phep di qua cac
// thay doi ve tien do/trang thai/ngay thuc te - dung nhu dac ta "Cap nhat
// tien do" (khong duoc doi thong tin quan trong cua du an).
function applyPermissionTierToFields(f, row, tier) {
  if (tier === "UPDATE") {
    const restricted = Object.assign({}, f);
    PROJECT_CORE_FIELDS.forEach((field) => {
      restricted[field] = row[field];
    });
    return restricted;
  }
  return f; // admin/manager/MANAGE/FULL: toan quyen cac truong
}

app.put("/api/projects/:code", requireAuth, (req, res) => {
  try {
    const code = decodeURIComponent(req.params.code);
    const row = db.prepare("SELECT * FROM projects WHERE code = ? AND deleted_at IS NULL").get(code);
    if (!row) return err(res, 404, `Không tìm thấy dự án "${code}"`);

    const isFullRole = req.user.role === "admin" || req.user.role === "manager";
    const level = isFullRole ? "FULL" : getProjectPermission(req.user, code);
    if (!level || level === "VIEW") {
      return err(res, 403, "Bạn không có quyền sửa dự án này.");
    }
    // Tuong duong "tier" dung de quyet dinh pham vi duoc sua: UPDATE = chi
    // tien do/trang thai/vuong mac; MANAGE/FULL (hoac admin/manager) = toan
    // quyen sua thong tin + cong viec + vat tu cua du an nay.
    const tier = level === "UPDATE" ? "UPDATE" : "MANAGE";

    const payload = req.body || {};
    const clientVersion = payload.__version;
    if (clientVersion != null && Number(clientVersion) !== row.version) {
      return err(res, 409, "Dữ liệu đã được người dùng khác cập nhật. Vui lòng tải lại trước khi lưu.");
    }
    const f = applyPermissionTierToFields(payloadToFields(payload), row, tier);
    const info = db
      .prepare(
        `UPDATE projects SET name=?, category=?, region=?, design_type=?, contractor=?, exec_year=?,
          responsible_unit=?, responsible_person=?, priority_level=?, status=?, planned_km_or_station=?,
          budget_value=?, contract_value=?, settlement_value=?, planned_start_date=?, planned_end_date=?,
          actual_start_date=?, actual_end_date=?, volume_done=?, progress=?, cancel_flag=?,
          version=version+1, updated_at=?, updated_by=?
         WHERE code=? AND version=?`
      )
      .run(
        f.name, f.category, f.region, f.design_type, f.contractor, f.exec_year,
        f.responsible_unit, f.responsible_person, f.priority_level, f.status, f.planned_km_or_station,
        f.budget_value, f.contract_value, f.settlement_value, f.planned_start_date, f.planned_end_date,
        f.actual_start_date, f.actual_end_date, f.volume_done, f.progress, f.cancel_flag,
        now(), req.user.display_name, code, row.version
      );
    if (info.changes === 0) {
      return err(res, 409, "Dữ liệu đã được người dùng khác cập nhật. Vui lòng tải lại trước khi lưu.");
    }
    // Muc UPDATE: khong duoc dong vao danh sach cong viec / vat tu, chi duoc
    // cap nhat "vuong mac" (issues) nhu dac ta.
    if (tier !== "UPDATE") {
      replaceTasks(code, payload.tasks);
      replaceMaterials(code, payload.materials, req.user.display_name);
    }
    replaceIssues(code, payload.issues, req.user.display_name);
    logHistory(code, req.user.display_name, "update", row, f);
    const newRow = db.prepare("SELECT version FROM projects WHERE code = ?").get(code);
    broadcastChange({ code, action: "update", by: req.user.display_name });
    res.json({ ok: true, child_code: code, version: newRow.version });
  } catch (e) {
    err(res, 500, "Cập nhật dự án thất bại: " + (IS_PROD ? "Đã có lỗi ở máy chủ." : e.message));
  }
});

app.post("/api/projects/:code/clone", requireRole("admin", "manager"), (req, res) => {
  const code = decodeURIComponent(req.params.code);
  const opts = req.body || {};
  const source = db.prepare("SELECT * FROM projects WHERE code = ? AND deleted_at IS NULL").get(code);
  if (!source) return err(res, 404, `Không tìm thấy dự án "${code}"`);
  const newCode = nextChildCode(source.parent_code, source.category);
  db.exec("BEGIN");
  try {
    db.prepare(
      `INSERT INTO projects (code, parent_code, name, category, region, design_type, contractor, exec_year,
        responsible_unit, responsible_person, priority_level, status, planned_km_or_station, budget_value,
        contract_value, settlement_value, planned_start_date, planned_end_date, actual_start_date, actual_end_date,
        volume_done, progress, cancel_flag, source, version, created_at, updated_at, updated_by)
       VALUES (?,?,?,?,?,?,?,?,?,?,?, 'Chưa thực hiện', ?,?,?,?,?,?,NULL,NULL,NULL,0,'Không','form',1,?,?,?)`
    ).run(
      newCode, source.parent_code, source.name, source.category, source.region, source.design_type,
      source.contractor, source.exec_year, source.responsible_unit, source.responsible_person, source.priority_level,
      source.planned_km_or_station, source.budget_value, source.contract_value, source.settlement_value,
      source.planned_start_date, source.planned_end_date,
      now(), now(), req.user.display_name
    );
    if (opts.includeTasks) {
      const tasks = taskRowsFor(code).map((t) => ({ ...t, pct_done: 0, status: "Chưa thực hiện" }));
      replaceTasks(newCode, tasks);
    }
    if (opts.includeMaterials) {
      const mats = db.prepare("SELECT * FROM project_materials WHERE project_code = ?").all(code);
      replaceMaterials(
        newCode,
        mats.map((m) => ({ material_code: m.material_code, material_name: m.material_name, unit: m.unit, planned_qty: m.planned_qty, received_qty: null, used_qty: null, note: m.note })),
        req.user.display_name
      );
    }
    if (opts.includeIssues) {
      const iss = db.prepare("SELECT * FROM project_issues WHERE project_code = ? AND status != 'Đã xử lý'").all(code);
      replaceIssues(
        newCode,
        iss.map((i) => ({ content: i.content, cause: i.cause, severity: i.severity, coordination_unit: i.responsible_unit, responsible_person: i.responsible_person, due_date: i.due_date, status: i.status, note: i.note })),
        req.user.display_name
      );
    }
    logHistory(newCode, req.user.display_name, "clone", null, {});
    db.exec("COMMIT");
    broadcastChange({ code: newCode, action: "clone", by: req.user.display_name });
    res.json({ ok: true, child_code: newCode });
  } catch (e) {
    db.exec("ROLLBACK");
    err(res, 500, "Nhân bản thất bại: " + e.message);
  }
});

app.delete("/api/projects/:code", requireAuth, (req, res) => {
  const code = decodeURIComponent(req.params.code);
  const isFullRole = req.user.role === "admin" || req.user.role === "manager";
  if (!isFullRole && !canDeleteProjectAcl(req.user, code)) {
    return err(res, 403, "Bạn không có quyền xóa dự án này.");
  }
  const row = db.prepare("SELECT * FROM projects WHERE code = ? AND deleted_at IS NULL").get(code);
  if (!row) return err(res, 404, `Không tìm thấy dự án "${code}"`);
  if (!row.parent_code) {
    const remaining = db.prepare("SELECT COUNT(*) c FROM projects WHERE parent_code = ? AND deleted_at IS NULL").get(code);
    if (remaining.c > 0) {
      return err(res, 400, "Dự án tổng này vẫn còn dự án chi tiết bên trong — hãy xóa hết dự án chi tiết trước.");
    }
  }
  db.prepare("UPDATE projects SET deleted_at = ?, deleted_by = ? WHERE code = ?").run(now(), req.user.display_name, code);
  logHistory(code, req.user.display_name, "delete", null, {});
  broadcastChange({ code, action: "delete", by: req.user.display_name });
  res.json({ ok: true });
});

app.get("/api/projects/:code/history", requireAuth, (req, res) => {
  const code = decodeURIComponent(req.params.code);
  const isFullRole = req.user.role === "admin" || req.user.role === "manager";
  if (!isFullRole && !canViewProject(req.user, code)) {
    return err(res, 403, "Bạn không có quyền xem lịch sử dự án này.");
  }
  const rows = db
    .prepare("SELECT * FROM project_history WHERE project_code = ? ORDER BY id DESC LIMIT 200")
    .all(code);
  res.json({ history: rows });
});

app.post("/api/import/preview", requireAuth, (req, res) => {
  err(res, 501, "Chức năng Nhập từ Excel chưa được hỗ trợ ở bản này. Vui lòng thêm/sửa từng dự án bằng form.");
});
app.post("/api/import/commit", requireAuth, (req, res) => {
  err(res, 501, "Chức năng Nhập từ Excel chưa được hỗ trợ ở bản này.");
});
app.get("/api/export", requireAuth, (req, res) => {
  res.json(buildBootstrap(req.user));
});

// ---------------------------------------------------------------------------
// Trang tinh
// ---------------------------------------------------------------------------
app.get("/admin-users.html", requireRole("admin"), (req, res) => {
  res.sendFile(ADMIN_HTML);
});
app.get(/^\/(?!api\/).*/, (req, res) => {
  res.sendFile(PUBLIC_HTML);
});

// API khong khop route nao o tren -> tra JSON 404 (thay vi trang HTML 404
// mac dinh cua Express, de fetch() phia client luon parse duoc .json()).
app.use("/api", (req, res) => {
  res.status(404).json({ error: "Không tìm thấy API." });
});

// Loi bat bat ngo (unhandled) o bat ky route nao o tren: tra ve JSON gon
// gang thay vi trang loi HTML mac dinh cua Express (rat de lo ca duong dan
// file server that len nguoi dung/console trinh duyet o che do khong phai
// production). Log day du ra console server de con debug.
app.use((errObj, req, res, next) => {
  console.error("Unhandled error:", errObj);
  if (res.headersSent) return next(errObj);
  res.status(500).json({
    error: IS_PROD ? "Đã có lỗi xảy ra ở máy chủ." : String((errObj && errObj.message) || errObj),
  });
});

app.listen(PORT, () => {
  console.log(`QL TKM Web App đang chạy tại http://localhost:${PORT}`);
});
