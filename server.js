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
const PROGRESS_HTML = path.join(__dirname, "progress-tasks.html");
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
function taskRowsFor(code) {
  return db
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
// ---------------------------------------------------------------------------
// Bang tien do CHI TIET (WBS) - "bang tien do chi tiet" theo tung dau muc
// cong viec, co san tu file Excel goc (4 giai doan). % hoan thanh CHUNG cua
// ca du an = tong (weight_pct * pct_done) tren TOAN BO cac dong cua du an
// do (khong phai chi trong 1 giai doan) - dung boi ca 2 noi: hien thi lai
// cho dung o tab "Tien do" (xem buildBootstrap) va tinh lai cot progress
// trong bang projects moi khi co dong duoc sua (xem PUT .../progress-tasks).
// ---------------------------------------------------------------------------
function progressBreakdownRowsFor(code) {
  return db
    .prepare("SELECT * FROM project_progress_tasks WHERE project_code = ? ORDER BY stage_no, stt")
    .all(code);
}
function computeProgressFromBreakdown(code) {
  const rows = progressBreakdownRowsFor(code);
  if (!rows.length) return null; // du an nay chua co bang WBS (vd du an tu tao qua form) -> giu co che cu
  let sum = 0;
  rows.forEach((r) => (sum += (r.weight_pct || 0) * (r.pct_done || 0)));
  return Math.max(0, Math.min(1, sum));
}
// ---------------------------------------------------------------------------
// Du bao "thoi gian hoan thanh" cua 1 du an chi tiet tu bang tien do chi tiet
// (WBS) - theo lua chon cua nguoi dung:
//  - Da hoan thanh 100%: lay Ngay ket thuc THUC TE (actual_end) muon nhat
//    trong cac dong lam "Ngay hoan thanh du an".
//  - Chua hoan thanh 100%: DU KIEN ngay hoan thanh = ngoai suy tu TOC DO tien
//    do hien tai, tinh tu Ngay bat dau tham chieu (uu tien Ngay bat dau THUC
//    TE som nhat da nhap; neu chua co thi lay Ngay bat dau KE HOACH som
//    nhat): so ngay da trai qua / % da lam = tong so ngay can, cong vao Ngay
//    bat dau tham chieu ra Ngay du kien hoan thanh.
//  - Ngoai ra van tra ve them Ngay ket thuc KE HOACH tre nhat (planned_end)
//    de nguoi dung tu so sanh som/dung han/tre han voi ngay du kien/thuc te.
// ---------------------------------------------------------------------------
function computeTimelineForCode(code) {
  const rows = progressBreakdownRowsFor(code);
  if (!rows.length) return null;
  const overall_progress = computeProgressFromBreakdown(code) || 0;
  const plannedStarts = rows.map((r) => r.planned_start).filter(Boolean).sort();
  const plannedEnds = rows.map((r) => r.planned_end).filter(Boolean).sort();
  const actualStarts = rows.map((r) => r.actual_start).filter(Boolean).sort();
  const actualEnds = rows.map((r) => r.actual_end).filter(Boolean).sort();
  const referenceStart = actualStarts[0] || plannedStarts[0] || null;
  const plannedCompletionDate = plannedEnds.length ? plannedEnds[plannedEnds.length - 1] : null;
  const base = { overall_progress, reference_start_date: referenceStart, planned_completion_date: plannedCompletionDate };

  if (overall_progress >= 0.999) {
    const doneDate = actualEnds.length ? actualEnds[actualEnds.length - 1] : null;
    return Object.assign({}, base, {
      status: "completed",
      completion_date: doneDate,
      note: doneDate ? null : "Đã đạt 100% nhưng chưa nhập đủ Ngày kết thúc thực tế cho các công việc.",
    });
  }
  if (!referenceStart) {
    return Object.assign({}, base, {
      status: "insufficient_data",
      completion_date: null,
      note: "Chưa nhập Ngày bắt đầu (kế hoạch hoặc thực tế) cho công việc nào để dự báo.",
    });
  }
  if (overall_progress <= 0) {
    return Object.assign({}, base, {
      status: "insufficient_data",
      completion_date: null,
      note: "Chưa có khối lượng hoàn thành nào để tính tốc độ tiến độ.",
    });
  }
  const startMs = Date.parse(referenceStart + "T00:00:00Z");
  if (Number.isNaN(startMs)) {
    return Object.assign({}, base, { status: "insufficient_data", completion_date: null, note: "Ngày bắt đầu không hợp lệ." });
  }
  const elapsedDays = (Date.now() - startMs) / 86400000;
  if (elapsedDays <= 0) {
    return Object.assign({}, base, {
      status: "insufficient_data",
      completion_date: null,
      note: "Ngày bắt đầu đang ở tương lai so với hôm nay.",
    });
  }
  const totalDaysNeeded = elapsedDays / overall_progress;
  const projDate = new Date(startMs + totalDaysNeeded * 86400000).toISOString().slice(0, 10);
  return Object.assign({}, base, { status: "projected", completion_date: projDate, note: null });
}
// Gop "thoi gian hoan thanh" len cap DU AN TONG (cha): theo lua chon cua
// nguoi dung, du an TONG duoc coi la hoan thanh khi TAT CA du an chi tiet
// (con) cua no hoan thanh 100% -> Ngay hoan thanh cua du an TONG = ngay hoan
// thanh (thuc te hoac du kien) MUON NHAT trong so cac du an con.
function computeParentTimeline(parentCode) {
  const children = db
    .prepare("SELECT code FROM projects WHERE parent_code = ? AND deleted_at IS NULL AND source = 'excel'")
    .all(parentCode);
  const items = children
    .map((c) => ({ code: c.code, timeline: computeTimelineForCode(c.code) }))
    .filter((x) => x.timeline);
  if (!items.length) return null;
  const allCompleted = items.every((x) => x.timeline.status === "completed");
  const missing = items.filter((x) => x.timeline.status === "insufficient_data").map((x) => x.code);
  const dated = items.filter((x) => x.timeline.completion_date);
  const completion_date = dated.length
    ? dated.map((x) => x.timeline.completion_date).sort().slice(-1)[0]
    : null;
  return {
    status: allCompleted ? "completed" : dated.length ? "projected" : "insufficient_data",
    completion_date,
    total_children: items.length,
    completed_children: items.filter((x) => x.timeline.status === "completed").length,
    missing_data_children: missing,
    children: items.map((x) => ({ code: x.code, status: x.timeline.status, completion_date: x.timeline.completion_date })),
  };
}
function progressBreakdownGrouped(code) {
  const rows = progressBreakdownRowsFor(code);
  const stagesMap = new Map();
  rows.forEach((r) => {
    if (!stagesMap.has(r.stage_no)) {
      stagesMap.set(r.stage_no, { stage_no: r.stage_no, stage_name: r.stage_name, weight_pct: 0, pct_of_package: 0, tasks: [] });
    }
    const stage = stagesMap.get(r.stage_no);
    stage.weight_pct += r.weight_pct || 0;
    stage.pct_of_package += (r.weight_pct || 0) * (r.pct_done || 0);
    stage.tasks.push({
      id: r.id,
      stt: r.stt,
      task_name: r.task_name,
      unit: r.unit,
      weight_pct: r.weight_pct,
      status: r.status,
      pct_done: r.pct_done,
      pct_of_package: (r.weight_pct || 0) * (r.pct_done || 0),
      planned_start: r.planned_start,
      planned_end: r.planned_end,
      actual_start: r.actual_start,
      actual_end: r.actual_end,
      note: r.note,
    });
  });
  const stages = Array.from(stagesMap.values()).sort((a, b) => a.stage_no - b.stage_no);
  let overall = 0;
  stages.forEach((s) => (overall += s.pct_of_package));
  return { stages, overall_progress: Math.max(0, Math.min(1, overall)) };
}
// Ghi de "detail.stages" + "progress"/"stageN_pct" cua 1 rawChild (doc thang
// tu raw_excel_json, von la ban chup dong bang tu Excel, khong bao gio tu
// thay doi) bang du lieu SONG hien tai trong bang project_progress_tasks, de
// tab "Tien do" tren giao dien luon hien dung so moi nhat sau khi ai do sua
// qua trang "Sua tien do chi tiet" - khong can dung/sua gi ben trong file
// public_index.html (ma React da dong goi san).
function applyLiveProgressBreakdown(rawChild, code) {
  const rows = progressBreakdownRowsFor(code);
  if (!rows.length) return rawChild; // du an nay chua co WBS -> giu nguyen nhu cu
  const { stages, overall_progress } = progressBreakdownGrouped(code);
  if (rawChild.detail && Array.isArray(rawChild.detail.stages)) {
    rawChild.detail.stages = stages.map((s) => ({
      stage_name: s.stage_name,
      weight_pct: s.weight_pct,
      pct_of_package: s.pct_of_package,
      tasks: s.tasks.map((t) => ({
        stt: t.stt,
        task_name: t.task_name,
        unit: t.unit,
        weight_pct: t.weight_pct,
        status: t.status,
        pct_done: t.pct_done,
        pct_of_package: t.pct_of_package,
        planned_start: t.planned_start,
        planned_end: t.planned_end,
        planned_actual: null,
        actual_start: t.actual_start,
        actual_end: t.actual_end,
        actual_actual: null,
        evaluation: null,
        documents: null,
        description: t.note,
      })),
    }));
  }
  rawChild.progress = overall_progress;
  stages.forEach((s, idx) => {
    rawChild["stage" + (idx + 1) + "_pct"] = s.weight_pct > 0 ? s.pct_of_package / s.weight_pct : 0;
  });
  return rawChild;
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
        let rawChild = JSON.parse(r.raw_excel_json);
        rawChild = applyLiveProgressBreakdown(rawChild, r.code);
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
      mt.received_qty === "" || mt.received_qty == null ? null : Number(mt.received_qty),
      mt.used_qty === "" || mt.used_qty == null ? null : Number(mt.used_qty),
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
    // Neu du an nay da co "bang tien do chi tiet" (WBS, xem mo ta o
    // computeProgressFromBreakdown), % hoan thanh PHAI luon duoc tinh tu
    // bang do - bo qua gia tri "% hoan thanh" ma form chinh sua chung (thanh
    // truot cu) gui len, de tranh 2 noi cung sua 1 con so gay lech nhau.
    // Muon doi tien do cho du an loai nay, dung API
    // PUT /api/projects/:code/progress-tasks (trang "Sua tien do chi tiet").
    const breakdownProgress = computeProgressFromBreakdown(code);
    if (breakdownProgress != null) f.progress = breakdownProgress;
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

// ---------------------------------------------------------------------------
// Bang tien do CHI TIET (WBS) cua 1 du an chi tiet - xem/sua tung dau muc
// cong viec (4 giai doan) de he thong tu tinh lai % hoan thanh chung, thay
// vi phai keo tay thanh truot "% hoan thanh" nhu truoc. Quyen sua: giong het
// quyen "Cap nhat tien do" (UPDATE) tro len - dung nhu ten muc quyen do.
// ---------------------------------------------------------------------------
app.get("/api/projects/:code/progress-tasks", requireAuth, (req, res) => {
  const code = decodeURIComponent(req.params.code);
  const row = db.prepare("SELECT code FROM projects WHERE code = ? AND deleted_at IS NULL").get(code);
  if (!row) return err(res, 404, `Không tìm thấy dự án "${code}"`);
  if (!canViewProject(req.user, code)) {
    return err(res, 403, "Bạn không có quyền xem dự án này.");
  }
  const { stages, overall_progress } = progressBreakdownGrouped(code);
  if (!stages.length) {
    return err(res, 404, "Dự án này chưa có bảng tiến độ chi tiết (chỉ áp dụng cho dự án chi tiết lấy từ Excel gốc).");
  }
  res.json({ code, stages, overall_progress, timeline: computeTimelineForCode(code) });
});

app.put("/api/projects/:code/progress-tasks", requireAuth, (req, res) => {
  const code = decodeURIComponent(req.params.code);
  const row = db.prepare("SELECT * FROM projects WHERE code = ? AND deleted_at IS NULL").get(code);
  if (!row) return err(res, 404, `Không tìm thấy dự án "${code}"`);
  if (!canUpdateProject(req.user, code)) {
    return err(res, 403, "Bạn không có quyền cập nhật tiến độ dự án này.");
  }
  const items = Array.isArray(req.body && req.body.tasks) ? req.body.tasks : null;
  if (!items || !items.length) return err(res, 400, 'Dữ liệu không hợp lệ - cần một mảng "tasks": [{ id, status, pct_done }].');

  // Ngay thang: chi nhan dinh dang "YYYY-MM-DD" (input type=date) hoac rong
  // (= xoa ngay). Gia tri sai dinh dang -> tra ve loi (khong am tham bo qua),
  // de nguoi dung biet ma sua lai.
  const DATE_RE = /^\d{4}-\d{2}-\d{2}$/;
  function normDate(v) {
    if (v === undefined || v === null || v === "") return null;
    const s = String(v).trim();
    return DATE_RE.test(s) ? s : false;
  }

  const upd = db.prepare(
    `UPDATE project_progress_tasks
       SET status = ?, pct_done = ?, planned_start = ?, planned_end = ?, actual_start = ?, actual_end = ?, updated_at = ?
       WHERE id = ? AND project_code = ?`
  );
  const ts = now();
  db.exec("BEGIN");
  try {
    for (const it of items) {
      const id = Number(it.id);
      let pct = Number(it.pct_done);
      if (!id || Number.isNaN(pct)) {
        db.exec("ROLLBACK");
        return err(res, 400, `Dữ liệu không hợp lệ cho dòng id=${it.id}.`);
      }
      pct = Math.max(0, Math.min(1, pct));
      const status = String(it.status || (pct >= 1 ? "Hoàn thành" : pct > 0 ? "Đang thực hiện" : "Chưa thực hiện"));
      const planned_start = normDate(it.planned_start);
      const planned_end = normDate(it.planned_end);
      const actual_start = normDate(it.actual_start);
      const actual_end = normDate(it.actual_end);
      if (planned_start === false || planned_end === false || actual_start === false || actual_end === false) {
        db.exec("ROLLBACK");
        return err(res, 400, `Ngày không hợp lệ ở dòng id=${id} (định dạng phải là YYYY-MM-DD).`);
      }
      const info = upd.run(status, pct, planned_start, planned_end, actual_start, actual_end, ts, id, code);
      if (info.changes === 0) {
        db.exec("ROLLBACK");
        return err(res, 400, `Không tìm thấy dòng tiến độ id=${id} thuộc dự án "${code}".`);
      }
    }
    const newProgress = computeProgressFromBreakdown(code);
    if (newProgress != null) {
      const info = db
        .prepare("UPDATE projects SET progress = ?, version = version + 1, updated_at = ?, updated_by = ? WHERE code = ? AND version = ?")
        .run(newProgress, ts, req.user.display_name, code, row.version);
      if (info.changes === 0) {
        db.exec("ROLLBACK");
        return err(res, 409, "Dữ liệu đã được người dùng khác cập nhật. Vui lòng tải lại trước khi lưu.");
      }
    }
    db.exec("COMMIT");
    logHistory(code, req.user.display_name, "update", row, { progress: newProgress });
    broadcastChange({ code, action: "update", by: req.user.display_name });
    res.json({ ok: true, code, progress: newProgress, timeline: computeTimelineForCode(code) });
  } catch (e) {
    db.exec("ROLLBACK");
    err(res, 500, "Cập nhật tiến độ chi tiết thất bại: " + (IS_PROD ? "Đã có lỗi ở máy chủ." : e.message));
  }
});

// Thoi gian hoan thanh: dung chung cho ca DU AN CHI TIET (tinh tu bang WBS
// cua chinh no) lan DU AN TONG (gop tu tat ca du an con - xem
// computeParentTimeline). Chi can 1 endpoint, FE tu hien thi khac nhau theo
// "is_parent".
app.get("/api/projects/:code/timeline", requireAuth, (req, res) => {
  const code = decodeURIComponent(req.params.code);
  const row = db.prepare("SELECT * FROM projects WHERE code = ? AND deleted_at IS NULL").get(code);
  if (!row) return err(res, 404, `Không tìm thấy dự án "${code}"`);
  if (!canViewProject(req.user, code)) {
    return err(res, 403, "Bạn không có quyền xem dự án này.");
  }
  if (!row.parent_code) {
    const rollup = computeParentTimeline(code);
    if (!rollup) return err(res, 404, "Dự án tổng này chưa có dự án chi tiết nào có bảng tiến độ chi tiết.");
    return res.json(Object.assign({ code, is_parent: true }, rollup));
  }
  const timeline = computeTimelineForCode(code);
  if (!timeline) return err(res, 404, "Dự án này chưa có bảng tiến độ chi tiết.");
  res.json(Object.assign({ code, is_parent: false }, timeline));
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
app.get("/progress-tasks.html", requireAuth, (req, res) => {
  res.sendFile(PROGRESS_HTML);
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
