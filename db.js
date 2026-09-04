// ============================================================================
// QL Tien do Du an TKM - Lop Database (SQLite, dung module node:sqlite co san
// tu Node 22, khong can bien dich native nen cai dat don gian tren moi may).
// ============================================================================
const { DatabaseSync } = require("node:sqlite");
const path = require("path");
const fs = require("fs");
const bcrypt = require("bcryptjs");

const DB_FILE = path.join(__dirname, "data", "qltkm.db");
const SEED_FILE = path.join(__dirname, "data", "seed_data.json");
const isNew = !fs.existsSync(DB_FILE);

const db = new DatabaseSync(DB_FILE);
db.exec("PRAGMA journal_mode = WAL;");
db.exec("PRAGMA foreign_keys = ON;");

db.exec(`
CREATE TABLE IF NOT EXISTS users (
  id INTEGER PRIMARY KEY AUTOINCREMENT,
  username TEXT NOT NULL UNIQUE,
  password_hash TEXT NOT NULL,
  display_name TEXT NOT NULL,
  role TEXT NOT NULL CHECK(role IN ('admin','manager','responsible','viewer')),
  active INTEGER NOT NULL DEFAULT 1,
  created_at TEXT NOT NULL
);

CREATE TABLE IF NOT EXISTS sessions (
  token TEXT PRIMARY KEY,
  user_id INTEGER NOT NULL REFERENCES users(id),
  created_at TEXT NOT NULL,
  expires_at TEXT NOT NULL
);

CREATE TABLE IF NOT EXISTS projects (
  code TEXT PRIMARY KEY,
  parent_code TEXT REFERENCES projects(code),
  name TEXT NOT NULL,
  category TEXT,
  region TEXT,
  design_type TEXT,
  contractor TEXT,
  exec_year TEXT,
  responsible_unit TEXT,
  responsible_person TEXT,
  priority_level TEXT,
  status TEXT,
  planned_km_or_station REAL,
  budget_value REAL,
  contract_value REAL,
  settlement_value REAL,
  planned_start_date TEXT,
  planned_end_date TEXT,
  actual_start_date TEXT,
  actual_end_date TEXT,
  volume_done REAL,
  progress REAL DEFAULT 0,
  cancel_flag TEXT DEFAULT 'Không',
  note TEXT,
  source TEXT NOT NULL DEFAULT 'form',
  raw_excel_json TEXT,
  version INTEGER NOT NULL DEFAULT 1,
  created_at TEXT NOT NULL,
  updated_at TEXT NOT NULL,
  updated_by TEXT,
  deleted_at TEXT,
  deleted_by TEXT
);
CREATE INDEX IF NOT EXISTS idx_projects_parent ON projects(parent_code);
CREATE INDEX IF NOT EXISTS idx_projects_status ON projects(status);
CREATE INDEX IF NOT EXISTS idx_projects_responsible ON projects(responsible_person);

CREATE TABLE IF NOT EXISTS project_tasks (
  id INTEGER PRIMARY KEY AUTOINCREMENT,
  project_code TEXT NOT NULL REFERENCES projects(code) ON DELETE CASCADE,
  task_name TEXT NOT NULL,
  responsible_person TEXT,
  start_date TEXT,
  due_date TEXT,
  pct_done REAL DEFAULT 0,
  status TEXT DEFAULT 'Chưa thực hiện',
  note TEXT,
  sort_order INTEGER DEFAULT 0,
  created_at TEXT NOT NULL,
  updated_at TEXT NOT NULL
);
CREATE INDEX IF NOT EXISTS idx_tasks_project ON project_tasks(project_code);

CREATE TABLE IF NOT EXISTS project_issues (
  id INTEGER PRIMARY KEY AUTOINCREMENT,
  project_code TEXT NOT NULL REFERENCES projects(code) ON DELETE CASCADE,
  content TEXT NOT NULL,
  cause TEXT,
  severity TEXT DEFAULT 'Trung bình',
  responsible_unit TEXT,
  responsible_person TEXT,
  due_date TEXT,
  status TEXT DEFAULT 'Chưa xử lý',
  note TEXT,
  source TEXT DEFAULT 'Nhập tay qua Form',
  created_at TEXT NOT NULL,
  updated_at TEXT NOT NULL,
  created_by TEXT
);
CREATE INDEX IF NOT EXISTS idx_issues_project ON project_issues(project_code);

CREATE TABLE IF NOT EXISTS project_materials (
  id INTEGER PRIMARY KEY AUTOINCREMENT,
  project_code TEXT NOT NULL REFERENCES projects(code) ON DELETE CASCADE,
  material_code TEXT,
  material_name TEXT NOT NULL,
  unit TEXT,
  planned_qty REAL,
  received_qty REAL,
  used_qty REAL,
  note TEXT,
  updated_at TEXT NOT NULL,
  updated_by TEXT
);
CREATE INDEX IF NOT EXISTS idx_materials_project ON project_materials(project_code);

CREATE TABLE IF NOT EXISTS project_members (
  id INTEGER PRIMARY KEY AUTOINCREMENT,
  project_code TEXT NOT NULL REFERENCES projects(code) ON DELETE CASCADE,
  user_id INTEGER NOT NULL REFERENCES users(id) ON DELETE CASCADE,
  UNIQUE(project_code, user_id)
);
CREATE INDEX IF NOT EXISTS idx_members_project ON project_members(project_code);
CREATE INDEX IF NOT EXISTS idx_members_user ON project_members(user_id);

-- Phan quyen chi tiet theo TUNG DU AN cho tung nguoi dung (RBAC nang cao).
-- Chi ap dung cho vai tro 'responsible' va 'viewer' - admin/manager luon
-- toan quyen moi du an nhu truoc, khong bi anh huong boi bang nay.
-- permission_level, tu thap den cao:
--   VIEW   : chi xem du an (thong tin, tien do, cong viec, vuong mac)
--   UPDATE : xem + cap nhat tien do/trang thai/vuong mac (khong sua thong
--            tin quan trong, khong dong/sua danh sach cong viec, khong vat tu)
--   MANAGE : xem + sua thong tin du an + quan ly cong viec + quan ly vat tu
--   FULL   : nhu MANAGE, cong them duoc xoa chinh du an chi tiet nay
CREATE TABLE IF NOT EXISTS user_project_permissions (
  id INTEGER PRIMARY KEY AUTOINCREMENT,
  user_id INTEGER NOT NULL REFERENCES users(id) ON DELETE CASCADE,
  project_code TEXT NOT NULL REFERENCES projects(code) ON DELETE CASCADE,
  permission_level TEXT NOT NULL CHECK(permission_level IN ('VIEW','UPDATE','MANAGE','FULL')),
  created_at TEXT NOT NULL,
  updated_at TEXT NOT NULL,
  UNIQUE(user_id, project_code)
);
CREATE INDEX IF NOT EXISTS idx_upp_user ON user_project_permissions(user_id);
CREATE INDEX IF NOT EXISTS idx_upp_project ON user_project_permissions(project_code);

CREATE TABLE IF NOT EXISTS project_history (
  id INTEGER PRIMARY KEY AUTOINCREMENT,
  project_code TEXT,
  user_name TEXT NOT NULL,
  action TEXT NOT NULL,
  field_changed TEXT,
  old_value TEXT,
  new_value TEXT,
  created_at TEXT NOT NULL
);
CREATE INDEX IF NOT EXISTS idx_history_project ON project_history(project_code);

CREATE TABLE IF NOT EXISTS categories (
  id INTEGER PRIMARY KEY AUTOINCREMENT,
  cat_key TEXT NOT NULL,
  value TEXT NOT NULL,
  UNIQUE(cat_key, value)
);
`);

// ---------------------------------------------------------------------------
// Khoi tao du lieu ban dau (chi chay 1 lan, khi database chua ton tai truoc do)
// ---------------------------------------------------------------------------
function seedIfNew() {
  if (!isNew) return;
  console.log("Lần đầu chạy: đang nạp dữ liệu gốc từ Excel vào database...");
  const seed = JSON.parse(fs.readFileSync(SEED_FILE, "utf8"));
  const now = new Date().toISOString();

  const PROJECT_COLUMNS = [
    "code", "parent_code", "name", "category", "region", "design_type", "contractor",
    "exec_year", "responsible_unit", "responsible_person", "priority_level", "status",
    "planned_km_or_station", "budget_value", "contract_value", "settlement_value",
    "planned_start_date", "planned_end_date", "actual_start_date", "actual_end_date",
    "volume_done", "progress", "cancel_flag", "source", "raw_excel_json",
    "created_at", "updated_at", "updated_by",
  ];
  const insertProject = db.prepare(
    `INSERT INTO projects (${PROJECT_COLUMNS.join(", ")}, version) VALUES (${PROJECT_COLUMNS.map(() => "?").join(",")}, 1)`
  );
  // Chen 1 dong project bang OBJECT co ten truong ro rang (khong dua theo vi
  // tri) de tranh dem nham so luong tham so khi co hang chuc cot.
  function insertProjectRow(fields) {
    const args = PROJECT_COLUMNS.map((col) => (col in fields ? fields[col] : null));
    insertProject.run(...args);
  }

  db.exec("BEGIN");
  try {
    for (const p of seed.parents || []) {
      insertProjectRow({
        code: p.parent_code,
        parent_code: null,
        name: p.parent_name || p.parent_code,
        cancel_flag: "Không",
        source: "excel",
        raw_excel_json: JSON.stringify(p),
        created_at: now,
        updated_at: now,
        updated_by: "excel-import",
      });
    }
    for (const c of seed.children || []) {
      insertProjectRow({
        code: c.child_code,
        parent_code: c.parent_code,
        name: c.child_name || c.child_code,
        category: c.category,
        region: c.region,
        design_type: c.design_type,
        contractor: c.contractor,
        exec_year: c.exec_year,
        status: c.status || "Chưa thực hiện",
        planned_km_or_station: c.planned_km_or_station ?? null,
        budget_value: c.budget_value ?? null,
        contract_value: c.contract_value ?? null,
        settlement_value: c.settlement_value ?? null,
        volume_done: c.volume_done ?? null,
        progress: c.progress ?? 0,
        cancel_flag: c.cancel_flag || "Không",
        source: "excel",
        raw_excel_json: JSON.stringify(c),
        created_at: now,
        updated_at: now,
        updated_by: "excel-import",
      });
    }
    const cats = seed.categories || {};
    const insertCat = db.prepare("INSERT OR IGNORE INTO categories (cat_key, value) VALUES (?,?)");
    for (const key of Object.keys(cats)) {
      for (const v of cats[key] || []) insertCat.run(key, v);
    }
    db.exec("COMMIT");
  } catch (e) {
    db.exec("ROLLBACK");
    throw e;
  }

  // Tai khoan quan tri mac dinh - PHAI doi mat khau ngay sau khi dang nhap lan dau.
  const adminHash = bcrypt.hashSync("admin123", 10);
  db.prepare(
    "INSERT INTO users (username, password_hash, display_name, role, active, created_at) VALUES (?,?,?,?,1,?)"
  ).run("admin", adminHash, "Quản trị viên", "admin", now);

  console.log("Đã tạo xong database. Tài khoản đăng nhập đầu tiên: admin / admin123 (đổi mật khẩu ngay).");
}

// ---------------------------------------------------------------------------
// Nang cap du lieu cu (idempotent, an toan chay lai nhieu lan): moi ban ghi
// project_members (phan cong kieu cu, chi co "duoc sua hay khong") duoc quy
// doi sang 1 dong trong user_project_permissions voi muc UPDATE - dung bang
// muc quyen chinh sua ma nguoi "phu trach" dang co truoc day, de khong ai bi
// mat quyen dang dung khi nang cap len ban co ACL chi tiet nay.
// ---------------------------------------------------------------------------
function migrateLegacyMembersToPermissions() {
  const legacyRows = db.prepare("SELECT project_code, user_id FROM project_members").all();
  if (!legacyRows.length) return;
  const ts = new Date().toISOString();
  const ins = db.prepare(
    `INSERT INTO user_project_permissions (user_id, project_code, permission_level, created_at, updated_at)
     VALUES (?,?,'UPDATE',?,?)
     ON CONFLICT(user_id, project_code) DO NOTHING`
  );
  for (const r of legacyRows) ins.run(r.user_id, r.project_code, ts, ts);
}

seedIfNew();
migrateLegacyMembersToPermissions();

module.exports = { db };
