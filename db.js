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

// ---------------------------------------------------------------------------
// [CHAN DOAN KHOI DONG - CHI GHI LOG, KHONG DOI HANH VI]
// In ra Railway Logs (hoac console khi chay local) day du thong tin de biet
// CHAC CHAN server dang mo file DB o dau va co dang bi "mat du lieu giua cac
// lan deploy" hay khong - khong ghi/sua/xoa gi vao database ca, khong log bat
// ky secret/token/mat khau nao. Dat TRUOC khi mo DatabaseSync() de kich thuoc
// file/trang thai "da ton tai hay chua" phan anh dung THOI DIEM TRUOC khi mo
// (mo SQLite se tu tao file moi neu chua co, nen phai kiem tra truoc do).
// ---------------------------------------------------------------------------
(function logStorageDiagnostics() {
  const dataDir = path.join(__dirname, "data");
  let dbSizeBytes = null;
  try {
    if (fs.existsSync(DB_FILE)) dbSizeBytes = fs.statSync(DB_FILE).size;
  } catch {
    // Bo qua loi doc kich thuoc file - khong lam gian doan qua trinh mo DB.
  }
  console.log("========== [CHAN DOAN LUU TRU - KHOI DONG SERVER] ==========");
  console.log("process.cwd()              =", process.cwd());
  console.log("__dirname (db.js)          =", __dirname);
  console.log("DB_FILE                    =", DB_FILE);
  console.log("Thư mục data/ tồn tại?     =", fs.existsSync(dataDir));
  console.log(
    "File DB đã tồn tại trước khi mở? =",
    !isNew,
    isNew ? "  => SẼ TẠO DATABASE MỚI + NẠP SEED (xem cảnh báo bên dưới nếu không phải lần đầu chạy)" : "  => mở file DB đã có sẵn, GIỮ NGUYÊN dữ liệu"
  );
  console.log("Kích thước file DB hiện tại =", dbSizeBytes === null ? "(chưa tồn tại / không đọc được)" : `${dbSizeBytes} bytes`);
  console.log("RAILWAY_VOLUME_NAME        =", process.env.RAILWAY_VOLUME_NAME || "(không đặt)");
  console.log("RAILWAY_VOLUME_MOUNT_PATH  =", process.env.RAILWAY_VOLUME_MOUNT_PATH || "(không đặt)");
  console.log("RAILWAY_ENVIRONMENT        =", process.env.RAILWAY_ENVIRONMENT || "(không đặt - có thể đang chạy ngoài Railway)");
  if (isNew) {
    console.warn(
      "CẢNH BÁO: Không tìm thấy file DB tại đường dẫn DB_FILE ở trên vào lúc " +
        "khởi động - hệ thống sẽ coi đây là LẦN ĐẦU CHẠY và tạo database mới " +
        "kèm nạp lại dữ liệu gốc từ data/seed_data.json. Nếu đây KHÔNG phải " +
        "lần đầu chạy server (tức là trước đó server đã từng chạy và có dữ " +
        "liệu thật), hãy DỪNG LẠI NGAY và kiểm tra cấu hình Railway Volume - " +
        "rất có thể Volume chưa được gắn đúng vào thư mục data/ ở trên, dẫn " +
        "đến việc mỗi lần deploy lại là một lần \"mất trắng\" dữ liệu cũ."
    );
  }
  console.log("=============================================================");
})();

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

-- [LEGACY / DEPRECATED] Co che phan quyen theo du an KIEU CU (chi co
-- "duoc/khong duoc sua", khong phan biet muc do). KHONG con la nguon quyen
-- chinh thuc - nguon quyen chinh thuc bay gio la user_project_permissions +
-- user_task_permissions (xem chu thich o duoi). Bang nay va du lieu trong no
-- duoc GIU NGUYEN (khong xoa bang, khong xoa du lieu) de tuong thich nguoc
-- va co the doi chieu/khoi phuc neu can, nhung KHONG con duoc bat ky logic
-- phan quyen nao trong server.js/auth.js su dung de cap quyen thuc te nua.
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

-- Giai doan 1 (nang cap phan quyen theo TUNG CONG VIEC/TASK ben trong 1 du
-- an). Bang nay la TUY CHON: mac dinh (khong co dong nao cho 1 cap
-- user+project) nghia la user duoc thao tac tren TAT CA task cua du an do,
-- dung muc quyen da cap o user_project_permissions (KHONG doi hanh vi dang
-- chay). Chi khi admin chu dong gioi han ("Chon task cu the") thi moi co
-- dong duoc them vao day - luc do user CHI duoc thao tac dung nhung task
-- duoc liet ke, o day (mac dinh = bang dung muc quyen project, khong the
-- vuot qua - xem rang buoc kiem tra o server.js/auth.js).
-- task_id tham chieu project_progress_tasks(id) - day chinh la bang "cong
-- viec/dau muc tien do" hien dang dung o trang "Sua tien do chi tiet".
CREATE TABLE IF NOT EXISTS user_task_permissions (
  id INTEGER PRIMARY KEY AUTOINCREMENT,
  user_id INTEGER NOT NULL REFERENCES users(id) ON DELETE CASCADE,
  project_code TEXT NOT NULL REFERENCES projects(code) ON DELETE CASCADE,
  task_id INTEGER NOT NULL REFERENCES project_progress_tasks(id) ON DELETE CASCADE,
  permission_level TEXT NOT NULL CHECK(permission_level IN ('VIEW','UPDATE','MANAGE','FULL')),
  created_at TEXT NOT NULL,
  updated_at TEXT NOT NULL,
  created_by TEXT,
  UNIQUE(user_id, project_code, task_id)
);
CREATE INDEX IF NOT EXISTS idx_utp_user ON user_task_permissions(user_id);
CREATE INDEX IF NOT EXISTS idx_utp_project ON user_task_permissions(project_code);
CREATE INDEX IF NOT EXISTS idx_utp_task ON user_task_permissions(task_id);
CREATE INDEX IF NOT EXISTS idx_utp_user_project ON user_task_permissions(user_id, project_code);

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

-- Bang tien do CHI TIET theo tung dau muc cong viec (WBS) cua 1 du an chi
-- tiet - day chinh la "bang tien do chi tiet" da co san tu file Excel goc
-- (4 giai doan x nhieu dau muc, moi dau muc co trong so weight_pct rieng,
-- cong don lai dung 100% cho ca du an). % hoan thanh CHUNG cua du an =
-- SUM(weight_pct * pct_done) tren toan bo cac dong cua du an do - xem ham
-- computeProgressFromBreakdown() trong server.js. Sua pct_done/status o day
-- se tu dong tinh lai % hoan thanh chung, khong con phai keo tay nua.
CREATE TABLE IF NOT EXISTS project_progress_tasks (
  id INTEGER PRIMARY KEY AUTOINCREMENT,
  project_code TEXT NOT NULL REFERENCES projects(code) ON DELETE CASCADE,
  stage_no INTEGER NOT NULL,
  stage_name TEXT NOT NULL,
  stt INTEGER NOT NULL,
  task_name TEXT NOT NULL,
  unit TEXT,
  weight_pct REAL NOT NULL DEFAULT 0,
  status TEXT NOT NULL DEFAULT 'Chưa thực hiện',
  pct_done REAL NOT NULL DEFAULT 0,
  planned_start TEXT,
  planned_end TEXT,
  actual_start TEXT,
  actual_end TEXT,
  note TEXT,
  created_at TEXT NOT NULL,
  updated_at TEXT NOT NULL,
  UNIQUE(project_code, stt)
);
CREATE INDEX IF NOT EXISTS idx_ppt_project ON project_progress_tasks(project_code);
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
// [LEGACY / DEPRECATED - CHI con giu lai de tham khao, KHONG con duoc goi
// tu dong nua - xem ghi chu duoi cung file nay]
// Nang cap du lieu cu (idempotent, an toan chay lai nhieu lan): moi ban ghi
// project_members (phan cong kieu cu, chi co "duoc sua hay khong") duoc quy
// doi sang 1 dong trong user_project_permissions voi muc UPDATE - dung bang
// muc quyen chinh sua ma nguoi "phu trach" dang co truoc day, de khong ai bi
// mat quyen dang dung khi nang cap len ban co ACL chi tiet nay.
//
// Ham nay da hoan thanh vai tro cua no: du lieu project_members tung ton tai
// tu truoc khi co ACL da duoc dong bo sang user_project_permissions trong
// nhung lan chay truoc day. TU LAN CAP NHAT HARDENING NAY TRO DI, ham nay
// KHONG con duoc goi tu dong khi server khoi dong nua (xem cuoi file) - de
// project_members khong con la con duong nao (ke ca gian tiep) co the tao
// ra quyen moi trong he thong ACL chinh thuc. project_members va cac ban
// ghi da ton tai trong bang KHONG bi xoa; ham nay chi khong con duoc GOI tu
// dong. Neu that su can khoi phuc/dong bo lai thu cong, co the goi ham nay
// truc tiep (vi du qua mot script rieng) - nhung day khong phai luong hoat
// dong mac dinh cua ung dung nua.
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

// ---------------------------------------------------------------------------
// Nap bang tien do chi tiet (WBS) tu du lieu Excel goc (raw_excel_json) vao
// bang project_progress_tasks - CHI chay cho nhung du an CHUA co dong nao
// trong bang moi (idempotent: an toan chay lai nhieu lan, khong doi lai du
// lieu da tung duoc admin/nguoi dung sua qua giao dien moi).
// ---------------------------------------------------------------------------
function migrateProgressBreakdownFromExcel() {
  const children = db
    .prepare("SELECT code, raw_excel_json FROM projects WHERE parent_code IS NOT NULL AND source = 'excel' AND raw_excel_json IS NOT NULL")
    .all();
  if (!children.length) return;
  const already = new Set(db.prepare("SELECT DISTINCT project_code FROM project_progress_tasks").all().map((r) => r.project_code));
  const ts = new Date().toISOString();
  const ins = db.prepare(
    `INSERT INTO project_progress_tasks
       (project_code, stage_no, stage_name, stt, task_name, unit, weight_pct, status, pct_done,
        planned_start, planned_end, actual_start, actual_end, note, created_at, updated_at)
     VALUES (?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?)
     ON CONFLICT(project_code, stt) DO NOTHING`
  );
  let migratedCount = 0;
  db.exec("BEGIN");
  try {
    for (const row of children) {
      if (already.has(row.code)) continue;
      let parsed;
      try {
        parsed = JSON.parse(row.raw_excel_json);
      } catch {
        continue;
      }
      const stages = parsed && parsed.detail && Array.isArray(parsed.detail.stages) ? parsed.detail.stages : null;
      if (!stages || !stages.length) continue;
      stages.forEach((stage, stageIdx) => {
        (stage.tasks || []).forEach((t) => {
          ins.run(
            row.code,
            stageIdx + 1,
            stage.stage_name || `Giai đoạn ${stageIdx + 1}`,
            t.stt ?? 0,
            t.task_name || "",
            t.unit || null,
            typeof t.weight_pct === "number" ? t.weight_pct : 0,
            t.status || "Chưa thực hiện",
            typeof t.pct_done === "number" ? t.pct_done : 0,
            t.planned_start || null,
            t.planned_end || null,
            t.actual_start || null,
            t.actual_end || null,
            t.description || null,
            ts,
            ts
          );
        });
      });
      migratedCount++;
    }
    db.exec("COMMIT");
  } catch (e) {
    db.exec("ROLLBACK");
    throw e;
  }
  if (migratedCount) {
    console.log(`Đã nạp bảng tiến độ chi tiết (WBS) từ Excel gốc cho ${migratedCount} dự án chi tiết.`);
  }
}

seedIfNew();
// [HARDENING] migrateLegacyMembersToPermissions() KHONG con duoc goi tu dong
// o day nua - xem chu thich chi tiet ngay phia tren dinh nghia ham do. Du
// lieu project_members va user_project_permissions da dong bo truoc day
// khong bi anh huong (khong xoa gi ca); day chi la ngat duong dong bo TU
// DONG trong tuong lai de project_members khong con kha nang tao them quyen
// moi trong he thong ACL.
migrateProgressBreakdownFromExcel();

// ---------------------------------------------------------------------------
// [AN TOAN VOLUME - CHI SAO CHEP, KHONG XOA/GHI DE FILE DANG DUNG]
// Phat hien qua log chan doan: Railway Volume co the dang duoc gan
// (RAILWAY_VOLUME_MOUNT_PATH) o MOT THU MUC KHAC voi thu muc dang thuc su
// chua DB_FILE (vi du Volume gan o "/data" nhung app dang mo DB o
// "/app/data/qltkm.db") - nghia la Volume HIEN TAI KHONG bao ve du lieu
// that; du lieu that dang nam tren dia TAM THOI cua container, se mat vao
// lan deploy ke tiep neu khong xu ly truoc.
//
// De chuan bi an toan cho buoc sua "Mount Path" cua Volume tren Railway (sua
// tu "/data" thanh dung thu muc dang chua DB_FILE) MA KHONG mat du lieu,
// doan nay tu dong, moi lan khoi dong:
//   1. Gop het du lieu con dang nam trong WAL vao file .db chinh (checkpoint)
//      de dam bao ban sao la BAN DAY DU, khong thieu du lieu vua ghi gan day.
//   2. Sao chep (KHONG xoa file goc dang dung) file .db chinh sang dung thu
//      muc Volume dang duoc gan that su, giu NGUYEN TEN FILE - de sau khi
//      sua Mount Path xong tren Railway, app se tu tim thay dung file nay.
// Neu 2 duong dan da trung nhau roi (Volume da gan dung cho) thi TU DONG
// KHONG lam gi ca - an toan de giu code nay lai vinh vien, deploy lai bao
// nhieu lan cung duoc, khong anh huong hieu nang hay du lieu dang chay.
// ---------------------------------------------------------------------------
try {
  const volumeMountPath = process.env.RAILWAY_VOLUME_MOUNT_PATH;
  const actualDbDir = path.dirname(DB_FILE);
  if (volumeMountPath && fs.existsSync(volumeMountPath) && path.resolve(volumeMountPath) !== path.resolve(actualDbDir)) {
    db.exec("PRAGMA wal_checkpoint(TRUNCATE);");
    const backupTarget = path.join(volumeMountPath, path.basename(DB_FILE));
    fs.copyFileSync(DB_FILE, backupTarget);
    console.log(
      `[AN TOÀN VOLUME] Đã sao 1 bản DB hiện tại (đã gộp đủ dữ liệu WAL, không xoá file gốc đang dùng) sang đúng nơi Railway Volume đang thực sự được gắn: ${backupTarget}. ` +
        `Sau khi bạn sửa Mount Path của Volume trên Railway thành "${actualDbDir}" và deploy lại, app sẽ tự tìm thấy đúng file này và KHÔNG bị mất dữ liệu.`
    );
  }
} catch (e) {
  console.warn(
    "[AN TOÀN VOLUME] Không sao lưu được sang thư mục Volume (không ảnh hưởng gì đến database đang chạy, chỉ là bước chuẩn bị an toàn):",
    e.message
  );
}

module.exports = { db };
