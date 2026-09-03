
(function () {
  "use strict";

  // Ẩn toàn bộ app cho tới khi biết chắc đã đăng nhập hay chưa, để tránh
  // nháy qua giao diện "chế độ chỉ xem" một tích tắc trước khi lộ ra form login.
  var hideStyle = document.createElement("style");
  hideStyle.textContent = "#root{visibility:hidden}";
  document.head.appendChild(hideStyle);

  var CURRENT_USER = null;
  var VERSION_MAP = {}; // child_code -> version, de phat hien xung dot khi luu
  var SELF_ACTIONS = []; // cac thay doi do CHINH TAB nay vua thuc hien (bo qua khi nhan SSE)

  // ---------------------------------------------------------------------
  // fetch: chi can gan __version vao PUT /api/projects/:code, con lai giu nguyen
  // (cookie phien dang nhap tu trinh duyet gui kem tu dong, khong can sua gi them).
  // ---------------------------------------------------------------------
  var realFetch = window.fetch.bind(window);
  window.fetch = function (input, init) {
    var url = typeof input === "string" ? input : (input && input.url) || "";
    var method = (init && init.method) || "GET";
    var m = /^\/api\/projects\/([^/]+)$/.exec(url);
    if (m && method === "PUT" && init && typeof init.body === "string") {
      try {
        var body = JSON.parse(init.body);
        var code = decodeURIComponent(m[1]);
        body.__version = VERSION_MAP[code];
        init = Object.assign({}, init, { body: JSON.stringify(body) });
      } catch (e) {}
    }
    return realFetch(input, init).then(function (resp) {
      if (resp.ok && /^\/api\/(projects|categories)/.test(url) && method !== "GET") {
        SELF_ACTIONS.push(Date.now());
        if (SELF_ACTIONS.length > 20) SELF_ACTIONS.shift();
      }
      if (resp.ok && url === "/api/bootstrap") {
        resp
          .clone()
          .json()
          .then(cacheVersions)
          .catch(function () {});
      }
      return resp;
    });
  };

  function cacheVersions(data) {
    try {
      (data.children || []).forEach(function (c) {
        if (c._version != null) VERSION_MAP[c.child_code] = c._version;
      });
      Object.keys(data.overrides || {}).forEach(function (code) {
        var o = data.overrides[code];
        if (o._version != null) VERSION_MAP[code] = o._version;
      });
      (data.addedChildren || []).forEach(function (c) {
        if (c._version != null) VERSION_MAP[c.child_code] = c._version;
      });
    } catch (e) {}
  }

  // ---------------------------------------------------------------------
  // Man hinh dang nhap
  // ---------------------------------------------------------------------
  function showLogin(errorMsg) {
    var existing = document.getElementById("__qltkm_login__");
    if (existing) existing.remove();
    var wrap = document.createElement("div");
    wrap.id = "__qltkm_login__";
    wrap.style.cssText =
      "position:fixed;inset:0;background:linear-gradient(135deg,#0f2f5b,#14396f);" +
      "display:flex;align-items:center;justify-content:center;z-index:99999;font-family:inherit;";
    wrap.innerHTML =
      '<div style="background:#fff;border-radius:14px;padding:32px 30px;width:360px;max-width:92vw;box-shadow:0 24px 60px rgba(0,0,0,.35)">' +
      '<div style="font-size:18px;font-weight:800;color:#0f2f5b;margin-bottom:4px">QL Tiến độ Dự án TKM</div>' +
      '<div style="font-size:12.5px;color:#6b7280;margin-bottom:20px">Đăng nhập để tiếp tục</div>' +
      '<label style="font-size:12.5px;font-weight:600;color:#374151">Tên đăng nhập</label>' +
      '<input id="__qltkm_u__" type="text" autofocus style="display:block;width:100%;box-sizing:border-box;margin:6px 0 14px;padding:9px 11px;border:1px solid #e2e6ec;border-radius:8px;font-size:13.5px" />' +
      '<label style="font-size:12.5px;font-weight:600;color:#374151">Mật khẩu</label>' +
      '<input id="__qltkm_p__" type="password" style="display:block;width:100%;box-sizing:border-box;margin:6px 0 6px;padding:9px 11px;border:1px solid #e2e6ec;border-radius:8px;font-size:13.5px" />' +
      '<div id="__qltkm_err__" style="color:#dc2626;font-size:12.5px;min-height:16px;margin-bottom:10px"></div>' +
      '<button id="__qltkm_go__" style="width:100%;padding:10px;border:none;border-radius:8px;background:#2563eb;color:#fff;font-weight:700;font-size:13.5px;cursor:pointer">Đăng nhập</button>' +
      '<div style="font-size:11.5px;color:#9ca3af;margin-top:14px;line-height:1.5">Lần đầu chạy: <b>admin</b> / <b>admin123</b> — hãy đổi mật khẩu ngay sau khi vào hệ thống.</div>' +
      "</div>";
    document.body.appendChild(wrap);
    if (errorMsg) document.getElementById("__qltkm_err__").textContent = errorMsg;

    function doLogin() {
      var u = document.getElementById("__qltkm_u__").value.trim();
      var p = document.getElementById("__qltkm_p__").value;
      if (!u || !p) {
        document.getElementById("__qltkm_err__").textContent = "Nhập đủ tên đăng nhập và mật khẩu.";
        return;
      }
      realFetch("/api/auth/login", {
        method: "POST",
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify({ username: u, password: p }),
      })
        .then(function (r) {
          return r.json().then(function (j) {
            if (!r.ok) throw new Error(j.error || "Đăng nhập thất bại");
            return j;
          });
        })
        .then(function () {
          location.reload();
        })
        .catch(function (e) {
          document.getElementById("__qltkm_err__").textContent = e.message;
        });
    }
    document.getElementById("__qltkm_go__").addEventListener("click", doLogin);
    document.getElementById("__qltkm_p__").addEventListener("keydown", function (e) {
      if (e.key === "Enter") doLogin();
    });
  }

  // ---------------------------------------------------------------------
  // Thanh trang thai nguoi dung + dang xuat
  // ---------------------------------------------------------------------
  function showUserBar(user) {
    var bar = document.createElement("div");
    bar.id = "__qltkm_userbar__";
    bar.style.cssText =
      "position:fixed;top:8px;right:14px;z-index:9998;background:#0f2f5b;color:#fff;" +
      "padding:6px 12px;border-radius:20px;font-size:12px;display:flex;gap:10px;align-items:center;" +
      "box-shadow:0 2px 8px rgba(0,0,0,.2)";
    var adminLink =
      user.role === "admin"
        ? '<a href="/admin-users.html" style="color:#bfdbfe;text-decoration:none;font-weight:600">⚙ Người dùng</a>'
        : "";
    bar.innerHTML =
      "<span>👤 <b>" +
      escapeHtml(user.display_name) +
      "</b> · " +
      escapeHtml(user.role_label) +
      "</span>" +
      adminLink +
      '<a id="__qltkm_logout__" href="#" style="color:#fecaca;text-decoration:none;font-weight:600">Đăng xuất</a>';
    document.body.appendChild(bar);
    document.getElementById("__qltkm_logout__").addEventListener("click", function (e) {
      e.preventDefault();
      realFetch("/api/auth/logout", { method: "POST" }).then(function () {
        location.reload();
      });
    });
  }
  function escapeHtml(s) {
    return String(s == null ? "" : s).replace(/[&<>"']/g, function (c) {
      return { "&": "&amp;", "<": "&lt;", ">": "&gt;", '"': "&quot;", "'": "&#39;" }[c];
    });
  }

  // ---------------------------------------------------------------------
  // Banner "co du lieu moi" qua SSE
  // ---------------------------------------------------------------------
  function connectSSE() {
    try {
      var es = new EventSource("/api/events");
      es.onmessage = function (evt) {
        try {
          var data = JSON.parse(evt.data);
          if (data.type !== "changed") return;
          if (data.by === (CURRENT_USER && CURRENT_USER.display_name)) return; // tu minh vua luu, app da tu refresh
          showChangedBanner(data);
        } catch (e) {}
      };
      es.onerror = function () {
        // trinh duyet se tu ket noi lai; khong lam gi them
      };
    } catch (e) {}
  }
  function showChangedBanner(info) {
    var existing = document.getElementById("__qltkm_banner__");
    if (existing) existing.remove();
    var b = document.createElement("div");
    b.id = "__qltkm_banner__";
    b.style.cssText =
      "position:fixed;left:50%;top:14px;transform:translateX(-50%);z-index:9997;" +
      "background:#0f2f5b;color:#fff;padding:10px 16px;border-radius:10px;font-size:13px;" +
      "box-shadow:0 8px 24px rgba(0,0,0,.25);display:flex;gap:12px;align-items:center";
    b.innerHTML =
      "<span>🔄 " +
      escapeHtml(info.by || "Người khác") +
      " vừa cập nhật dữ liệu.</span>" +
      '<button id="__qltkm_reload__" style="background:#2563eb;border:none;color:#fff;padding:6px 12px;border-radius:6px;font-weight:700;cursor:pointer;font-size:12.5px">Tải lại</button>';
    document.body.appendChild(b);
    document.getElementById("__qltkm_reload__").addEventListener("click", function () {
      location.reload();
    });
  }

  // ---------------------------------------------------------------------
  // RBAC tren giao dien: an/khoa nut theo vai tro (server van tu kiem tra
  // quyen o moi API - day chi la lop giao dien cho gon, khong phai lop bao mat).
  // ---------------------------------------------------------------------
  function applyRoleUI() {
    if (!CURRENT_USER) return;
    var role = CURRENT_USER.role;
    var canCreate = role === "admin" || role === "manager";
    var canDeleteClone = role === "admin" || role === "manager";
    var canEditAny = role === "admin" || role === "manager";
    var assigned = CURRENT_USER.assigned_codes || null; // chi co voi role 'responsible'

    document.querySelectorAll("button").forEach(function (btn) {
      var t = (btn.textContent || "").trim();
      if (t.indexOf("THÊM DỰ ÁN MỚI") !== -1 || t.indexOf("NHẬP TỪ EXCEL") !== -1) {
        if (!canCreate) {
          btn.disabled = true;
          btn.title = "Vai trò của bạn không có quyền thêm dự án mới.";
          btn.style.opacity = "0.5";
          btn.style.cursor = "not-allowed";
        }
      }
    });
  }

  // Quan sat menu "⋮" (Xem chi tiết / Chỉnh sửa / Nhân bản dự án) moi khi no
  // xuat hien, de: (a) an "Chỉnh sửa"/"Nhân bản" theo quyen, (b) chen them nut "Xóa dự án".
  function patchActionMenu(menu) {
    if (!CURRENT_USER || menu.__qltkmPatched) return;
    menu.__qltkmPatched = true;
    var role = CURRENT_USER.role;
    var canDeleteClone = role === "admin" || role === "manager";

    // Tim ma du an chi tiet tu hang <tr> gan nhat chua menu nay
    var tr = menu.closest("tr");
    var code = null;
    if (tr && tr.firstElementChild) code = (tr.firstElementChild.textContent || "").trim();

    var buttons = Array.prototype.slice.call(menu.querySelectorAll("button"));
    var editBtn = buttons.find(function (b) {
      return (b.textContent || "").trim() === "Chỉnh sửa";
    });
    var cloneBtn = buttons.find(function (b) {
      return (b.textContent || "").trim() === "Nhân bản dự án";
    });

    if (editBtn) {
      var canEditThis =
        role === "admin" ||
        role === "manager" ||
        (role === "responsible" && code && CURRENT_USER.assigned_codes && CURRENT_USER.assigned_codes.indexOf(code) !== -1);
      if (!canEditThis) {
        editBtn.disabled = true;
        editBtn.style.opacity = "0.4";
        editBtn.style.cursor = "not-allowed";
        editBtn.title = role === "viewer" ? "Tài khoản chỉ xem, không có quyền sửa." : "Bạn chưa được phân công dự án này.";
      }
    }
    if (cloneBtn && !canDeleteClone) {
      cloneBtn.disabled = true;
      cloneBtn.style.opacity = "0.4";
      cloneBtn.style.cursor = "not-allowed";
      cloneBtn.title = "Vai trò của bạn không có quyền nhân bản dự án.";
    }
    if (canDeleteClone && code) {
      var delBtn = document.createElement("button");
      delBtn.textContent = "🗑 Xóa dự án";
      delBtn.style.cssText =
        "display:block;width:100%;text-align:left;padding:9px 14px;border:none;background:transparent;" +
        "cursor:pointer;font-size:12.5px;color:#dc2626";
      delBtn.addEventListener("click", function (ev) {
        ev.stopPropagation();
        if (!confirm('Xóa dự án chi tiết "' + code + '"? Thao tác này không thể hoàn tác.')) return;
        realFetch("/api/projects/" + encodeURIComponent(code), { method: "DELETE" })
          .then(function (r) {
            return r.json().then(function (j) {
              if (!r.ok) throw new Error(j.error || "Xóa thất bại");
              return j;
            });
          })
          .then(function () {
            location.reload();
          })
          .catch(function (e) {
            alert(e.message);
          });
      });
      menu.appendChild(delBtn);
    }
  }

  var mo = new MutationObserver(function (mutations) {
    mutations.forEach(function (m) {
      m.addedNodes.forEach(function (node) {
        if (node.nodeType !== 1) return;
        // menu hanh dong: div tuyet doi, chua nut "Chỉnh sửa"
        if (node.querySelector && node.querySelector("button")) {
          var btns = node.querySelectorAll("button");
          for (var i = 0; i < btns.length; i++) {
            if ((btns[i].textContent || "").trim() === "Chỉnh sửa") {
              patchActionMenu(node);
              break;
            }
          }
        }
      });
    });
    applyRoleUI();
  });

  function boot() {
    realFetch("/api/auth/me")
      .then(function (r) {
        return r.json();
      })
      .then(function (data) {
        if (!data.user) {
          hideStyle.remove();
          showLogin();
          return;
        }
        CURRENT_USER = data.user;
        if (CURRENT_USER.role === "responsible") {
          realFetch("/api/auth/my-assignments")
            .then(function (r) {
              return r.ok ? r.json() : { project_codes: [] };
            })
            .catch(function () {
              return { project_codes: [] };
            })
            .then(function (m) {
              CURRENT_USER.assigned_codes = m.project_codes || [];
              finishBoot();
            });
        } else {
          finishBoot();
        }
      })
      .catch(function () {
        hideStyle.remove();
        showLogin();
      });
  }
  function finishBoot() {
    hideStyle.remove();
    showUserBar(CURRENT_USER);
    connectSSE();
    mo.observe(document.body, { childList: true, subtree: true });
    applyRoleUI();
    setInterval(applyRoleUI, 1500); // du phong cho cac lan render lai cua React
  }

  if (document.readyState === "loading") {
    document.addEventListener("DOMContentLoaded", boot);
  } else {
    boot();
  }
})();
