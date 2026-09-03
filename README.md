# QL Tiến độ Dự án TKM — Web App dùng chung (có Backend + Database + Đăng nhập)

Đây là bản nâng cấp thật sự của file HTML gốc: không còn là một trang mô phỏng
chạy một mình trên máy bạn nữa, mà là một **Web App 3 lớp** — Giao diện (trình
duyệt) → Server (Node.js) → Database (file SQLite) — để nhiều người có thể
cùng truy cập một địa chỉ, cùng xem, cùng chỉnh sửa, và dữ liệu của người này
lưu xong thì người khác load lại sẽ thấy ngay.

## 0. Vì sao các nút "Thêm dự án", "Chỉnh sửa", "Lưu" trước đây không hoạt động dùng chung?

File HTML gốc là một ứng dụng React đã "đóng gói" (bundle) chỉ chạy được với
dữ liệu nạp sẵn ngay trong file — nó **không có server, không có database**.
Khi bạn bấm Lưu, ứng dụng cố gắng gọi đến một địa chỉ API (`/api/...`) không
hề tồn tại, request thất bại, nên coi như không lưu được gì — hoặc chỉ lưu
tạm trong bộ nhớ trình duyệt của riêng máy bạn (không chia sẻ được cho ai).
Đây chính là nguyên nhân gốc rễ. Bản này giải quyết đúng vào gốc rễ đó bằng
cách xây dựng thật một Backend (Node.js/Express) và một Database (SQLite),
thay vì chỉ sửa lại giao diện.

## 1–3. Công nghệ sử dụng

| Lớp | Công nghệ | Vì sao chọn |
|---|---|---|
| Frontend | React (bundle gốc, giữ nguyên giao diện/biểu đồ/bộ lọc bạn đang quen dùng) + 1 lớp mã JavaScript nhỏ được "tiêm" thêm (đăng nhập, phân quyền, thông báo real-time) | Không phải build lại từ đầu, giữ nguyên trải nghiệm cũ |
| Backend | Node.js 22+ / Express | Nhẹ, cài đặt đơn giản, không cần công cụ build phức tạp |
| Database | SQLite (qua module `node:sqlite` có sẵn trong Node — không cần cài driver riêng) | Chỉ là 1 file `.db` duy nhất, không cần cài đặt máy chủ database riêng (như MySQL/Postgres), rất phù hợp quy mô một phòng/ban dùng chung |

## 4. Cách cài đặt lên một máy chủ (server)

1. Cài **Node.js phiên bản 22.5 trở lên** trên máy sẽ đóng vai trò server
   (máy tính công ty để bật 24/7, hoặc 1 VPS/cloud server).
2. Copy toàn bộ thư mục này lên máy đó.
3. Mở terminal/cmd tại thư mục này, chạy:
   ```
   npm install
   npm start
   ```
4. Thấy dòng `QL TKM Web App đang chạy tại http://localhost:3000` là đã chạy
   thành công. (Thư mục `node_modules` đã được đính kèm sẵn trong file nén
   gửi cho bạn, nên bước `npm install` thường sẽ chạy rất nhanh — nó chỉ xác
   nhận lại là mọi thứ đã có đủ.)
5. Lần đầu chạy, hệ thống tự tạo database và nạp sẵn toàn bộ 44 dự án tổng /
   74 dự án chi tiết từ dữ liệu Excel gốc, cùng 1 tài khoản quản trị:
   - Tên đăng nhập: `admin`
   - Mật khẩu: `admin123`
   - **Hãy đổi mật khẩu này ngay sau khi đăng nhập lần đầu** (vào "👤 Quản
     trị viên" → có thể đổi qua trang Quản lý người dùng, hoặc dùng API đổi
     mật khẩu).

## 5. Nhiều máy tính truy cập cùng lúc như thế nào?

- **Trong cùng văn phòng / cùng mạng LAN**: trên máy chủ, tìm địa chỉ IP nội
  bộ của máy đó (Windows: `ipconfig`, Mac/Linux: `ifconfig`/`ip addr` —
  thường dạng `192.168.x.x`). Các máy khác trong cùng mạng wifi/LAN mở trình
  duyệt, gõ `http://192.168.x.x:3000` là truy cập được, mỗi người đăng nhập
  bằng tài khoản riêng của mình.
- **Truy cập từ xa / nhiều chi nhánh**: cần triển khai lên một máy chủ luôn
  bật (máy tính để bàn cấu hình chạy 24/7, hoặc thuê VPS/cloud server —
  Google Cloud, AWS, DigitalOcean, Vietnix, v.v.), sau đó cấu hình mở cổng
  mạng (firewall/port-forwarding) và trỏ tên miền nếu muốn địa chỉ đẹp.
  Bước này liên quan hạ tầng mạng cụ thể của công ty bạn nên khuyến nghị nhờ
  bộ phận IT/nhà cung cấp hosting hỗ trợ cấu hình mạng, phần code thì không
  cần chỉnh sửa gì thêm.

## 6. Cách tạo tài khoản người dùng

- Đăng nhập bằng tài khoản `admin` → bấm **"👤 Quản trị viên" → "⚙ Người
  dùng"** ở góc trên bên phải (hoặc vào thẳng địa chỉ `/admin-users.html`).
- Điền Tên đăng nhập / Họ tên / Mật khẩu / chọn Vai trò → bấm "+ Tạo tài
  khoản".
- Với người có vai trò **"Người phụ trách"**, sau khi tạo xong, bấm nút
  **"Phân công dự án"** cạnh tên họ để tick chọn đúng những dự án chi tiết mà
  người đó được phép chỉnh sửa.
- Trang này cũng cho phép **Khóa/Mở khóa** tài khoản và **Đặt lại mật khẩu**
  cho từng người khi cần (ví dụ khi họ quên mật khẩu).

## 7. Phân quyền hoạt động ra sao (RBAC)

4 vai trò cố định, được kiểm tra ở **phía server** (không thể bị qua mặt chỉ
bằng cách sửa giao diện trình duyệt):

| Vai trò | Quyền |
|---|---|
| **Quản trị viên (admin)** | Toàn quyền: thêm/sửa/xóa mọi dự án, quản lý tài khoản, phân quyền |
| **Quản lý (manager)** | Xem tất cả, tạo mới, chỉnh sửa mọi dự án, cập nhật trạng thái/tiến độ |
| **Người phụ trách (responsible)** | Chỉ **chỉnh sửa** được các dự án chi tiết đã được admin "Phân công" cho mình (tiến độ, công việc, vướng mắc, vật tư); vẫn **xem được** toàn bộ dữ liệu như những người khác |
| **Người xem (viewer)** | Chỉ xem, không có bất kỳ nút chỉnh sửa/thêm/xóa nào hoạt động |

Giao diện sẽ tự ẩn/khóa các nút mà vai trò hiện tại không được phép bấm, để
gọn gàng — nhưng đây chỉ là lớp "cho đẹp". Lớp bảo mật thật sự nằm ở server:
mọi request thêm/sửa/xóa đều được server kiểm tra lại quyền trước khi ghi vào
database, dù request đó có đến từ đâu.

## 8. Dữ liệu được lưu ở đâu

Toàn bộ dữ liệu (danh sách dự án, công việc, vướng mắc, vật tư, tài khoản,
lịch sử chỉnh sửa...) được lưu trong **một file duy nhất**:
```
data/qltkm.db
```
nằm ngay trong thư mục cài đặt server. Đây là file SQLite chuẩn — có thể mở
xem bằng các công cụ như "DB Browser for SQLite" nếu cần kiểm tra trực tiếp.

## 9. Cách sao lưu (backup) database

Cách đơn giản và an toàn nhất:
1. Dừng server (Ctrl+C ở cửa sổ terminal đang chạy `npm start`).
2. Copy 3 file trong thư mục `data/`: `qltkm.db`, `qltkm.db-shm`,
   `qltkm.db-wal` (2 file sau có thể không tồn tại nếu server đã tắt sạch —
   vẫn cứ copy nếu có) sang một nơi lưu trữ khác (ổ cứng ngoài, Google
   Drive, v.v.), đặt tên kèm ngày tháng, ví dụ `qltkm_2026-08-28.db`.
3. Khởi động lại server (`npm start`).

Nên đặt lịch backup định kỳ (hàng ngày/hàng tuần tuỳ mức độ quan trọng dữ
liệu). Nếu không muốn dừng server, chỉ copy được **khi** không có ai đang
ghi dữ liệu cùng lúc — cách trên (dừng hẳn server) là cách chắc chắn nhất để
tránh backup bị lỗi giữa chừng.

## 10. Cách nâng cấp lên phiên bản mới mà không mất dữ liệu

1. Dừng server.
2. **Không xoá thư mục `data/`** — đây là nơi chứa toàn bộ dữ liệu thật.
3. Thay thế các file code (`server.js`, `db.js`, `auth.js`, `public_index.html`,
   `shim_frontend.js`, `admin-users.html`, `package.json`, `node_modules/`...)
   bằng phiên bản mới.
4. Khởi động lại server.

Vì database dùng lệnh `CREATE TABLE IF NOT EXISTS` nên việc thêm bảng/cột mới
trong tương lai sẽ không xoá dữ liệu cũ. Tuy nhiên, **nếu một bản nâng cấp
trong tương lai cần đổi cấu trúc bảng đã có** (ví dụ đổi tên cột, đổi kiểu dữ
liệu) thì sẽ cần một đoạn mã "migration" chuyển đổi riêng — phiên bản hiện
tại **chưa có sẵn cơ chế migration tự động** cho trường hợp đó, nên nếu về
sau cần thay đổi cấu trúc dữ liệu sâu, hãy backup kỹ trước khi nâng cấp và
nhờ hỗ trợ kỹ thuật kiểm tra trước.

---

## Những điều đã tự kiểm tra (theo đúng 7 kịch bản bạn yêu cầu)

Toàn bộ 7 kịch bản dưới đây đã được kiểm thử tự động (giả lập nhiều người
dùng/nhiều trình duyệt cùng lúc thao tác thật trên server) trước khi gửi cho
bạn:

1. ✅ Tạo dự án mới → Lưu → tải lại trang (F5) → dữ liệu vẫn còn nguyên (đã
   lưu thật vào file database, không phải bộ nhớ tạm của trình duyệt).
2. ✅ Người dùng A (admin) tạo dự án mới → người dùng B (tài khoản khác, vai
   trò Quản lý) đăng nhập → thấy ngay dự án đó.
3. ✅ Người dùng A sửa tiến độ dự án → Lưu → người dùng B tải lại → thấy
   đúng tiến độ mới.
4. ✅ Hai người cùng mở một dự án để sửa: người lưu trước thành công bình
   thường; người lưu sau nhận đúng thông báo bắt buộc:
   *"Dữ liệu đã được người dùng khác cập nhật. Vui lòng tải lại trước khi
   lưu."* — và **không** bị ghi đè mất dữ liệu của người lưu trước.
5. ✅ Tài khoản "Người xem" và "Người phụ trách" (với dự án chưa được phân
   công): nút Chỉnh sửa/Thêm mới tự động bị khoá trên giao diện, và server
   cũng từ chối (403) nếu có ai cố tình gọi thẳng API để bỏ qua giao diện.
6. ✅ Xóa dự án: có hộp thoại xác nhận, kiểm tra đúng quyền (chỉ
   admin/manager xóa được — thử bằng tài khoản Người xem bị chặn với lỗi
   403), dữ liệu được đánh dấu đã xóa trong database (xóa mềm — vẫn giữ lại
   lịch sử để tra cứu khi cần), giao diện cập nhật ngay sau khi xóa.
7. ✅ Tạo dự án tổng mới → tạo dự án chi tiết trực thuộc dự án tổng đó →
   kiểm tra lại qua API: mối quan hệ cha/con được lưu và hiển thị đúng.

## Những điểm còn giới hạn, xin nói rõ để bạn nắm được

Bản đặc tả bạn gửi rất đầy đủ và chi tiết (25 mục). Phần lớn đã được xây
dựng đúng như yêu cầu. Một vài điểm được đơn giản hoá có chủ đích, xin nêu rõ
thay vì để bạn tự phát hiện sau:

- **Vai trò/quyền hạn** hiện là 4 vai trò cố định trong code (admin / manager
  / responsible / viewer), chưa phải là một hệ thống phân quyền động (tạo
  thêm vai trò mới, tuỳ chỉnh từng quyền riêng lẻ) như mô tả ở phần thiết kế
  bảng dữ liệu trong yêu cầu gốc. Với quy mô một phòng/ban thì 4 vai trò này
  thường là đủ dùng; nếu sau này cần vai trò tuỳ biến sâu hơn, đây sẽ là điểm
  cần phát triển thêm.
- **"Người phụ trách" xem được toàn bộ dữ liệu**, chỉ bị giới hạn ở quyền
  **chỉnh sửa** (chỉ sửa được các dự án đã được phân công). Việc giới hạn cả
  quyền *xem* theo từng người sẽ cần chỉnh sâu vào giao diện gốc (vốn là mã
  đã đóng gói/thu gọn, khó tách nhỏ theo từng phần dữ liệu) nên hiện chưa làm.
- **Cập nhật gần thời gian thực** dùng Server-Sent Events (một trong các lựa
  chọn bạn cho phép) — khi ai đó lưu thay đổi, người khác đang mở trang sẽ
  thấy ngay một thông báo nhỏ "🔄 ... vừa cập nhật dữ liệu" kèm nút "Tải lại".
  Đây là kiểu "báo cho biết rồi tự bấm tải lại", **chưa phải** kiểu tự động
  cập nhật lại dữ liệu ngay trên màn hình mà không cần thao tác gì (do phần
  giao diện gốc là mã đã đóng gói, không tiện chỉnh để tự "vá" từng phần dữ
  liệu đang hiển thị).
- **Nhập/Xuất Excel**: khung API đã có sẵn (`/api/import/preview`,
  `/api/import/commit`) nhưng phần xử lý đọc file Excel thật **chưa được xây
  dựng** (trả về "chưa được hỗ trợ") — đây là phần việc còn lại lớn nhất nếu
  bạn cần dùng tính năng này. Xuất dữ liệu dạng JSON đầy đủ thì đã có sẵn
  (`/api/export`).

Nếu bạn muốn hoàn thiện thêm bất kỳ điểm nào ở trên (đặc biệt là Nhập/Xuất
Excel, hoặc phân quyền xem theo từng người), cứ cho biết — đây là các phần
có thể làm tiếp trên nền móng Backend + Database đã xây dựng xong.
