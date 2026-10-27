# PHP2Shell Local Security Checker

Bộ công cụ Bash gọn nhẹ để kiểm tra cục bộ các dấu hiệu phơi nhiễm liên quan đến **CVE-2026-109618** và **CVE-2026-109619**, thường được gọi chung là PHP2Shell.

Dự án gồm hai script kiểm tra chỉ đọc:

- **Kiểm tra nhanh** — so sánh phiên bản PHP CLI tìm thấy trong `PATH` với các mốc phiên bản upstream đã được vá.
- **Kiểm tra nâng cao** — bổ sung rà soát một số dấu hiệu trên máy cục bộ: tiến trình đáng ngờ, kết nối mạng, tệp PHP mới chỉnh sửa, mẫu webshell phổ biến và một số vị trí có thể chứa cơ chế duy trì truy cập.

> **Đây là công cụ sàng lọc phục vụ phòng thủ, không phải mã khai thác, công cụ quét từ xa hay giải pháp điều tra số toàn diện.** Script không gửi yêu cầu đến website và không thử kích hoạt lỗ hổng.

## Công cụ kiểm tra được gì?

| Script | Phạm vi kiểm tra | Không thể kết luận |
| --- | --- | --- |
| Kiểm tra nhanh | Phiên bản PHP CLI và SAPI do lệnh `php` trong `PATH` báo cáo | Phiên bản/cấu hình đang dùng bởi Apache `mod_php`, PHP-FPM, container hoặc runtime web khác; bản vá backport của nhà cung cấp |
| Kiểm tra nâng cao | Các mục của kiểm tra nhanh và một số chỉ báo cục bộ trên máy | Máy chắc chắn an toàn, cảnh báo chắc chắn là sự cố, hoặc đã tìm thấy mọi cơ chế duy trì truy cập |

Kết quả **đã vá** có nghĩa phiên bản CLI được phát hiện đạt mốc upstream tương ứng. Đây không phải bằng chứng rằng mọi runtime PHP trên máy đều đã được vá. Phiên bản thấp hơn mốc là lý do cần kiểm tra và cập nhật; một số gói do nhà cung cấp duy trì có thể đã backport bản sửa nhưng vẫn giữ cách đánh số phiên bản khác với upstream.

## Phiên bản upstream đã có bản sửa

Dự án PHP công bố các phiên bản đã vá sau:

| Nhánh PHP | Phiên bản đã vá |
| --- | ---: |
| 8.2 | 8.2.35 |
| 8.3 | 8.3.36 |
| 8.4 | 8.4.27 |
| 8.5 | 8.5.12 |

Các mốc này áp dụng cho bản phát hành upstream. Với gói của bản phân phối Linux, control panel, dịch vụ hosting hoặc nhánh cũ được nhà cung cấp hỗ trợ, hãy kiểm tra advisory bảo mật và changelog của chính nhà cung cấp đó.

## Yêu cầu

- Linux có Bash
- PHP CLI để kiểm tra phiên bản
- Các tiện ích hệ thống phổ biến được script sử dụng, như `ps`, `ss`, `find` và `grep`
- Quyền root hoặc quyền phù hợp để kiểm tra nâng cao có phạm vi đầy đủ hơn (được khuyến nghị, không bắt buộc với kiểm tra nhanh)

Nếu chạy kiểm tra nâng cao mà không đủ quyền, một số tiến trình, socket, thư mục hoặc crontab của người dùng khác có thể không đọc được.

## Cách sử dụng

Clone repository và chạy script phù hợp trên máy cần kiểm tra:

```bash
git clone https://github.com/VNCS-GLOBAL/php2shell.git
cd php2shell
chmod +x php2shell-simple-check.sh php2shell-advanced-check.sh
```

### Kiểm tra nhanh phiên bản

```bash
./php2shell-simple-check.sh
```

Script kiểm tra executable `php` được phân giải từ `PATH` hiện tại. Nếu không tìm thấy PHP, script sẽ thông báo và thoát với mã lỗi khác 0.

### Kiểm tra và rà soát chỉ báo cục bộ

```bash
sudo ./php2shell-advanced-check.sh
```

Đọc toàn bộ kết quả, gồm tất cả dòng `[!]` và `[CRITICAL]`. Hãy xem chúng là đầu mối cần xác minh, không phải kết luận cuối cùng. Tên tiến trình, mẫu tệp hoặc SSH key xuất hiện có thể hợp lệ trong môi trường cụ thể.

## Quy trình đánh giá khuyến nghị

1. **Kiểm kê mọi runtime PHP.** Bao gồm web server, các pool PHP-FPM, container, tác vụ định kỳ, môi trường staging và máy dự phòng.
2. **Kiểm tra đúng runtime đang phục vụ lưu lượng.** Lệnh `php` thường chỉ kiểm tra PHP CLI; ứng dụng web có thể sử dụng binary, SAPI, tệp cấu hình hoặc image container khác.
3. **Xác minh trạng thái gói với nhà cung cấp.** Kiểm tra gói đã có bản sửa bảo mật chưa, kể cả bản backport được ghi nhận trong advisory.
4. **Cập nhật theo hướng dẫn của nhà cung cấp và khởi động lại/triển khai lại worker liên quan.** Sau đó xác nhận tiến trình đang chạy đã sử dụng gói mới.
5. **Điều tra các chỉ báo bất thường.** Đối chiếu dữ liệu tiến trình, mạng, hệ thống tệp, web server, PHP và công cụ bảo vệ endpoint. Nếu nghi ngờ bị xâm nhập, hãy bảo toàn bằng chứng theo quy trình ứng phó sự cố.

Cập nhật lên bản PHP có chứa bản sửa là biện pháp khắc phục chính. Thay đổi cấu hình hoặc lọc request có thể giảm phơi nhiễm trong một số môi trường, nhưng không nên được xem là thay thế cho bản vá của nhà cung cấp.

## Cách hiểu kết quả kiểm tra nâng cao

Script nâng cao kiểm tra một số nhóm chỉ báo thường gặp:

- Phiên bản PHP CLI và trạng thái `session.upload_progress.enabled`
- Tiến trình có thể đáng ngờ khi chạy dưới tài khoản dịch vụ web
- Kết nối đang mở và cổng lắng nghe liên quan đến tiến trình web
- Tệp PHP mới sửa trong một số web root được chọn
- Một số mẫu mã PHP thường gặp trong webshell
- Crontab của một số tài khoản và tệp `authorized_keys` dưới một số thư mục người dùng

Các phép kiểm tra này đơn giản và có giới hạn. Hoạt động quản trị hợp lệ có thể tạo cảnh báo; mã bị làm rối, công cụ đổi tên, đường dẫn không nằm trong phạm vi quét, tiến trình chạy rất ngắn, vị trí duy trì truy cập khác hoặc thiếu quyền đọc đều có thể khiến script bỏ sót. Script không kiểm tra mọi PHP SAPI và không phân tích đầy đủ metadata gói của từng nhà cung cấp. **Không có cảnh báo không đồng nghĩa máy không bị xâm nhập.**

## Sử dụng an toàn

Chỉ chạy script trên hệ thống bạn sở hữu hoặc được ủy quyền quản trị. Công cụ được thiết kế cho kiểm tra phòng thủ cục bộ. Hãy đọc mã nguồn trước khi chạy với quyền cao và xem xét các kết quả dựa trên ngữ cảnh của môi trường.

## Đóng góp

Bạn có thể gửi issue hoặc pull request. Khi báo lỗi, vui lòng cung cấp:

- Hệ điều hành và nguồn gói PHP đang sử dụng
- Script và câu lệnh đã chạy
- Kết quả liên quan sau khi đã xóa hostname, địa chỉ IP, tên người dùng và dữ liệu nhạy cảm
- Kết quả mong đợi và kết quả thực tế

Không đính kèm thông tin xác thực, khóa riêng, dữ liệu khách hàng hoặc log bảo mật chưa được ẩn danh vào issue công khai.

## Tài liệu tham khảo

- [Advisory PHP: CVE-2026-109618](https://github.com/php/php-src/security/advisories/GHSA-w8hw-w9fx-j79w)
- [Advisory PHP: CVE-2026-109619](https://github.com/php/php-src/security/advisories/GHSA-6wmf-4rv5-p3rp)
- [Kho lưu trữ thông báo bảo mật PHP](https://www.php.net/archive/2026.php)


