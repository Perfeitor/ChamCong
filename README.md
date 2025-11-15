# ProductionLabor

Hệ thống **ProductionLabor** là nền tảng hỗ trợ các nhà máy trong khu công nghiệp
quản lý biến động lao động theo ngày, phân công công việc, hệ số công, ngày lễ,
và tính toán tổng công – lương thực tế cuối tháng. Hệ thống được xây dựng
với mục tiêu giảm tải công việc thủ công cho tổ trưởng và phòng nhân sự,
đồng thời tăng tính minh bạch trong quản lý lao động sản xuất.

## 🎯 Mục tiêu chính
- Quản lý lao động theo tổ/nhóm làm việc.
- Phân công công việc theo ngày với hệ số công linh hoạt.
- Đánh dấu ngày lễ, ngày đặc biệt, hoặc hệ số lương tùy chọn.
- Theo dõi sản lượng/năng suất theo công nhân hoặc theo tổ.
- Tổng hợp số công (8 giờ) và tính lương cuối kỳ.
- Giảm sai sót do ghi chép thủ công và tăng tính chuẩn xác dữ liệu.

## 🏭 Phạm vi áp dụng
- Nhà máy trong khu công nghiệp.
- Xưởng sản xuất có biến động lao động theo ca/ngày.
- Môi trường có nhiều loại việc với hệ số lương không cố định.
- Doanh nghiệp cần hệ thống hóa việc phân công và chấm công theo tính chất sản xuất.

## 🖥 Công nghệ sử dụng
- **Blazor Server**: giao diện và xử lý nghiệp vụ phía UI.
- **ASP.NET Core**: nền tảng của toàn bộ hệ thống.
- **Entity Framework Core**: quản lý dữ liệu.
- **SQL Server** hoặc **PostgreSQL** (tùy môi trường triển khai).

## 📂 Cấu trúc dự án
- `ProductionLabor` – phần nghiệp vụ cốt lõi.
- `ProductionLabor.WebUI` – giao diện quản lý, vận hành bởi tổ trưởng, quản đốc và phòng nhân sự.

## 🚀 Tính năng chính
- Tạo danh sách công nhân theo tổ.
- Gán công việc mỗi ngày cho từng công nhân hoặc cả tổ.
- Chọn hệ số công theo loại việc (8h/công).
- Cập nhật hệ số ngày lễ/nghỉ hưởng lương.
- Nhập hoặc gán năng suất (production output).
- Xuất báo cáo tổng công cuối kỳ.
- Tính lương theo công và hệ số sản lượng.
