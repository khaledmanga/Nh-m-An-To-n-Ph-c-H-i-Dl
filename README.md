# Đồ án giữa kỳ môn An toàn và phục hồi dữ liệu

- **Nhóm**: `NEEDFORFOOD`

- **Hệ thống tập tin**: `FAT32`

## Thành viên nhóm

| MSSV | Họ và tên |
| --- | --- |
| 21126020 | Trương Hoàng Kha |
| 22127189 | Phạm Bình Khánh |
| 23127140 | Đặng Nguyễn Duy Tuyên |
| 23127282 | Trần Sở Vinh |

Thông tin cấu hình nhóm nằm trong [nhom.json](nhom.json).

## Cấu trúc repo

| Đường dẫn | Mục đích |
| --- | --- |
| [`bai_lam.py`](bai_lam.py) | Các hàm làm bài của nhóm, được giao diện dòng lệnh [recover.py](recover.py) của giảng viên gọi |
| [`fat32/`](fat32/) | Các module đọc cấu trúc FAT32 dùng chung |
| [`recovery/`](recovery/) | Thuật toán phục hồi cho từng tình huống |
| [`tests/`](tests/) | Các file test cho phần cài đặt của nhóm |
| [`samples/fat32/`](samples/fat32/) | Các ảnh mẫu FAT32 công khai và JSON đáp án tương ứng |
| [`samples/NEEDFORFOOD/fat32/`](samples/NEEDFORFOOD/fat32/) | Các ảnh FAT32 chính thức của nhóm, không có JSON đáp án |
| [`nhom.json`](nhom.json) | Thông tin nhóm và đăng ký phần cộng điểm |
| [`recover.py`](recover.py), [`binio.py`](binio.py), [`tienich.py`](tienich.py), [`selftest.py`](selftest.py) | Giao diện dòng lệnh, đọc/ghi byte, tiện ích và công cụ tự kiểm tra do giảng viên cung cấp |

