# Ảnh FAT32 dùng cho đồ án

- `fat32/`: ảnh mẫu công khai (`clean.img`, `case1.img`, `case2.img`, `case3.img`) và các JSON đáp án tương ứng. Lấy từ `Sample_Image/mau/fat32/` do giảng viên cung cấp.
- `NEEDFORFOOD/fat32/`: ảnh chính thức của nhóm NEEDFORFOOD, không có JSON đáp án.

Ảnh và đáp án được lưu cục bộ, không đưa vào Git.

Chạy tự kiểm tra trên bộ ảnh mẫu công khai:

```sh
python3 selftest.py --mau samples/fat32
```

Không chạy `selftest.py` trên bộ ảnh nhóm vì công cụ này cần JSON đáp án. Dùng `recover.py --image <đường_dẫn_ảnh> --case <1|2|3> --out <thư_mục_kết_quả>` cho từng ảnh nhóm; nhật ký và kết quả phục hồi cần được kiểm chứng riêng.
