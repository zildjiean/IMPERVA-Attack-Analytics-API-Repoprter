# IMPERVA Attack Analytics API Reporter

🔒 **เครื่องมือสร้างรายงานการโจมตีจาก Imperva Attack Analytics API**

แอปพลิเคชัน Flask สำหรับสร้างรายงานการโจมตีจาก Imperva Attack Analytics API ในรูปแบบ HTML ที่สวยงามและใช้งานง่าย

## ✨ ฟีเจอร์หลัก

- 📊 **สร้างรายงานอัตโนมัติ** จาก Imperva Attack Analytics API
- 🎨 **รายงาน HTML สวยงาม** พร้อมกราฟและตาราง
- 📱 **Responsive Design** ใช้งานได้ทุกอุปกรณ์
- 🔄 **ติดตามสถานะ** การสร้างรายงานแบบ Real-time
- 📥 **ดาวน์โหลดรายงาน** ในรูปแบบ HTML
- 👀 **ดูรายงานออนไลน์** ผ่านเว็บเบราว์เซอร์
- 🗑️ **ลบรายงาน** ที่ไม่ต้องการออกได้
- 🐳 **Docker Support** สำหรับการ Deploy ที่ง่ายดาย

## 🚀 การติดตั้งและใช้งาน

### วิธีที่ 1: ใช้งานผ่าน Docker (แนะนำ)

#### ข้อกำหนดเบื้องต้น
- Docker และ Docker Compose

#### ขั้นตอนการติดตั้ง

1. **Clone Repository**
```bash
git clone https://github.com/your-username/IMPERVA-Attack-Analytics-API-Reporter.git
cd IMPERVA-Attack-Analytics-API-Reporter
```

2. **รัน Docker Compose**
```bash
docker-compose up -d
```

3. **เข้าใช้งาน**
   - เปิดเว็บเบราว์เซอร์ไปที่: `http://localhost:5000`

#### คำสั่ง Docker ที่มีประโยชน์

```bash
# ดู logs
docker-compose logs -f

# หยุดการทำงาน
docker-compose down

# รีสตาร์ท
docker-compose restart

# อัปเดตและรีบิลด์
docker-compose up --build -d
```

### วิธีที่ 2: ติดตั้งแบบ Manual

#### ข้อกำหนดเบื้องต้น
- Python 3.8+
- pip

#### ขั้นตอนการติดตั้ง

1. **Clone Repository**
```bash
git clone https://github.com/your-username/IMPERVA-Attack-Analytics-API-Reporter.git
cd IMPERVA-Attack-Analytics-API-Reporter
```

2. **สร้าง Virtual Environment**
```bash
python -m venv venv
source venv/bin/activate  # Linux/Mac
# หรือ
venv\Scripts\activate     # Windows
```

3. **ติดตั้ง Dependencies**
```bash
pip install -r requirements.txt
```

4. **รันแอปพลิเคชัน**
```bash
python app.py
```

5. **เข้าใช้งาน**
   - เปิดเว็บเบราว์เซอร์ไปที่: `http://localhost:5000`

## 📖 วิธีการใช้งาน

### 1. สร้างรายงานใหม่

1. เข้าไปที่หน้าแรกของแอปพลิเคชัน
2. กรอกข้อมูลที่จำเป็น:
   - **Customer Account ID (CAID)**: รหัสบัญชีลูกค้า
   - **API Key**: คีย์สำหรับเข้าถึง API
   - **วันที่รายงาน**: วันที่ต้องการสร้างรายงาน
   - **เขตเวลา**: เขตเวลาสำหรับรายงาน
   - **ธีม**: เลือกธีมสำหรับรายงาน (Light/Dark)
3. คลิก "สร้างรายงาน"
4. รอให้ระบบประมวลผล (อาจใช้เวลาสักครู่)

### 2. ดูรายงานที่สร้างแล้ว

1. คลิก "รายงานที่สร้างแล้ว" ในเมนู
2. ดูรายการรายงานทั้งหมดพร้อมสถานะ
3. สำหรับรายงานที่เสร็จแล้ว สามารถ:
   - **ดูรายงาน**: เปิดรายงานในแท็บใหม่
   - **ดาวน์โหลด**: ดาวน์โหลดไฟล์ HTML
   - **ลบ**: ลบรายงานที่ไม่ต้องการ

### 3. ติดตามสถานะรายงาน

- รายงานที่กำลังประมวลผลจะแสดงสถานะ "กำลังประมวลผล"
- คลิก "ตรวจสอบสถานะ" เพื่อดูความคืบหน้า
- หากเกิดข้อผิดพลาด สามารถคลิก "ดูข้อผิดพลาด" เพื่อดูรายละเอียด

## 🏗️ โครงสร้างโปรเจกต์

```
IMPERVA-Attack-Analytics-API-Reporter/
├── app.py                 # แอปพลิเคชันหลัก Flask
├── aa_report.py          # โมดูลสำหรับสร้างรายงาน
├── requirements.txt      # Python dependencies
├── Dockerfile           # Docker configuration
├── docker-compose.yml   # Docker Compose configuration
├── .dockerignore       # Docker ignore file
├── templates/          # HTML templates
│   ├── index.html     # หน้าแรก
│   ├── reports.html   # หน้ารายงาน
│   ├── 404.html       # หน้า 404
│   └── 500.html       # หน้า 500
├── static/            # Static files
│   ├── css/          # CSS files
│   └── js/           # JavaScript files
├── reports/           # โฟลเดอร์เก็บรายงานที่สร้าง
└── venv/             # Virtual environment
```

## 🔧 การกำหนดค่า

### Environment Variables

- `FLASK_ENV`: โหมดการทำงาน (development/production)
- `PYTHONPATH`: Python path สำหรับ Docker

### Docker Configuration

- **Port**: 5000 (สามารถเปลี่ยนได้ใน docker-compose.yml)
- **Volume**: `./reports:/app/reports` สำหรับเก็บรายงาน
- **Health Check**: ตรวจสอบสถานะแอปพลิเคชันทุก 30 วินาที

## 🛠️ การพัฒนา

### การเพิ่มฟีเจอร์ใหม่

1. Fork repository นี้
2. สร้าง branch ใหม่: `git checkout -b feature/new-feature`
3. Commit การเปลี่ยนแปลง: `git commit -am 'Add new feature'`
4. Push ไปยัง branch: `git push origin feature/new-feature`
5. สร้าง Pull Request

### การรัน Development Server

```bash
# ใช้ Virtual Environment
source venv/bin/activate
export FLASK_ENV=development
python app.py
```

## 🐛 การแก้ไขปัญหา

### ปัญหาที่พบบ่อย

1. **Port 5000 ถูกใช้งานแล้ว**
   - เปลี่ยน port ใน docker-compose.yml หรือหยุดโปรแกรมที่ใช้ port 5000

2. **ไม่สามารถเชื่อมต่อ API ได้**
   - ตรวจสอบ API Key และ CAID
   - ตรวจสอบการเชื่อมต่ออินเทอร์เน็ต

3. **รายงานไม่แสดงผล**
   - ตรวจสอบ logs: `docker-compose logs -f`
   - ตรวจสอบไฟล์ในโฟลเดอร์ reports/

## 📝 License

MIT License - ดูรายละเอียดใน [LICENSE](LICENSE) file

## 🤝 การสนับสนุน

หากพบปัญหาหรือต้องการความช่วยเหลือ:

1. เปิด [Issue](https://github.com/your-username/IMPERVA-Attack-Analytics-API-Reporter/issues) ใน GitHub
2. ตรวจสอบ [Wiki](https://github.com/your-username/IMPERVA-Attack-Analytics-API-Reporter/wiki) สำหรับคำแนะนำเพิ่มเติม

## 🙏 ขอบคุณ

- [Flask](https://flask.palletsprojects.com/) - Web framework
- [Bootstrap](https://getbootstrap.com/) - CSS framework
- [Chart.js](https://www.chartjs.org/) - Charting library
- [Font Awesome](https://fontawesome.com/) - Icons

---

**Made with ❤️ for Imperva Attack Analytics**

> สคริปต์หลัก: `aa_report.py`
> เอาต์พุต: HTML เปิดได้ทันที (รองรับ Dark/Light, ปรับฟอนต์, ตารางค้นหา/เรียง, ดาวน์โหลด CSV/JSON)

---

## ตารางเนื้อหา

* [คุณสมบัติ](#คุณสมบัติ)
* [สกรีนช็อต](#สกรีนช็อต)
* [ข้อกำหนดระบบ](#ข้อกำหนดระบบ)
* [การติดตั้ง](#การติดตั้ง)
* [วิธีใช้งานแบบรวดเร็ว](#วิธีใช้งานแบบรวดเร็ว)
* [ออปชันทั้งหมด](#ออปชันทั้งหมด)

---

## คุณสมบัติ

* **KPI รวม**
  Threat Events (รวม `events_count`), Block Events (รวม `violations_blocked.value`), จำนวน High-Security Incidents (CRITICAL+MAJOR)
* **Threat Activities (stacked)**
  กราฟแท่งรายชั่วโมง/รายวัน โดย **แจกจ่าย `events_count` ของ incident** ลงช่วงเวลาที่ incident active ตาม `first_event_time → last_event_time`
* **Top N ทั้งหมดอิง `events_count`**
  Signatures / Countries / IPs / Hosts / Tools *(Tools พ่วง `(type)` หากมีหลายค่า)*
* **Per-Website breakdown**
  เลือกเว็บที่ต้องการ (`--breakdown-hosts`) แสดงการ์ด (ตาราง + donut chart) ย่อ–ขยายได้
* **UI พร้อมใช้งาน**
  Dark/Light toggle, A-/A+ font, ตารางค้นหา/เรียง และ **ดาวน์โหลด CSV/JSON**
* **จัดการค่าที่ว่าง**
  ฟิลด์ว่าง ⇒ แสดงเป็น **`Other`** และไว้ **บรรทัดสุดท้าย** ทุกตาราง/กราฟ
* **เครือข่าย/ความปลอดภัย**
  รองรับ proxy / custom CA / certifi / retry / timeout

---

## สกรีนช็อต

<img width="1625" height="1183" alt="image" src="https://github.com/user-attachments/assets/6218f9b5-ddaa-4aff-985a-68be7e31b9ad" />


## ข้อกำหนดระบบ

* Python **3.8+**
* อินเทอร์เน็ตสำหรับโหลด Chart.js จาก CDN (โหมดออฟไลน์/air-gap ยังไม่รองรับ — ดู Roadmap)

---

## การติดตั้ง

```bash
git clone https://github.com/<your-org>/<your-repo>.git
cd <your-repo>

python3 -m venv venv
source venv/bin/activate

# ไม่บังคับ แต่แนะนำหากต้องการ CA bundle มาตรฐาน
pip install certifi
```

ตั้งค่าคีย์แบบ environment variables (สะดวก):

```bash
export IMPERVA_API_ID="YOUR_API_ID"
export IMPERVA_API_KEY="YOUR_API_KEY"
```

> หรือส่งผ่าน argument `--api-id` / `--api-key` ขณะรันก็ได้

---

## วิธีใช้งานแบบรวดเร็ว

รายงานช่วง 1–15 ส.ค. 2025 แบบรายชั่วโมง:

```bash
python3 aa_report.py \
  --api-id "$IMPERVA_API_ID" \
  --api-key "$IMPERVA_API_KEY" \
  --caid 2317715 \
  --date 2025-08-01 --end-date 2025-08-15 \
  --tz Asia/Bangkok \
  --granularity hour \
  --out report.html
```

ตัวอย่างกรองเฉพาะ **CRITICAL,MAJOR** และระบุ **เว็บ** ที่ต้องการ breakdown:

```bash
python3 aa_report.py \
  --caid 2317715 \
  --date 2025-08-01 --end-date 2025-08-15 \
  --severity-filter CRITICAL,MAJOR \
  --breakdown-hosts www.example.com,api.example.com \
  --out critical-major.html
```

ปัญหา SSL ในองค์กร:

```bash
# ใช้ CA ของ certifi
python3 aa_report.py ... --use-certifi

# หรือระบุ CA bundle ขององค์กร
python3 aa_report.py ... --ca-bundle /path/to/ca.pem

# (เฉพาะทดสอบ) ปิด verify
python3 aa_report.py ... --insecure
```

---

## ออปชันทั้งหมด

| ออปชัน                                                | คำอธิบาย                                                                           |
| ----------------------------------------------------- | ---------------------------------------------------------------------------------- |
| `--api-id`, `--api-key`                               | API credentials (หรือใช้ env `IMPERVA_API_ID`, `IMPERVA_API_KEY`)                  |
| `--caid <int>`                                        | Customer Account ID                                                                |
| `--date YYYY-MM-DD`                                   | วันที่เริ่มต้น                                                                     |
| `--end-date YYYY-MM-DD`                               | วันที่สิ้นสุด (ไม่ใส่ = ใช้วันเดียวกับ `--date`)                                   |
| `--tz <IANA>`                                         | ไทม์โซน (เช่น `Asia/Bangkok`)                                                      |
| `--granularity {hour,day}`                            | ความละเอียดของกราฟ Threat Activities                                               |
| `--severity-filter LIST`                              | กรอง incident ตาม severity (เช่น `CRITICAL,MAJOR`)                                 |
| `--breakdown-limit <N>`                               | จำกัด Top N ของทุกตาราง/กราฟ (ดีฟอลต์ 10)                                          |
| `--breakdown-hosts host1,host2`                       | ระบุเว็บสำหรับ Per-Website breakdown (ไม่ใส่ = ใช้ Top Hosts ที่พบ ยกเว้น `Other`) |
| `--mask-ips`                                          | เปิดการ mask IP ในตาราง (ดีฟอลต์ `/24`)                                            |
| `--mask-cidr <int>`                                   | เลือกระดับ mask IP (8/16/24 …)                                                     |
| `--theme {dark,light,auto}`                           | ธีมเริ่มต้นของรายงาน                                                               |
| `--out file.html`                                     | ไฟล์ผลลัพธ์ (ไม่ใส่ = ตั้งชื่ออัตโนมัติจาก CAID+ช่วงวัน)                           |
| `--timeout <sec>`                                     | HTTP timeout                                                                       |
| `--concurrency <N>`                                   | จำนวนเธรดดึง incident stats                                                        |
| `--https-proxy URL`                                   | Proxy (เช่น `https://user:pass@host:port`)                                         |
| `--max-retries <N>` / `--retry-backoff <sec>`         | Retry policy                                                                       |
| `--ca-bundle <path>` / `--use-certifi` / `--insecure` | ตั้งค่า SSL ตามนโยบายองค์กร                                                        |

---

## การแมประหว่างฟิลด์รายงาน ↔︎ API

* **Severity** → `severity` *(ใช้จัดสีในกราฟ)*
* **Signatures** → `dominant_attack_violation`
* **Events** → `events_count` *(ทุก Top/ตาราง/กราฟใช้ค่านี้)*
* **Countries** → `dominant_attack_country.country`
* **Target Websites** → `dominant_attacked_host.value`
* **Attack Tools** → `dominant_attack_tool.name` + `(type)` (แสดงหลายชนิดได้ เช่น `(Bot)(Library)`)
* **Threat Activities timeline** → แจกจ่าย `events_count` ตาม `first_event_time` → `last_event_time` ลงบัคเก็ตเวลา
* **ค่าใดว่าง** → แสดงเป็น **`Other`** และจัดไว้ลำดับท้าย
