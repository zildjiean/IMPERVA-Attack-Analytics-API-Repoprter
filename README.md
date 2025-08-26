# Imperva Cloud WAF – Attack Analytics Report (HTML)

สร้างรายงาน **Attack Analytics** แบบ **HTML เดียว** จาก Imperva Cloud WAF โดยใช้ **ข้อมูลจาก API เท่านั้น** พร้อม UI สำหรับผู้บริหาร: KPI, กราฟ Threat Activities (stacked), Top N (Signatures/Countries/IPs/Hosts/Tools) และ **Per-Website breakdown** ที่ย่อ–ขยายได้

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
* [การแมประหว่างฟิลด์รายงาน ↔︎ API](#การแมประหว่างฟิลด์รายงาน--api)
* [การแก้ปัญหา](#การแก้ปัญหา)
* [Roadmap / ยังไม่รองรับ](#roadmap--ยังไม่รองรับ)
* [Contributing](#contributing)
* [Security / Privacy](#security--privacy)
* [License](#license)

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
