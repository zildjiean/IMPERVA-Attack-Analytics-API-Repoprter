# Attack Analytics Daily/Range Report (Imperva Cloud WAF)

รายงาน HTML สำหรับ **Imperva Cloud WAF – Attack Analytics** ที่สร้างจาก **API response เท่านั้น** เพื่อสรุปภาพรวมเหตุการณ์และการโจมตีรายวัน/ช่วงเวลา ในรูปแบบที่นำไปนำเสนอผู้บริหารได้ทันที

> สคริปต์หลัก: `aa_report.py`
> ผลลัพธ์: ไฟล์ HTML เดียว เปิดได้ในเบราว์เซอร์ (มีโหมด Light/Dark, ปรับขนาดฟอนต์, ตารางค้นหา/เรียง/ดาวน์โหลด CSV/JSON, กราฟ Chart.js)

---

## ✨ ไฮไลต์ของรายงาน

* **KPI รวม**

  * Threat Events = ผลรวม **`events_count`**
  * Block Events = ผลรวมจาก `violations_blocked.value`
  * High-Security Incidents = นับ incident ที่ `severity ∈ {CRITICAL, MAJOR}`

* **Threat Activities (Stacked by Severity)**
  แสดงเป็นกราฟแท่ง (รายชั่วโมง/รายวัน) โดยกระจาย **`events_count` ของแต่ละ incident ไปยังช่วงเวลาที่ incident นั้น active** ตาม `first_event_time` → `last_event_time` (แจกจ่ายถ่วงน้ำหนักแบบเท่า ๆ กันในบัคเก็ตที่ทับซ้อน)

* **Top 10 / Top N (ใช้แต่ `events_count`)**

  * Signatures → `dominant_attack_violation`
  * Countries → `dominant_attack_country.country`
  * IPs → จาก `attack_ips[].value|count`
  * Target Websites → `dominant_attacked_host.value`
  * Attack Tools → `dominant_attack_tool.name` และ **พ่วง `(type)`** ที่มีหลายค่าได้

* **Per-Website Breakdown**
  เลือกเว็บที่ต้องการ (`--breakdown-hosts`) แสดงการ์ดสรุป (ตาราง + donut chart) ของ **Signature/Country/IP/Tool** สำหรับเว็บนั้น ๆ
  การ์ด **ย่อ/ขยาย** ได้ และมีปุ่ม **Expand All / Collapse All**

* **UI พร้อมใช้งานจริง**

  * Light/Dark theme toggle, ปรับฟอนต์ A-/A+
  * ตารางมีช่องกรอง, sort, และ **ดาวน์โหลด CSV/JSON**
  * กราฟ donut ถูกคุมขนาด ไม่ทำให้เลย์เอาต์เพี้ยน

* **นโยบายข้อมูลว่าง**
  ฟิลด์ที่ว่าง/ไม่มีค่า แสดงเป็น **`Other`** และจัดไว้ **บรรทัดล่างสุด** ของแต่ละรายการ

---

## 🔧 การติดตั้ง

ต้องมี Python 3.8+
แนะนำให้ใช้ virtualenv

```bash
python3 -m venv venv
source venv/bin/activate
pip install certifi  # ถ้าต้องการใช้ CA bundle ของ certifi
```

> ไม่มี dependency อื่น (ใช้ `urllib`/`ssl` ในมาตรฐาน)

---

## 🔐 ตัวแปรแวดล้อม (สะดวก)

```bash
export IMPERVA_API_ID="YOUR_API_ID"
export IMPERVA_API_KEY="YOUR_API_KEY"
```

หรือส่งผ่าน argument ก็ได้

---

## ▶️ การใช้งานพื้นฐาน

```bash
python3 aa_report.py \
  --api-id 123456 \
  --api-key xxxxxx \
  --caid 2317715 \
  --date 2025-08-01 \
  --end-date 2025-08-15 \
  --tz Asia/Bangkok \
  --granularity hour \
  --out report.html
```

เปิด `report.html` ในเบราว์เซอร์ได้ทันที

---

## ⚙️ Options ทั้งหมด

| Option                                        | คำอธิบาย                                                                      |
| --------------------------------------------- | ----------------------------------------------------------------------------- |
| `--api-id` / `--api-key`                      | ค่า API ของ Imperva (หรือใช้ `IMPERVA_API_ID`/`IMPERVA_API_KEY`)              |
| `--caid <int>`                                | Customer Account ID                                                           |
| `--date YYYY-MM-DD`                           | วันที่เริ่มต้น                                                                |
| `--end-date YYYY-MM-DD`                       | วันที่สิ้นสุด (ถ้าไม่ใส่ = วันเดียวกับ `--date`)                              |
| `--tz <IANA TZ>`                              | Timezone (เช่น `Asia/Bangkok`)                                                |
| `--granularity {hour,day}`                    | ความละเอียดของกราฟ Threat Activities                                          |
| `--severity-filter LIST`                      | กรอง incident ตาม severity (เช่น `CRITICAL,MAJOR`)                            |
| `--breakdown-limit <N>`                       | จำกัด Top N ของทุกตาราง/โดนัท (ค่าเริ่มต้น 10)                                |
| `--breakdown-hosts host1,host2`               | ระบุรายเว็บที่จะทำ breakdown (ถ้าไม่ใส่ จะใช้ Top Hosts ที่พบ ยกเว้น `Other`) |
| `--mask-ips`                                  | เปิดการ mask IP ในตาราง (ค่าปริยาย `/24`)                                     |
| `--mask-cidr <int>`                           | เลือกระดับการ mask IP (8/16/24 …)                                             |
| `--theme {dark,light,auto}`                   | ธีมเริ่มต้นของรายงาน                                                          |
| `--out <file.html>`                           | ชื่อไฟล์เอาต์พุต (ถ้าไม่ใส่ จะตั้งชื่อจาก CAID + ช่วงวันที่)                  |
| `--timeout <sec>`                             | HTTP timeout                                                                  |
| `--concurrency <N>`                           | จำนวน thread ดึง incident stats                                               |
| `--https-proxy URL`                           | กำหนด proxy                                                                   |
| `--max-retries <N>` / `--retry-backoff <sec>` | นโยบาย retry                                                                  |
| `--ca-bundle <path>`                          | ใช้ไฟล์ CA bundle ขององค์กร                                                   |
| `--use-certifi`                               | ใช้ CA bundle จาก `certifi`                                                   |
| `--insecure`                                  | ปิดการตรวจสอบใบรับรอง (เฉพาะทดสอบ)**ไม่แนะนำ**                                |

---

## 🧮 แผนรวมข้อมูล (Mapping → API JSON)

* **Severity** → `severity` (ใช้แยกสีในกราฟ)
* **Signature** → `dominant_attack_violation`
* **Events/Count** → `events_count` (และ `violations_blocked.value` สำหรับ Block Events)
* **Country** → `dominant_attack_country.country`
* **Target Website** → `dominant_attacked_host.value`
* **Attack Tool** → `dominant_attack_tool.name` + `(type)` จาก `dominant_attack_tool.type`
* **Threat Activity Timeline** → ใช้ `first_event_time`, `last_event_time` (epoch ms) แจกจ่าย `events_count` ลงบัคเก็ต
* ค่าใดไม่มี/ว่าง → **`Other`**

> รายงานนี้ **ไม่สร้าง/เดาข้อมูล** — ทุกตัวเลขอ้างอิงจาก API response เท่านั้น

---

## 📊 ตัวอย่างคำสั่งยอดนิยม

### รายวันเดียว (กราฟรายชั่วโมง)

```bash
python3 aa_report.py --caid 2317715 \
  --date 2025-08-24 --tz Asia/Bangkok --granularity hour \
  --out report_2025-08-24.html
```

### ช่วง 2 สัปดาห์ + กรองเฉพาะ CRITICAL/MAJOR + ระบุเว็บที่จะ breakdown

```bash
python3 aa_report.py --caid 2317715 \
  --date 2025-08-01 --end-date 2025-08-15 \
  --severity-filter CRITICAL,MAJOR \
  --breakdown-hosts www.example.com,api.example.com \
  --out critical_major.html
```

### แก้ปัญหา SSL ขององค์กร

```bash
python3 aa_report.py ... --use-certifi
# หรือ
python3 aa_report.py ... --ca-bundle /path/to/internal-ca.pem
# (ทดสอบเท่านั้น)
python3 aa_report.py ... --insecure
```

---

## 🧩 โครงสร้างไฟล์ผลลัพธ์

* HTML เดียว (self-contained *ยกเว้น* Chart.js โหลดจาก CDN)
* ส่วนต่าง ๆ: KPI / Threat Activities / Top Signatures / Top Countries / Top IPs / Top Hosts / Top Tools / Per-Website
* ทุกตารางมีปุ่มค้นหา เรียงคอลัมน์ และดาวน์โหลด CSV/JSON

---

## 🔎 การวินิจฉัยปัญหา (Troubleshooting)

* **กราฟไม่ขึ้น / หน้าว่าง**
  เปิด DevTools Console ดู error:

  * ถ้าเน็ตองค์กรบล็อก CDN → ให้เปิดสิทธิ์ `cdn.jsdelivr.net` (ตอนนี้ยังไม่มีโหมด offline)
  * ไม่มี incident ในช่วงเวลาที่เลือก → จะขึ้นแบนเนอร์แจ้ง “No Threat Activities”

* **SSL: CERTIFICATE\_VERIFY\_FAILED**
  ใช้ `--use-certifi` หรือ `--ca-bundle <ไฟล์ CA>`
  *(หลีกเลี่ยง `--insecure` ในโปรดักชัน)*

* **ค่า IP ทั้งหมดเป็น 0**
  ตรวจสอบว่าช่วงวันที่ครอบคลุม incident จริง และ API ของ incident stats ถูกเรียกสำเร็จ (สคริปต์จะแจ้ง “Partial data …” หากดึงบาง incident ไม่สำเร็จ)

---

## 🔒 ความปลอดภัยและความเป็นส่วนตัว

* สคริปต์อ่านข้อมูลผ่าน HTTPS เท่านั้น
* ไม่มีการส่งข้อมูลไปที่อื่น ไม่เก็บคีย์/ผลลัพธ์ถาวร
* รองรับ proxy และ CA ขององค์กร

---

## 🗺️ สิ่งที่ยัง **ไม่รองรับ** (Roadmap)

> ตามข้อตกลงงานล่าสุด— **ยังไม่ทำ** ฟีเจอร์ด้านล่าง

* แยก `--website-limit` ออกจาก `--breakdown-limit`
* โหมด `--non-interactive` / `--no-cdn` (offline / air-gap)
* `Dockerfile` + ตัวอย่าง `cron`/systemd timer สำหรับ daily job
* ส่งออก PDF (`--export-pdf`) ด้วย headless Chrome

---

## 🧾 ใบอนุญาต

สำหรับใช้งานภายในองค์กร/โปรเจ็กต์นี้เท่านั้น

---

## 🙋 FAQ สั้น ๆ

* **ทำไมเปอร์เซ็นต์บางตารางไม่ลงตัว 100%?**
  ปัดเศษทศนิยมและการจัดกลุ่ม `Other` อาจทำให้รวมน้อย/มากกว่าเล็กน้อย

* **ค่าที่ว่างแสดงเป็นอะไร?**
  ทุกฟิลด์ว่างจะแสดงเป็น **`Other`** และถูกวางไว้แถวล่างสุดเสมอ

* **ทำไม Threat Activities ไม่เท่าค่า events\_count ตรง ๆ?**
  กราฟ “แจกจ่าย” `events_count` ของ incident ไปตามเวลาที่ incident นั้น active เพื่อสะท้อนกิจกรรมในแต่ละช่วง

---

## 💬 ติดต่อ/แก้ไขเพิ่มเติม

ต้องการปรับหัวตาราง/สี/ขนาดโดนัท/ฟอนต์/การจัดวาง หรือเพิ่มช่องทาง mask IP/เลือกเว็บอัตโนมัติ บอกได้เลยครับ เดี๋ยวจัดให้!
