# Attack Analytics Executive + Technical Report Generator

สคริปต์ **`aa_exec_report.py`** สำหรับดึงข้อมูลจาก **Imperva Attack Analytics API** และสร้างรายงาน **HTML (และ PDF)** ที่อ่านง่าย ทั้งสำหรับผู้บริหารและทีมเทคนิค

---

## 🔑 ฟีเจอร์หลัก

- **ดึงข้อมูล Incident** โดยใช้ API Spec ของ Imperva
- **รองรับ Chunking** (`--chunk-days`) เพื่อหลีกเลี่ยง timeout และ rate limit
- **Filter ได้หลายแบบ**: Severity, Host, Violation, Country, Min-events
- **Aggregation**: สรุป Top Attackers, Tools, Rules, Violations, CVEs
- **Rule-name Mapping**: แสดงชื่อกฎแทนรหัส (`--rules-map rules.json/csv`)
- **MoM Comparison**: เปรียบเทียบกับเดือนก่อนหน้า (`--prev-export`)
- **Report UI**: 
  - Dark Mode toggle 🌓  
  - Privacy Mode (blur IP/Host) 🫣  
  - Export CSV ⬇️  
  - Printable/Export PDF 🖨️  
- **Charts**:
  - Daily Incident Trend  
  - Severity Distribution  
  - Blocked vs Alerted (Stacked Bar)  
  - Incident Heatmap (Day × Hour)  
- **Featured Incidents**: Search + Filter + Copy IP/Host 📋
- **Sample Events**: ดึง event รายละเอียดสำหรับ incident เด่น
- **Slack Notify**: ส่งสรุปรายงานเข้า Slack (`--slack-webhook`)
- **Config Preload**: โหลดค่า default จากไฟล์ YAML (`--config`)

---

## ⚙️ การติดตั้ง

```bash
git clone https://github.com/<your-username>/<your-repo>.git
cd <your-repo>

# แนะนำสร้าง virtualenv
python3 -m venv venv
source venv/bin/activate

# ติดตั้ง dependencies
pip install requests python-dateutil pyyaml
