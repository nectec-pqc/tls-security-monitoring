# assetfinder

ค้นหา subdomain ของเว็บไซต์เป้าหมาย ใช้สำหรับงาน Bug Bounty / Pentest

## ติดตั้ง

```bash
git clone https://github.com/tomnomnom/assetfinder.git
cd assetfinder
go mod init github.com/tomnomnom/assetfinder
go mod tidy
go build -o assetfinder .
```

## วิธีใช้

```bash
# ค้นหา subdomain ทั้งหมด
assetfinder example.com

# แสดงเฉพาะ subdomain (ไม่เอา domain อื่นที่เกี่ยวข้อง)
assetfinder --subs-only example.com

# อ่านจากไฟล์
cat domains.txt | assetfinder --subs-only

# รันแบบไม่ต้อง build
go run . example.com
```

ผลลัพธ์จะออกมาทีละบรรทัด สามารถ pipe ต่อได้:

```bash
assetfinder --subs-only example.com | sort -u > subdomains.txt
```

## ตั้งค่า API Key (ไม่บังคับ)

ถ้าไม่ตั้ง source นั้นจะถูกข้ามไปเอง โปรแกรมยังใช้งานได้ปกติ

```bash
export VT_API_KEY="xxx"           # VirusTotal
export FB_APP_ID="xxx"            # Facebook
export FB_APP_SECRET="xxx"        # Facebook
```

## Rate Limit

| Source       | Limit                | ต้องใช้ Key                    | สถานะ   |
|:-------------|:---------------------|:-----------------------------|:--------:
| crt.sh       | ไม่จำกัด               | —                            | ✅ ใช้ได้ |
| HackerTarget | 100 req/วัน           | —                            | ✅ ใช้ได้ |
| urlscan.io   | 30 req/นาที           | —                            | ✅ ใช้ได้ |
| VirusTotal   | 4 req/นาที (500/วัน)   | `VT_API_KEY`                 | ✅ ใช้ได้ |
| Facebook     | ~200 req/ชม.         | `FB_APP_ID` `FB_APP_SECRET`  | ✅ ใช้ได้ |
| CertSpotter  | —                    | —                            | ❌ ปิดแล้ว|
| ThreatCrowd  | —                    | —                            | ❌ ปิดแล้ว|
| BufferOverrun| —                    | —                            | ❌ ปิดแล้ว|
| Spyse        | —                    | —                            | ❌ ปิดแล้ว|

> โปรแกรมมี rate limiter ในตัว จำกัดไว้ 1 req/วินาที/source เพื่อป้องกันโดน block

## ตรวจสอบ Rate Limit ด้วยตัวเอง

```bash
# urlscan.io
curl -sD - -o /dev/null "https://urlscan.io/api/v1/search/?q=domain:example.com" | grep -i rate

# HackerTarget
curl -sD - -o /dev/null "https://api.hackertarget.com/hostsearch/?q=example.com" | grep -i api
```

## License

MIT - Tom Hudson
