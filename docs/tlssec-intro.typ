#import "@preview/fletcher:0.5.8" as fletcher: node, edge
#import "@preview/shadowed:0.2.0": shadowed
#import "@preview/codly:1.3.0": codly-init, codly

#set heading(numbering: "1.1)")
#set text(font: ("Sarabun", "Libertinus Serif"))
#show link: underline

#show raw: it => box(
  fill: rgb("ddd"),
  inset: 2pt,
  baseline: 2pt,
  radius: 2pt,
  it
)

#let diagram(..args, shadow: (:)) = {
  let shadow = (
    radius: 4pt,
    inset: 1em,
  ) + shadow
  shadowed(..shadow)[#fletcher.diagram(..args)]
}

#show: codly-init.with()
#codly(
  number-format: none,
)

= TLS Security Monitoring (`tlssec`)

#quote(block: true)[
  `tlssec` เป็นชุดเครื่องมือสำหรับสำรวจและเฝ้าระวังความปลอดภัยในการตั้งค่า Transport Layer Security (TLS)
  ให้ความสะดวกในการเก็บข้อมูลอย่างต่อเนื่อง, ค้นหาข้อมูล, และประมวลผลทางสถิติ เพื่อ
]

เครื่องมือ opensource นี้อยู่ในระหว่างการพัฒนาโดยมีผู้พัฒนาหลักจาก
#link("https://www.nectec.or.th/")[ศูนย์เทคโนโลยีอิเล็กทรอนิกส์และคอมพิวเตอร์แห่งชาติ (NECTEC)]

== Installation

+ Install docker engine.
  - ผู้ใช้ Linux สามารถ #link("https://docs.docker.com/engine/install/")[ติดตั้ง Docker Engine] ได้โดยตรง.
  - ผู้ใช้ Windows สามารถติดตั้ง Docker Engine ผ่าน
    #link("https://docs.docker.com/desktop/setup/install/windows-install/")[Docker Desktop for Windows]
+ Download source จาก tlssec github repository

  ```shell
  git clone https://github.com/nectec-pqc/tls-security-monitoring.git
  cd tls-security-monitoring
  docker compose build
  ```
+ จากนั้นสามารถเข้าสู่สภาพแวดล้อมพร้อมใช้งานใน container ได้เพียงรันคำสั่งเดียว คือ

  ```shell
  docker compose run --rm dev-cli
  ```

  ทั้งนี้ การรันครั้งแรกอาจจะใช้เวลานานเป็นพิเศษ เนื่องจากต้อง download dependencies,
  สร้าง `tlssec` image และติดตั้งข้อมูลเริ่มต้นใน database
  แต่เมื่อเสร็จแล้ว ผู้ใช้จะสามารถสั่งคำสั่ง `tlssec` CLI ในสภาพแวดล้อมนี้ เพื่อใช้เครื่องมือย่อยต่างๆตามหัวข้อถัดไปได้

== Basic usage of Command Line Interface (CLI)

สมมุติว่าต้องการเก็บข้อมูล TLS security ของ websites ตามรายชื่อใน file CSV
โดยเริ่มเก็บข้อมูลทันที 1 รอบ แล้วรายงานผล
ขั้นแรกเริ่มจากจัด format ของ file ให้ถูกต้องตามตัวอย่างด้านล่าง

#codly(
  header: [*domain-names.csv*],
  header-cell-args: (align: center, ),
)
```
example.com
example.net
```

จากนั้นเพิ่มรายชื่อ domain names เข้าไปเป็นเป้าหมายใน database โดยคำสั่ง

```shell
tlssec targets add domain-names.csv
```

จากนั้นเรียกคำสั่ง

```shell
tlssec scan
```

เพื่อเริ่มต้นเก็บข้อมูลทุกเป้าหมายทันที
ทั้งนี้ `tlssec scan` จะไม่เก็บข้อมูลของแต่ละเป้าหมายถี่เกินที่ตั้งไว้
(หรือ ทุก 7 วันหากไม่ได้ตั้ง)
เพื่อไม่ให้เกิดความรบกวนต่อเป้าหมายบ่อยเกินจำเป็น
และให้สามารถทำซ้ำเพื่อทำงานต่อจากการหยุดการทำงานโดยไม่คาดคิดได้

เมื่อการเก็บข้อมูลเสร็จแล้ว สามารถผลิตรายงานเป็น file ได้ด้วยคำสั่ง

```shell
tlssec report
```

file ที่ถูกสร้างขึ้นจะปรากฎใน `/workdir` directory
ผู้ใช้สามารถอ่านคำอธิบายคำสั่งย่อยต่างๆและตัวเลือกเพิ่มเติมในการใช้งานผ่าน option `--help` เช่น

```shell
tlssec report --help
```

== Clean up

หลังใช้งานควรจะหยุดการให้บริการ background services (เช่น database) ด้วยคำสั่ง

```shell
docker compose down
```

โดยข้อมูลจะถูกเก็บไว้อัตโนมัติ ใช้งานต่อได้ในครั้งถัดไป
แต่หากต้องการจะลบข้อมูลทั้งหมดแล้วเริ่มใหม่ตั้งแต่ต้น ให้ใช้คำสั่ง

```shell
docker compose down --volumes
```

// TODO: Architecture
