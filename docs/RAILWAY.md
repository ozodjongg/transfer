# Railway'ga deploy qilish va release chiqarish

Bu qo'llanma ikki narsani tushuntiradi:

1. Relay serverni (`cmd/server`) Railway'ga joylash.
2. GitHub Releases sahifasiga avtomatik build chiqarish.

> **Muhim:** relay server **HTTP emas, oddiy TCP** protokolda ishlaydi. Shuning
> uchun Railway'dagi oddiy "Public Domain" (`*.up.railway.app`, HTTPS) **ishlamaydi**.
> Sizga **TCP Proxy** kerak bo'ladi.

---

## 1. Railway'ga deploy

### 1.1. Loyihani yaratish

1. <https://railway.com> ga GitHub akkaunt orqali kiring.
2. **New Project → Deploy from GitHub repo** ni bosing va `transfer` repositoriyasini tanlang.
   (Agar ro'yxatda ko'rinmasa, **Configure GitHub App** orqali Railway'ga repoga ruxsat bering.)
3. Railway repodagi `railway.json` faylini o'qiydi va `Dockerfile` orqali build qiladi.
   Qo'shimcha build sozlamasi shart emas.

### 1.2. TCP Proxy yoqish

1. Servisni oching → **Settings → Networking**.
2. **Public Networking** bo'limida **TCP Proxy** ni tanlang.
3. **Target port** ga `8080` ni kiriting (Dockerfile'dagi `-addr :8080`).
4. Railway sizga shunga o'xshash manzil beradi:

   ```text
   shortline.proxy.rlwy.net:12345
   ```

   Bu — klientlar ulanadigan relay manzili. Uni saqlab qo'ying.

### 1.3. Muhim sozlamalar

- **Replicas = 1** bo'lsin. Server xona (room) holatini xotirada saqlaydi; 2 ta replika
  bo'lsa, yuboruvchi va qabul qiluvchi turli nusxalarga tushib qolib, bir-birini topa olmaydi.
- **Region**: foydalanuvchilarga eng yaqin regionni tanlang (Settings → Region).
- **Trafik**: relay orqali o'tgan fayl serverga kiradi va chiqadi, ya'ni 1 GB fayl ≈ 2 GB
  trafik. Railway egress (chiquvchi trafik) uchun pul oladi — tarif sahifasini tekshiring.
  LAN va Internet-P2P yo'llari ishlaganda fayl relay orqali o'tmaydi.

### 1.4. Server parametrlarini o'zgartirish (ixtiyoriy)

Standart parametrlar `Dockerfile` dagi `CMD` qatorida. Ularni Railway'da o'zgartirish
uchun **Settings → Deploy → Custom Start Command** ga to'liq buyruq yozing, masalan:

```bash
/app/transfer-server -addr :8080 -max-transfer-gb 5 -max-rooms 50
```

Barcha parametrlar: `-max-transfer-gb`, `-room-ttl`, `-transfer-timeout`, `-resume-grace`,
`-max-rooms`, `-max-manifest-mb`, `-max-connections`, `-max-handshakes-per-minute`,
`-max-pake-attempts`.

### 1.5. Tekshirish

- **Deployments → View Logs** da server ishga tushgani haqidagi log ko'rinishi kerak.
- Kompyuteringizdan port ochiqligini tekshiring:

  ```bash
  # Linux/macOS
  nc -vz shortline.proxy.rlwy.net 12345
  # Windows PowerShell
  Test-NetConnection shortline.proxy.rlwy.net -Port 12345
  ```

### 1.6. Avtomatik deploy

Railway standart holatda ulangan branchga (odatda `main`) har bir push qilinganda
qayta deploy qiladi. Branchni **Settings → Source** da o'zgartirish mumkin.

---

## 2. Klientni Railway serverga ulash

Klient papkasidagi `config.json` da `server` ni Railway TCP Proxy manziliga almashtiring:

```json
{
  "server": "shortline.proxy.rlwy.net:12345",
  "tls": { "enabled": false, "insecure_skip_verify": false }
}
```

`tls.enabled` ni `false` qoldiring: Railway TCP Proxy TLS qo'shmaydi, server esa TLS
sertifikatisiz ishga tushirilgan. (Ma'lumot baribir AES-256-GCM bilan uchdan-uchgacha
shifrlangan.)

Tekshirish:

```bash
transfer config
transfer send test.txt
```

---

## 3. GitHub Releases'ga avtomatik build

`.github/workflows/release.yml` workflow'i `v` bilan boshlanadigan tag push qilinganda:

1. `go vet` va `go test` ni ishga tushiradi;
2. Windows, Linux, macOS (amd64 va arm64) uchun `transfer` va `server` ni build qiladi;
3. har bir platforma uchun arxiv yaratadi (Windows — `.zip`, boshqalar — `.tar.gz`),
   ichida `transfer`, `server`, `config.json`, `README.md`;
4. `SHA256SUMS.txt` yaratadi;
5. hammasini yangi GitHub Release'ga yuklaydi.

### 3.1. Relay manzilini release'ga "tikib" qo'yish (tavsiya etiladi)

Foydalanuvchilar `config.json` ni qo'lda o'zgartirmasligi uchun:

1. GitHub → repo → **Settings → Secrets and variables → Actions → Variables** tab.
2. **New repository variable**:
   - Name: `TRANSFER_SERVER`
   - Value: `shortline.proxy.rlwy.net:12345`

Shundan keyin har bir release ichidagi `config.json` avtomatik shu manzil bilan chiqadi.
Variable qo'yilmasa, `config.json` repodagidek (`localhost:8080`) qoladi.

### 3.2. Release chiqarish

```bash
git tag v8.0.0
git push origin v8.0.0
```

Keyin GitHub → **Actions** tabida "Release" workflow'ini kuzating. Tugagach,
**Releases** sahifasida `v8.0.0` paydo bo'ladi.

Release'siz faqat build'ni sinab ko'rish uchun: **Actions → Release → Run workflow**.
Bunda fayllar faqat workflow artifact sifatida saqlanadi.

### 3.3. Muammolar

| Belgi | Sabab / yechim |
| --- | --- |
| Workflow `Resource not accessible by integration` bilan yiqiladi | **Settings → Actions → General → Workflow permissions** da "Read and write permissions" ni yoqing. |
| Klient `connection refused` / timeout | `config.json` dagi port TCP Proxy bergan port ekanini, target port `8080` ekanini tekshiring. |
| Yuboruvchi va qabul qiluvchi bir-birini topmaydi | Railway'da replikalar soni 1 ekanini tekshiring. |
| Windows SmartScreen ogohlantirishi | Binary imzolanmagan; "More info → Run anyway". |
