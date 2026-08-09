# Pro Transfer

Room-code based direct streaming file-transfer service written in Go.
The server does **not** persist uploaded files: it only relays bytes from sender to receiver.
No account/authentication system is required.

## Client usage

The client reads its connection settings from `config.json`. In a normal Windows build,
`config.json` lives next to `client-windows-amd64.exe`. If it is missing, the client automatically
creates a default `config.json` on first launch — even when started with no command — and then uses it.
An existing config is never overwritten automatically. Invalid JSON or invalid values produce a clear error.

Example `config.json`:

```json
{
  "server": "files.example.com:8443",
  "download_dir": "downloads",
  "tls": {
    "enabled": true,
    "insecure_skip_verify": false,
    "server_name": "files.example.com"
  },
  "timeouts": {
    "connect": "10s",
    "io": "2h"
  }
}
```

For a local server:

```json
{
  "server": "localhost:8080",
  "download_dir": "downloads",
  "tls": {
    "enabled": false,
    "insecure_skip_verify": false,
    "server_name": ""
  },
  "timeouts": {
    "connect": "10s",
    "io": "2h"
  }
}
```

After that, no server flag is needed.

Send a file:

```powershell
client-windows-amd64.exe send report.xlsx
```

Receive a file:

```powershell
client-windows-amd64.exe receive AB7K4M9Q2X
```

Show the config currently being used:

```powershell
client-windows-amd64.exe config
```

The program first looks for `config.json` next to the executable. During development,
it also supports `config.json` in the current working directory. An optional
`PRO_TRANSFER_CONFIG` environment variable can point to another config file.

## Server usage

Local server:

```powershell
server-windows-amd64.exe -addr :8080
```

Public server with TLS:

```bash
./server \
  -addr :8443 \
  -tls-cert /etc/pro-transfer/fullchain.pem \
  -tls-key /etc/pro-transfer/privkey.pem \
  -max-file-gb 10 \
  -room-ttl 10m \
  -transfer-timeout 2h \
  -max-handshakes-per-minute 120
```

The server configuration remains CLI-based because it is normally started once as a
service. The client is the frequently used executable, so its repetitive settings live
in `config.json`.

## Main properties

- cryptographically generated 10-character room codes;
- no accounts/authentication;
- framed/versioned control protocol;
- streaming transfer without loading the whole file into RAM;
- SHA-256 integrity verification;
- safe output filenames;
- atomic `.part -> final` save;
- duplicate filename protection;
- sender/receiver progress display;
- optional TLS;
- configurable max file size and connection limits;
- room TTL and network deadlines;
- graceful server shutdown;
- per-IP handshake rate limiting;
- standard-library-only build.

## Build

Linux/macOS:

```bash
make build
```

Windows x64:

```bash
make windows
```

The Windows target creates:

```text
bin/
├── client-windows-amd64.exe
├── server-windows-amd64.exe
└── config.json
```

## Tests

```bash
go test ./...
go vet ./...
```

## Protocol summary

Control messages are length-prefixed JSON frames (`uint32 big-endian length + JSON`).
After `file_meta`, exactly `size` raw bytes follow. The receiver calculates SHA-256 and
only renames the temporary file when the hash and server completion message are valid.

## Windows: PATH avtomatik sozlanadi

`client.exe` Windows'da birinchi marta ishga tushganda o'z papkasini joriy foydalanuvchining **User PATH** qiymatiga avtomatik qo'shadi. Administrator huquqi talab qilinmaydi va System PATH o'zgartirilmaydi.

Birinchi ishga tushirishdan keyin yangi CMD yoki PowerShell oynasini oching. Keyin `client.exe` qayerda turganidan qat'i nazar quyidagicha ishlatish mumkin:

```powershell
client send C:\Files\report.xlsx
client receive AB7K4M9Q2X
client config
```

Agar PATH'ni avtomatik yangilash Windows siyosati sabab bloklansa, client ishlashda davom etadi va faqat ogohlantirish chiqaradi.
