# Pro Transfer v4

Room-code based one-to-one file transfer service written in Go.

- 1 sender + 1 receiver per room
- no authentication/accounts
- server does not persist transferred files
- streaming transfer (file is not loaded into RAM)
- automatic reconnect + resume after temporary TCP resets
- SHA-256 end-to-end integrity verification
- live speed, ETA and transferred-byte diagnostics
- optimized 1 MiB reusable transfer buffers
- TCP keepalive / larger socket buffers
- Railway-ready Dockerfile

## Windows client

On first launch `client.exe`:

1. creates `config.json` next to itself if it does not exist;
2. adds its own directory to the current Windows user's PATH;
3. does not require administrator privileges.

After opening a new terminal:

```powershell
client send D:\Files\report.xlsx
client receive AB7K4M9Q2X
client config
```

Default config:

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

For Railway, replace `server` with the public TCP Proxy endpoint, for example:

```json
"server": "turntable.proxy.rlwy.net:18473"
```

## Automatic resume

If a TCP connection is reset during a transfer, both clients automatically reconnect.
The receiver keeps a deterministic temporary file:

```text
.protransfer-ROOMCODE.part
```

The receiver reports the number of bytes actually present in that file. The sender seeks
to that byte offset and continues from there. The relay server itself still stores no file.

Example:

```text
[!] Transfer uzildi: 19.7 MiB / 34.1 MiB
[↻] avtomatik resume ...
[↻] Resume: 19.4 MiB dan davom etadi (56.89%)
Yuborish:  72.13% | 24.6 MiB / 34.1 MiB | 4.8 MiB/s | ETA 00:02
```

The receiver's local `.part` size is authoritative because it represents bytes that were
actually written on the receiving machine.

Default resume behavior:

- up to 8 automatic reconnect attempts in the client;
- increasing retry delay (up to 8 seconds);
- server keeps an interrupted room resumable for 2 minutes by default;
- a completed room is cached briefly so a lost final acknowledgement can still recover.

## Server

Local:

```bash
./server -addr :8080
```

Important options:

```text
-addr :8080
-max-file-gb 10
-room-ttl 10m
-transfer-timeout 2h
-resume-grace 2m
-max-connections 512
-max-handshakes-per-minute 120
```

Optional TLS:

```bash
./server \
  -addr :8443 \
  -tls-cert fullchain.pem \
  -tls-key privkey.pem
```

## Railway deployment

The included multi-stage `Dockerfile` builds and runs only the server binary.

1. Push the repository to GitHub.
2. Create a Railway service from the repository.
3. Railway detects the `Dockerfile` and builds it automatically.
4. In **Settings -> Networking**, choose **TCP Proxy**.
5. Set target/internal port to `8080`.
6. Copy the generated public `hostname:port` into the Windows client's `config.json`.
7. Keep the service at **1 replica**, because room state is intentionally in-memory.

## Transfer protocol v2

Control messages are length-prefixed JSON frames:

```text
uint32 big-endian frame length + JSON
```

The data payload itself remains raw streaming bytes.

Normal flow:

```text
Sender                 Server                 Receiver
  | CREATE + metadata    |                       |
  |--------------------->|                       |
  | CREATED + room       |                       |
  |<---------------------|                       |
  |                      |<----------- JOIN -----|
  |                      |--- metadata/JOINED -->|
  |                      |<- receiver_ready -----|
  |<---- peer_ready -----|----- peer_ready ----->|
  |====== raw bytes =====|====== raw bytes =====>|
  |                      |<------ verified ------|
  |<------ complete -----|------- complete ------>|
```

Resume flow:

```text
TCP reset
   |
   +-- sender:   resume_send(room, same file metadata)
   +-- receiver: resume_receive(room) + local .part offset
   +-- server:   peer_ready(offset)
   +-- sender:   seek(offset) and continue
```

## Integrity

The sender calculates SHA-256 before creating the room. After all bytes are received,
the receiver calculates SHA-256 over the completed `.part` file. The server sends final
`complete` only after the receiver reports successful verification.

## Build

```bash
make test
make vet
make build
```

Windows x64:

```bash
make windows
```

Output:

```text
bin/
├── client.exe
├── server.exe
└── config.json
```

## Tests

```bash
go test ./...
go vet ./...
```

The test suite includes an end-to-end integration test that intentionally cuts the sender
TCP connection during a transfer and verifies that reconnect + resume produces a byte-for-byte
identical output file.
