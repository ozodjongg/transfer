# Pro Transfer v5

Secure, room-code based one-to-one transfer utility written in Go.

## V5 highlights

- 1 sender + 1 receiver per room
- multiple files in one transfer
- whole folder transfer, including nested and empty folders
- no manual ZIP/unzip required
- end-to-end AES-256-GCM encryption
- encrypted manifest: server cannot read file names, folder names or SHA-256 values
- server never receives the transfer secret
- authenticated encrypted chunks with fresh random nonces
- automatic reconnect + chunk-boundary resume
- SHA-256 verification of every received file
- no server-side file storage
- streaming; files are never loaded fully into RAM
- live progress / speed / ETA
- symlinks rejected
- path traversal protection on receive
- automatic `config.json` creation
- Windows User PATH auto-registration
- Railway-ready Dockerfile

## Command line

Send one file:

```powershell
transfer send report.xlsx
```

Send multiple files:

```powershell
transfer send report.xlsx photo.jpg data.csv
```

Send a folder:

```powershell
transfer send "D:\Projects\My Project"
```

Mix files and folders:

```powershell
transfer send report.xlsx "D:\Projects\My Project" photo.jpg
```

The sender prints a transfer code like:

```text
BHTP8AH7XN.QWertY...<secret>...
```

Receive:

```powershell
transfer receive BHTP8AH7XN.QWertY...<secret>...
```

The complete `ROOM.SECRET` value must be shared with the receiver. Only the `ROOM`
part is sent to the relay server; the secret stays between sender and receiver.

## End-to-end encryption

V5 generates a fresh random 256-bit transfer secret for every transfer.
Two independent AES-256-GCM keys are derived from it:

- one for the manifest;
- one for file payload chunks.

The encrypted manifest contains paths, directory structure, sizes and per-file SHA-256
hashes. The relay receives only ciphertext plus aggregate transfer sizes.

Conceptually:

```text
Sender                                Relay                                Receiver
------                                -----                                --------
files/folders
   |
manifest -> AES-256-GCM  ----------> encrypted manifest ----------------> decrypt manifest
   |
file chunks -> AES-256-GCM ---------> ciphertext only -------------------> authenticate/decrypt
                                                                          |
                                                                      recreate folders
                                                                      write files
                                                                      SHA-256 verify
```

TLS can still be enabled in `config.json`; E2E encryption protects file content even when
TLS is disabled. TLS additionally protects transport metadata such as room IDs and aggregate
sizes from passive network observers.

## Resume

Payload is encrypted in independent authenticated chunks (default 512 KiB plaintext per
chunk). Every transmission of a chunk uses a fresh random AES-GCM nonce, including retries. Receiver state is persisted inside a hidden staging directory:

```text
downloads/
└── .protransfer-<room>-<transfer-id>/
    ├── state.json
    └── content/
```

Only a fully received and successfully authenticated chunk advances `state.json`.
If TCP is reset in the middle of a chunk, that chunk is retransmitted after reconnect.
Completed chunks are not sent again.

Example:

```text
[!] Transfer uzildi: 18.0 MiB / 100.0 MiB
[↻] avtomatik resume ...
[↻] Receiver resume: lokal state = 17.5 MiB (17.50%)
[↻] Resume: 17.5 MiB dan davom etadi (17.50%)
```

The relay itself still stores no transferred files.

## Folder behavior

A source folder is reconstructed with the same root name and relative structure.
Empty folders and zero-byte files are preserved.

Example:

```text
transfer send report.xlsx "D:\Project"
```

Receiver result:

```text
downloads/
├── report.xlsx
└── Project/
    ├── src/
    ├── images/
    └── empty-folder/
```

If a destination root already exists, a unique name such as `Project (1)` is selected.

## Security rules

- symlinks are rejected rather than followed;
- absolute paths are rejected;
- `..` path traversal is rejected;
- duplicate/colliding manifest paths are rejected;
- every encrypted chunk is authenticated before being written;
- every final file is verified with SHA-256;
- wrong transfer secrets cannot decrypt the manifest;
- server logs do not contain file/folder names.

## Windows client behavior

On first launch `transfer.exe`:

1. creates `config.json` next to the executable if missing;
2. adds its executable directory to Windows **User PATH**;
3. does not require administrator rights.

Open a new terminal after the first launch, then use `transfer` from any directory.

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

For Railway replace `server` with your public TCP Proxy endpoint:

```json
"server": "your-proxy.proxy.rlwy.net:12345"
```

## Server

Run locally:

```bash
./server -addr :8080
```

Important options:

```text
-addr :8080
-max-transfer-gb 10
-room-ttl 10m
-transfer-timeout 2h
-resume-grace 2m
-max-rooms 100
-max-manifest-mb 2
-max-connections 240
-max-handshakes-per-minute 600
```

Optional transport TLS:

```bash
./server \
  -addr :8443 \
  -tls-cert fullchain.pem \
  -tls-key privkey.pem
```

## Railway

1. Push this repository to GitHub.
2. Create a Railway service from the repository.
3. Railway builds the included `Dockerfile` automatically.
4. Open **Settings -> Networking -> TCP Proxy**.
5. Set internal/target port to `8080`.
6. Put the generated `hostname:port` into client `config.json`.
7. Keep **1 replica** because room state is intentionally in process memory.

The server stores only ephemeral room state and encrypted manifest ciphertext.

## Protocol v5

Control frames:

```text
uint32 big-endian length + JSON
```

Encrypted payload bytes are relayed directly after the peer-ready handshake.

Normal flow:

```text
Sender                    Server                    Receiver
  | CREATE encrypted meta   |                         |
  |------------------------>|                         |
  | CREATED room            |                         |
  |<------------------------|                         |
  |                         |<---------- JOIN room ---|
  |                         |-- encrypted manifest -->|
  |                         |<- receiver_ready(offset)|
  |<------ peer_ready ------|------ peer_ready ------>|
  |==== encrypted chunks ===|==== encrypted chunks ==>|
  |                         |<-------- verified ------|
  |<------- complete -------|-------- complete ------>|
```

The secret portion of the transfer code is never included in these server messages.

## Build

```bash
make test
make vet
make windows
make linux
```

Windows output:

```text
bin/
├── transfer.exe
├── client.exe      # compatibility copy of transfer.exe
├── server.exe
└── config.json
```

Linux output:

```text
bin/
├── transfer-linux-amd64
└── server-linux-amd64
```

## Tests performed

The test suite covers:

- protocol frame round-trip;
- transfer-code secret round-trip;
- encrypted-manifest confidentiality / wrong-secret rejection;
- multiple file + nested folder manifest generation;
- empty folder preservation;
- path traversal rejection;
- full E2E encrypted transfer;
- forced TCP disconnect during transfer;
- automatic resume from an authenticated chunk boundary;
- final byte-for-byte content verification.

Run:

```bash
go test ./...
go test -race ./internal/transfer
go vet ./...
```
