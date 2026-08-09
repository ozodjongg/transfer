# Pro Transfer v6

One-to-one secure file/folder transfer utility written in Go.

V6 keeps the V5 encrypted multi-file protocol and adds **network intelligence**:

- automatic same-LAN direct transfer;
- automatic public relay fallback;
- configurable parallel public TCP streams (default: 4);
- per-stream resume state;
- secret-derived reconnect room aliases;
- authenticated direct-LAN handshake;
- automatic cleanup of the unused public room after LAN direct is selected.

## Main features

- 1 sender + 1 receiver per transfer
- send one file, many files, folders, or a mixture
- nested folders, empty folders and zero-byte files
- no manual ZIP/unzip
- end-to-end AES-256-GCM
- encrypted manifest (paths, names and SHA-256 values are not plaintext on the relay)
- fresh random AES-GCM nonce for every transmitted chunk
- SHA-256 final verification of every file
- automatic reconnect and authenticated chunk-boundary resume
- no server-side file storage for live transfers
- streaming; full files are never loaded into RAM
- path-traversal protection
- symlinks rejected
- live speed / progress / ETA
- Windows User PATH auto-registration
- automatic `config.json` creation
- Railway-ready Dockerfile

## V6 route selection

Sender always creates the public relay room first. When `network.lan_direct=true`, it also opens an authenticated local TCP endpoint.

Local candidate addresses are **encrypted with the transfer secret** and placed in the complete transfer code. They are not included in the plaintext manifest and are not sent to the relay as route hints.

Receiver behavior:

```text
Receive code
    |
    +--> decrypt LAN route hint with SECRET
    |
    +--> LAN endpoint reachable + HMAC proof accepted?
            |
            +-- YES --> direct LAN payload transfer
            |           public room is cancelled
            |
            +-- NO  --> public relay
                         parallel TCP data streams
```

LAN direct is not NAT traversal. It is intended for devices that can directly reach each other on the same LAN/Wi-Fi/VPN. If Windows Firewall blocks the sender's local listener, the receiver automatically falls back to the configured public relay.

## Transfer code

Typical V6 code:

```text
ROOM.SECRET.ENCRYPTED_ROUTES
```

The third part is optional when there are no usable local candidates. **Always share the complete code.**

- `ROOM` — public rendezvous room identifier;
- `SECRET` — 256-bit E2E secret;
- `ENCRYPTED_ROUTES` — optional AES-GCM encrypted LAN candidate hint.

The E2E secret is not required by the relay to decrypt any content; the relay cannot decrypt the manifest or payload.

## Usage

One file:

```powershell
transfer send report.xlsx
```

Multiple files:

```powershell
transfer send report.xlsx photo.jpg data.csv
```

Folder:

```powershell
transfer send "D:\Projects\My Project"
```

Mixed:

```powershell
transfer send report.xlsx "D:\Projects\My Project" photo.jpg
```

Receiver:

```powershell
transfer receive <FULL-TRANSFER-CODE>
```

## End-to-end encryption

A fresh 256-bit random secret is generated per transfer. HKDF-SHA256 derives independent keys for:

- encrypted manifest;
- encrypted payload chunks;
- encrypted LAN route hints;
- public data-stream attach credential.

Payload chunks use AES-256-GCM. Each transmission, including a retransmission, gets a fresh random nonce.

```text
Sender                         Relay                         Receiver
------                         -----                         --------
manifest -> AES-GCM ---------> ciphertext ----------------> decrypt
chunk    -> AES-GCM ---------> ciphertext ----------------> auth/decrypt
                                                            |
                                                            +-> WriteAt
                                                            +-> resume state
                                                            +-> SHA-256 final verify
```

The relay still sees operational metadata needed to relay a transfer, such as aggregate byte sizes, opaque room/stream identifiers and connection timing. TLS can additionally protect transport metadata from passive network observers.

## Parallel public relay

Default client config uses four public data streams:

```text
control connection
    |
    +-- data stream 0
    +-- data stream 1
    +-- data stream 2
    +-- data stream 3
```

The encrypted chunk plan is split into contiguous stream ranges. Receiver persists an authenticated progress offset for every stream independently.

If stream 0 fails while streams 1-3 finish:

```text
stream 0: 25%  -> resume later
stream 1: 100% -> kept
stream 2: 100% -> kept
stream 3: 100% -> kept
```

The completed stream ranges are not resent after reconnect.

Parallel connections can improve WAN throughput when a single TCP flow is limited by latency/routing, but they cannot exceed the real sender upload, receiver download, relay bandwidth or ISP limits.

## Secure reconnect aliases

The initial public room is used for the first connection. Future reconnect aliases are deterministically derived from the E2E secret with HMAC-SHA256 and registered as opaque aliases when the transfer is created.

Clients therefore do not need to reuse the visible initial room string for every resume attempt.

## Resume state

Receiver staging directory:

```text
downloads/
└── .protransfer-<room>-<transfer-id>/
    ├── state.json
    └── content/
```

V6 state stores a separate encrypted-payload offset for each public data stream. Only fully received and successfully authenticated chunks advance the corresponding offset.

When all files pass SHA-256 verification, staging roots are atomically moved into the configured download directory and the hidden state directory is removed.

## Default config

```json
{
  "server": "localhost:8080",
  "download_dir": "downloads",
  "tls": {
    "enabled": false,
    "insecure_skip_verify": false
  },
  "timeouts": {
    "connect": "10s",
    "io": "2h"
  },
  "network": {
    "lan_direct": true,
    "parallel_streams": 4
  }
}
```

`parallel_streams` accepts `1..8`.

For Railway:

```json
"server": "your-tcp-proxy.proxy.rlwy.net:12345"
```

Use Railway **TCP Proxy**, not the private `*.railway.internal` address.

## Connection capacity

With `parallel_streams=4`, one actively relayed transfer can temporarily use roughly:

```text
2 control TCP connections
+ 4 sender data connections
+ 4 receiver data connections
= up to 10 TCP connections
```

So a server configured with `-max-connections 240` is connection-limited to roughly two dozen fully active 4-stream transfers at once, although many waiting rooms can still exist with far fewer connections. Set `parallel_streams=1` when connection count matters more than WAN throughput.

LAN direct payloads do not consume public relay data-stream connections; the unused public room is cancelled after direct transport wins.

## Server

Local:

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
./server -addr :8443 -tls-cert fullchain.pem -tls-key privkey.pem
```

E2E payload encryption remains active whether transport TLS is enabled or disabled.

## Railway

The repository root contains a multi-stage `Dockerfile`. Deploy it and configure:

```text
TCP Proxy target port: 8080
Replicas: 1
```

Keep one replica because room/session state is currently in-process memory.

## Build

```bash
go test ./...
go vet ./...
make linux
make windows
```

Windows client:

```text
bin/transfer.exe
```

Windows server:

```text
bin/server.exe
```

Linux binaries:

```text
bin/transfer-linux-amd64
bin/server-linux-amd64
```

## Validation performed

V6 includes tests for:

- encrypted route-hint round trip and tamper rejection;
- secret-derived direct authentication proof;
- secret-derived reconnect aliases;
- V5-style single-stream public resume compatibility inside V6;
- four-stream public transfer;
- forced failure of one public data stream followed by per-stream resume;
- LAN direct transfer with zero public payload streams;
- multiple files / nested folders / empty folders;
- final byte-for-byte and SHA-256 correctness;
- race detector on the transfer package.
