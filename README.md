# Pro Transfer V8

Pro Transfer V8 is a small, account-free, end-to-end encrypted file and folder transfer utility written in Go.

The user experience stays deliberately small:

```bash
transfer send "D:\portfolio\my_music"
```

The sender prints a four-word invitation such as:

```text
silverfox-rosefield-nightflame-snowwater
```

The receiver runs:

```bash
transfer receive silverfox-rosefield-nightflame-snowwater
```

V8 chooses the best available route automatically:

1. **LAN direct TCP** — same LAN/Wi-Fi/VPN when directly reachable.
2. **Internet P2P** — STUN-assisted authenticated UDP hole punching.
3. **Public relay fallback** — encrypted payload through the configured TCP relay when direct paths fail.

There are no user accounts, login system or database.

## Security model

The four-word phrase is an invitation secret, not the file-encryption key.

The initial public relay rendezvous carries a PAKE exchange. The complete phrase is never sent to the relay. After mutual PAKE key confirmation, the sender transfers a freshly generated random 256-bit transfer secret inside an AES-GCM authenticated envelope. LAN candidates and Internet-P2P endpoint information are exchanged only inside that authenticated encrypted exchange.

The random transfer secret is then used through domain-separated HKDF derivations for the data encryption and transport credentials.

Payload properties:

- AES-256-GCM end-to-end encryption;
- fresh random nonce for each encrypted file chunk;
- encrypted/authenticated manifest;
- SHA-256 recorded for every file and verified at completion;
- secret-derived relay data attach token;
- secret-derived reconnect aliases;
- authenticated direct-route join proof;
- Internet P2P UDP packets carry a separate HMAC-SHA256 authentication tag;
- safe destination-path validation;
- symlinks are rejected rather than followed.

The relay therefore does not receive the plaintext file content, file/folder names, or the random E2E transfer secret. As any network relay, it can still observe transport-level metadata such as connection IPs, times and transferred byte counts when the public relay is used.

## Four-word code

V8 generates four independently random human-readable compound words from a 4096-entry generated dictionary.

Example:

```text
bloomtrail-azuresail-firestream-mosscrown
```

A limited part of the phrase is used only to select the relay rendezvous room; the remaining uncertainty is authenticated through PAKE. The public room identifier is intentionally not a verifier for the full four-word phrase. The relay also enforces a per-room PAKE-attempt limit.

The phrase is never used directly as an AES key.

## Route selection

### 1. LAN direct

When `network.lan_direct` is enabled, the sender advertises directly reachable local TCP candidates only after the PAKE channel is authenticated.

```text
Sender  ============================> Receiver
                 LAN TCP

Relay: rendezvous/control only
```

If the LAN route succeeds, file payload bytes do not traverse the public relay.

### 2. Internet P2P

When `network.internet_p2p` is enabled, each peer creates a UDP socket and uses a STUN Binding request to discover the public endpoint associated with that same socket. The two endpoints are exchanged inside the PAKE-authenticated encrypted control exchange.

Both peers then send authenticated hole-punch packets simultaneously. If a packet arrives with the correct session HMAC, that authenticated source endpoint becomes the peer address.

```text
                   STUN
                 /      \
             Sender    Receiver
                 \      /
                  \    /
             UDP hole punching
                     |
               direct P2P data
```

The P2P stream uses a bounded reliable ordered UDP layer with sequence numbers, cumulative acknowledgements, retransmission, out-of-order buffering and authenticated NAT rebinding. The application payload remains AES-GCM encrypted above that transport.

**Important limitation:** STUN/hole punching cannot make every NAT reachable. Symmetric NAT, strict CGNAT, enterprise firewalls or UDP blocking may prevent direct P2P. V8 does not require TURN because the existing Pro Transfer public relay is the fallback path.

If Internet P2P cannot be established, V8 automatically continues through the public relay.

If a selected P2P route fails hard during a transfer, V8 discards the partial one-stream P2P staging state and safely restarts through the canonical public-relay session. This deliberately prefers correctness/integrity over trying to mix incompatible direct and multi-stream relay offsets.

### 3. Public relay

When direct transport is unavailable:

```text
Sender -> Relay -> Receiver
```

The server streams ciphertext and does not persist normal live file payloads to disk.

The public path supports 1–8 parallel TCP data streams; the default is 4. Resume state is tracked independently per stream at authenticated chunk boundaries.

## Default config

`config.json` is automatically created next to the executable if it does not exist.

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
    "internet_p2p": true,
    "stun_servers": [
      "stun.l.google.com:19302"
    ],
    "p2p_discovery_timeout": "1500ms",
    "p2p_connect_timeout": "5s",
    "parallel_streams": 4
  }
}
```

For a Railway TCP Proxy, replace `server` with the public proxy hostname and port, for example:

```json
"server": "your-service.proxy.rlwy.net:12345"
```

The Railway relay itself only needs its TCP listener. Internet P2P uses outbound UDP from the two clients to their configured STUN server and then peer-to-peer UDP between the clients.

## Windows

On Windows, `transfer.exe` tries to add the directory containing itself to the current user's PATH. Administrator privileges are not required for the User PATH change. Open a new terminal after the first run.

If Windows Firewall asks whether to allow the application on a network, direct LAN/P2P connectivity can depend on the selected firewall permission. Public relay fallback remains available when direct traffic is blocked.

## Commands

Send one file:

```bash
transfer send report.xlsx
```

Send multiple files and folders:

```bash
transfer send report.xlsx photo.jpg "D:\My Project"
```

Receive:

```bash
transfer receive silverfox-rosefield-nightflame-snowwater
```

Show current config:

```bash
transfer config
```

## Server

Local:

```bash
go run ./cmd/server -addr :8080
```

Important defaults:

- max transfer size: 10 GiB;
- room TTL: 10 minutes;
- transfer timeout: 2 hours;
- resume grace: 2 minutes;
- max rooms: 100;
- max encrypted manifest: 2 MiB;
- max connections: 240;
- handshakes/minute: 600;
- PAKE attempts/room: 16.

The server keeps room/session state in process memory. Run one relay replica unless room-state coordination is added externally.

## Railway / Docker

The included Dockerfile builds only the relay server:

```bash
docker build -t pro-transfer-v8 .
docker run --rm -p 8080:8080 pro-transfer-v8
```

For Railway, expose target TCP port `8080` through a TCP Proxy. Client STUN/P2P traffic does not need to pass through the Railway container.

## Build

```bash
go test ./...
go vet ./...
make windows
make linux
```

Windows binaries:

```text
bin/transfer.exe
bin/server.exe
```

Linux binaries:

```text
bin/transfer-linux-amd64
bin/server-linux-amd64
```

## Resume model

Public relay resume is chunk-boundary safe. The receiver's committed local state is authoritative, and each public data stream tracks its own completed ciphertext offset.

Direct LAN sessions resume on the same direct transport. A terminal Internet-P2P failure intentionally falls back to public relay from a clean staging state rather than mixing P2P one-stream offsets with public N-stream offsets.

## Server resource behavior

Normal relay transfers are streamed; a 10 GiB file is not loaded into 10 GiB of RAM and is not normally stored as a 10 GiB server file. Public relay mode still consumes network traffic in both directions: roughly the payload enters and leaves the relay. LAN/P2P direct mode keeps bulk payload off the relay entirely.

## V8 test coverage

The source test suite includes:

- four-word code generation/parsing and public-room separation;
- PAKE shared-key agreement;
- wrong-passphrase confirmation failure;
- encrypted random transfer-secret envelope;
- encrypted endpoint negotiation;
- AES-GCM manifest and data authentication;
- multi-file/folder transfer;
- empty folders and zero-byte files;
- SHA-256 final verification;
- path-traversal rejection;
- LAN direct relay bypass;
- parallel public TCP transfer;
- forced public-stream disconnect and resume;
- STUN XOR-MAPPED-ADDRESS parsing;
- authenticated UDP hole punching;
- reliable bidirectional UDP stream;
- Internet P2P transfer with public payload bypass;
- STUN/P2P discovery failure -> relay fallback;
- selected P2P hard failure -> clean public-relay fallback;
- race-detector coverage for the transfer package.

The automated Internet-P2P integration test uses a local fake STUN server so the NAT-traversal protocol can be deterministically exercised. Real-world NAT/CGNAT behavior varies by network and must still be field-tested across actual ISPs.

## Third-party notice

The focused P-256 PAKE core in `internal/transfer/pake_p256.go` is adapted from the MIT-licensed `github.com/schollz/pake/v3` project. See `THIRD_PARTY_NOTICES.md`.

The STUN parser, authenticated UDP hole-punching layer and reliable UDP stream in V8 are implemented in this repository and do not add a new Go module dependency.
