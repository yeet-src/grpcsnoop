# grpcsnoop

**tcpdump for gRPC** — watch the protobuf messages flowing between services, decoded to readable fields, straight from the kernel.

<p align="center">
  <img src="https://img.shields.io/badge/platform-Linux-1793D1" alt="Linux">
  <img src="https://img.shields.io/badge/built%20with-yeet%20%2B%20eBPF-8A2BE2" alt="yeet + eBPF">
  <img src="https://img.shields.io/badge/license-GPL-3DA639" alt="GPL">
  <a href="https://discord.gg/dYZu9PjKB"><img src="https://img.shields.io/badge/chat-Discord-5865F2" alt="Discord"></a>
</p>

**grpcsnoop turns the plaintext gRPC/protobuf flowing between containers into a live, decoded feed in your terminal.** It attaches an eBPF program at the TC layer, reassembles the HTTP/2 stream off the wire, and walks the protobuf wire format — so you see request and response messages as structured fields without TLS keys, without app changes, and without naming a PID.

> [!TIP]
> **You can't `tcpdump` this.** gRPC is protobuf framed inside HTTP/2 — binary, length-prefixed, header-compressed. Even unencrypted it's unreadable on the wire, and the moment TLS is involved a packet capture is just ciphertext. grpcsnoop hooks the TC layer on the container's veth, reads the (plaintext) packet payload with `bpf_skb_load_bytes`, reassembles TCP, and unwinds all three layers for you.

## Quick start

```sh
curl -fsSL https://yeet.cx | sh     # installs the yeet daemon (does the privileged eBPF load)
make                                # builds grpcsnoop.bpf.o

# spin up two containers talking plaintext gRPC over a bridge
bash demo/up.sh

# in another terminal (from the repo root), watch the decoded protobuf flow
yeet run . --port 50051

bash demo/down.sh                   # tear the containers down
```

Runs until `Ctrl-C`. No sudo needed for `yeet run` — the yeet daemon performs the eBPF work.

## A 60-second gRPC primer

gRPC looks like one thing but it's three layers stacked, which is exactly why a raw capture is useless:

**1. protobuf — the message.** Your `EchoRequest{ message: "hi", repeat: 3 }` is encoded as a compact binary blob: a sequence of `(field-number, wire-type, value)` tuples. No field names, no types on the wire — `message` becomes "field 1, length-delimited" and `repeat` becomes "field 2, varint". To read it you walk the wire format; to *name* the fields you need the `.proto`.

**2. gRPC framing — the envelope.** Each message gets a 5-byte prefix: 1 compression flag + a 4-byte big-endian length. That's how the receiver knows where one message ends.

**3. HTTP/2 — the transport.** Those framed messages ride inside HTTP/2 `DATA` frames, multiplexed across streams, with request metadata (the `:path` that names the RPC method) in HPACK-compressed `HEADERS` frames. And in production it's all usually wrapped in **TLS**.

So a `tcpdump` gives you TLS ciphertext (if encrypted) or, at best, an opaque HTTP/2 byte soup. grpcsnoop captures the plaintext payload and unwinds all three layers.

**Wire types** you'll see in the output:

| Wire type | Used for |
|---|---|
| varint | ints, bools, enums |
| 64-bit | doubles, fixed64 |
| length-delimited | strings, bytes, **nested messages**, packed repeated |
| 32-bit | floats, fixed32 |

## Common use cases

- A service returns the wrong field and the logs don't show the payload — see the actual request and response between two pods.
- Debugging a gRPC integration between services where you don't control both ends.
- Confirming a client is sending the fields you think it is, before blaming the server.
- Understanding an undocumented internal gRPC API by watching real east-west traffic.

## What you're looking at

Each captured message is one decoded protobuf, tagged with direction and the TCP flow. With a schema (this repo ships one for the demo — see below) you get names, real scalar types, nested messages, and enums:

```
→ REQ  10.89.0.3:43210 → 10.89.0.2:50051  stream:1  20b
  EchoRequest
  message (string) "hello protosnoop"
  repeat (int32) 3
← RESP 10.89.0.2:50051 → 10.89.0.3:43210  stream:7  161b
  ListResponse
  items Item {
    name (string) "Widget A"
    price (double) 9.99
    status (Status) ACTIVE
  }
  ...
```

Without a schema, fields show by number and wire type (`field 1 (string) "…"`).

- **`→ REQ` / `← RESP`** — direction, inferred from which side owns the gRPC port.
- **flow + `stream:N`** — the TCP 4-tuple and HTTP/2 stream id, so you can follow one RPC. A real `stream:N` means the bytes came from an HTTP/2 DATA frame (confirmed gRPC).
- **fields** — protobuf, named via the schema or by number. Nested messages indent; `repeated` fields repeat; non-UTF-8 bytes fall back to hex. Pass `--hex` to also dump raw bytes.

## How it works

A single BPF object (`grpcsnoop.bpf.c`) attaches two SchedCls programs via **TCX** and ships each TCP segment's payload up a ring buffer:

| Hook | What it captures |
|---|---|
| `tcx/ingress` + `tcx/egress` | every TCP segment on the matched port, payload read with `bpf_skb_load_bytes` (handles nonlinear skbs, unlike a raw `skb->data` read) |

It attaches to every host interface by default (wildcard) and filters to the gRPC port via the `port_set` map — so it catches a container's traffic on its host-side veth without you naming the interface.

Userspace (yeet's V8 runtime) does the rest:

```
main.js        entry: attach TCX progs, write target port, subscribe to the ring buffer
tcpstream.js   TCP reassembly — orders segments by seq, dedupes copies seen across
               veths, walks HTTP/2 frames incrementally
proto.js       protobuf wire decoder — schema-free (field numbers) or, when schema.js
               is present, named/typed via content-aware best-fit
schema.js      generated proto schema (from demo/test.proto); rebuild: make schema
render.js      ANSI output, hex dump (pure)
```

Because TCX hooks are per-interface (not per-PID), it works across containers — the trade-off vs a syscall hook is that it reassembles the TCP stream itself.

## Requirements

> [!IMPORTANT]
> Linux **≥ 6.6** (TCX links) with BTF (`CONFIG_DEBUG_INFO_BTF=y`) — default on current Arch, Fedora, Ubuntu, and Debian 12+. CO-RE means no per-kernel recompile.

- The yeet daemon, which handles the privileged BPF load. `curl -fsSL https://yeet.cx | sh`.
- For the demo: Docker with the `compose` plugin.
- To build: `clang` (BPF target) and `bpftool`.

## Honest caveats

> [!NOTE]
> What grpcsnoop doesn't do:

- **Plaintext only.** If the gRPC channel uses TLS, the TC hook sees ciphertext on the wire. Reading TLS'd gRPC needs an in-process uprobe *before* encryption — a different hook. This tool is for insecure/plaintext gRPC: mesh-internal traffic with TLS terminated at the edge, or any east-west path that isn't encrypted.
- **Not loopback.** `bpf_program__attach_tcx` returns `EINVAL` on `lo`, so same-host `localhost` traffic isn't visible — the traffic has to cross a real interface (a container veth, as in the demo).
- **Big / split messages.** TCP segments are reassembled, but gRPC is extracted per HTTP/2 DATA frame, so a single message split across multiple DATA frames is the known gap.
- **No RPC method name.** HPACK header decoding isn't implemented, so the `:path` (e.g. `/svc/Method`) isn't shown — only the message bodies and (via schema best-fit) the message type.
- **Best-fit ambiguity.** Without the `:path`, the message *type* is inferred by matching field numbers/wire-types/content; look-alike messages (e.g. two single-`int32` requests) can still be misattributed.

## Community questions

**Why not just use Wireshark?**
Wireshark has a great gRPC dissector — if you can hand it the TLS keys and the `.proto`. grpcsnoop is for the case where you can't: it reads plaintext at the kernel boundary and decodes with one command, no capture file, no app changes.

**Does it work with Go / Rust / any language?**
Yes — it hooks the kernel, not a library, so it's language-agnostic as long as the traffic is plaintext. (This is also why a libssl-uprobe approach *doesn't* generalize: Go and Rust don't use libssl.)

**Will it interfere with the traffic?**
No. The TCX programs are passive observers — they return `TCX_NEXT`, so the packet passes through untouched.

**Do I need the `.proto` file?**
No — without it you get field numbers, wire types, and full structure. **With it you get field names and exact scalar types.** Generate a schema module once:

```sh
make schema PROTO=demo/test.proto   # writes schema.js
```

Then grpcsnoop imports `schema.js` and decodes against it — turning `field 1 (string) "hi"` into `EchoRequest { message: "hi" }`, `price (double) 9.99` instead of a raw fixed64, and enum values by name. The message type isn't on the wire, so it's matched by best-fit; for anything it can't confidently match it falls back to field numbers, so a stale schema degrades gracefully rather than lying. This repo ships a `schema.js` from `demo/test.proto`; point it at your own service with `make schema PROTO=yours.proto`.

**Can I scope it to one container?**
By default it attaches to all interfaces and filters by port. To pin it to one container's host-side veth, pass `--ifindex N` (find it with `ip link`).

## The demo

`demo/` runs two containers — a gRPC server and a looping client — on a Docker bridge, the same `veth ↔ bridge` plumbing the TCX hook needs. See [`demo/README.md`](demo/README.md):

```sh
bash demo/up.sh          # build image, start ps-server + ps-client
yeet run . --port 50051  # watch the decoded gRPC (from the repo root)
bash demo/down.sh
```

`testservice/` holds the same `.proto`/app and the poetry env `make schema` uses for `grpcio-tools`.

## Building from source

```sh
make          # generates vmlinux.h, builds grpcsnoop.bpf.o
make clean
```

Needs `clang` (BPF target) and `bpftool`; the generated `vmlinux.h` and `*.bpf.o` are gitignored.

## License

The BPF program is GPL (`SEC("license") = "GPL"`), as required by the kernel helpers it uses.

## Community

Questions, ideas, or want to show what you're snooping? Join the [Discord](https://discord.gg/dYZu9PjKB).

---

Built with [yeet](https://yeet.cx). yeet is a Linux runtime for writing eBPF programs and live system tools in JavaScript.
