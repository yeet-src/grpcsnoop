# grpcsnoop demo — two containers talking gRPC, inspected at the TC layer

Spins up two containers on a bridge network speaking **plaintext gRPC/protobuf**,
then lets you watch the decoded messages flow by attaching an eBPF **TCX** probe
to the containers' veths — no TLS keys, no app changes, no per-PID targeting.

```
 ┌─────────────┐   gRPC/HTTP2/protobuf    ┌─────────────┐
 │  ps-client  │ ───────────────────────▶ │  ps-server  │
 │  (loops RPCs)│ ◀─────────────────────── │ (Echo/GetUser│
 └─────────────┘     over docker bridge    │  /ListItems) │
        │                                   └─────────────┘
        └──── veth ──┐                  ┌── veth ────┘
                  host bridge (br-…)  ◀── TCX ingress/egress hooks here
```

## Run it

```sh
# 1. bring the two containers up (builds the image on first run)
bash demo/up.sh

# 2. in another terminal (from the repo root), watch the traffic
yeet run . --port 50051

# 3. tear down
bash demo/down.sh
```

`up.sh` auto-uses `sudo` for docker if your user can't reach the daemon.
`yeet run` does **not** need sudo — the yeet daemon performs the eBPF work.

## What you'll see

Field names come from the committed `schema.js` (generated from `test.proto`),
so messages decode with names, real scalar types, nested messages and enums:

```
→ REQ  10.x.x.3:43210 → 10.x.x.2:50051  stream:1  20b
  EchoRequest
  message (string) "hello protosnoop"
  repeat (int32) 3
← RESP 10.x.x.2:50051 → 10.x.x.3:43210  stream:7  161b
  ListResponse
  items Item {
    name (string) "Widget A"
    price (double) 9.99
    status (Status) ACTIVE
  }
  ...
```

If you edit `test.proto`, regenerate the schema: `make schema PROTO=demo/test.proto`
(it uses the testservice poetry env, so `cd testservice && poetry install` once if
you haven't). Delete `schema.js`'s contents — set it to `export default null;` — for
raw field-number decoding.

## How it works

- **Capture:** `grpcsnoop.bpf.c` attaches SchedCls programs via TCX to
  every host interface (`tcx/ingress` + `tcx/egress`) and reads each TCP
  segment's payload with `bpf_skb_load_bytes` (works on nonlinear skbs).
  It filters to the gRPC port via the `port_set` map, so only this traffic
  is shipped up.
- **Reassembly:** `tcpstream.js` orders segments by TCP sequence (deduping the
  copies seen across multiple veths), then walks HTTP/2 frames incrementally.
- **Decode:** `proto.js` decodes the gRPC DATA-frame bodies as protobuf —
  field numbers/wire types with no `.proto`, or field names + real types if you
  generated `schema.js` (best-fit matches the message type, since it isn't on
  the wire).

Files live at the repo root (`main.js`, `tcpstream.js`, `proto.js`,
`grpcsnoop.bpf.o`); this folder is just the containerized workload + scripts.
