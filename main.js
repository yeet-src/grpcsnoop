// SPDX-License-Identifier: GPL-2.0
// grpcsnoop — watch plaintext gRPC/protobuf at the TC layer, across containers.
// Attaches SchedCls programs via TCX (ingress + egress) and reads payloads with
// bpf_skb_load_bytes (handles nonlinear skbs), then reassembles the TCP stream
// and decodes HTTP/2 → gRPC → protobuf.
//
//   yeet run . --port 50051 [--ifindex N] [--hex]
//
// By default it attaches to every host interface (wildcard) and filters by
// the gRPC port — so it catches the container's traffic on its host-side
// veth without you naming it. Pass --ifindex to pin to one interface.

import { BpfObject, RingBuf, HashMap } from "yeet:bpf";
import { decodeProto, renderFields, decodeNamed } from "./proto.js";
import { Reassembler, fmtIp } from "./tcpstream.js";
import { output, hexDump } from "./render.js";
import schema from "./schema.js";

const ports = []
  .concat(yeet.args.port ?? [])
  .concat(yeet.args._ ?? [])
  .map(p => parseInt(p, 10))
  .filter(p => p > 0 && p < 65536);
if (ports.length === 0) {
  console.error("usage: yeet run . --port <grpc-port> [--ifindex N] [--hex]");
  yeet.exit();
}
const showHex = !!yeet.args.hex;
const ifindex = yeet.args.ifindex ? parseInt(yeet.args.ifindex, 10) : null;

// Pin to one interface if --ifindex given, else wildcard (all interfaces).
const tcxSpec = ifindex ? { kind: "tcx", ifindex: [ifindex] } : { kind: "tcx" };

const probe = new BpfObject({ exe: "./grpcsnoop.bpf.o", base: import.meta.dirname });

let control;
try {
  control = await probe
    .bind("events",   { kind: "ringbuf", btf_struct: "seg_event" })
    .bind("port_set", { kind: "hashmap" })
    .attach("on_ingress", tcxSpec)
    .attach("on_egress",  tcxSpec)
    .start();
} catch (err) {
  console.error(`[grpcsnoop] failed to load eBPF: ${err.message}`);
  yeet.exit();
}

const portMap = new HashMap(control, "port_set");
for (const p of ports) await portMap.update(p, { v: 1 });

const where = ifindex ? `ifindex ${ifindex}` : "all interfaces";
output(`${style.bold("grpcsnoop")}  ports ${style.cyan(ports.join(","))}  mode: ${style.dim(`tcx (${where})`)}`);
output(style.dim("─".repeat(64)));

const portSet = new Set(ports);

function printMessage(m) {
  const toServer = portSet.has(m.dport);
  const arrow = toServer ? style.green("→ REQ ") : style.cyan("← RESP");
  const flow  = `${fmtIp(m.saddr)}:${m.sport} → ${fmtIp(m.daddr)}:${m.dport}`;
  const cmp   = m.compressed ? style.yellow(" [compressed]") : "";

  output(`${arrow} ${style.dim(flow)}  stream:${m.streamId}  ${m.payload.length}b${cmp}`);
  const named = decodeNamed(m.payload, schema);
  if (named) {
    output(`  ${style.bold(named.typeName)}`);
    for (const line of named.lines) output(line);
  } else {
    const fields = decodeProto(m.payload);
    if (fields.length > 0) for (const line of renderFields(fields)) output(line);
    else output(`  ${style.dim("(no fields decoded)")}`);
  }
  if (showHex) output(hexDump(m.payload));
  output("");
}

const reasm = new Reassembler(printMessage);

await new RingBuf(control, "events").subscribe(
  (raw) => {
    const ev = raw.seg_event ?? raw;
    const data = (ev.data instanceof Uint8Array
      ? ev.data
      : Uint8Array.from(Object.values(ev.data))).subarray(0, ev.captured);
    reasm.push(ev, data);
  },
  (err) => console.error("[grpcsnoop] ringbuf error:", err.message),
);

await new Promise(() => {});  // run until Ctrl-C
