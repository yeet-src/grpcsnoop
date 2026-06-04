// SPDX-License-Identifier: GPL-2.0
// TCP stream reassembly → HTTP/2 frame walk → gRPC message extraction.
//
// At the packet layer each event is one TCP segment. We rebuild the ordered
// byte stream per flow (4-tuple + direction), then parse HTTP/2 frames
// incrementally, emitting the protobuf body of each gRPC DATA frame.
//
// Because system-wide net tracepoints can see the same segment on several
// devices (e.g. veth xmit + peer receive), duplicates arrive — they're
// deduplicated naturally by TCP sequence number during reassembly.

const FRAME_DATA  = 0x0;
const FLAG_PADDED = 0x08;

// "PRI * HTTP/2.0\r\n\r\nSM\r\n\r\n" — client connection preface.
const PREFACE = [
  0x50,0x52,0x49,0x20,0x2a,0x20,0x48,0x54,0x54,0x50,0x2f,0x32,
  0x2e,0x30,0x0d,0x0a,0x0d,0x0a,0x53,0x4d,0x0d,0x0a,0x0d,0x0a,
];

function read24(b, p) { return (b[p] << 16) | (b[p+1] << 8) | b[p+2]; }
function read31(b, p) {
  return ((b[p] & 0x7f) * 0x1000000) + (b[p+1] << 16) + (b[p+2] << 8) + b[p+3];
}
function read32(b, p) {
  return (b[p] * 0x1000000) + (b[p+1] << 16) + (b[p+2] << 8) + b[p+3];
}

function concat(a, b) {
  const out = new Uint8Array(a.length + b.length);
  out.set(a, 0);
  out.set(b, a.length);
  return out;
}

function prefacePrefix(buf) {
  const n = Math.min(buf.length, PREFACE.length);
  for (let i = 0; i < n; i++) if (buf[i] !== PREFACE[i]) return false;
  return true;
}

class Flow {
  constructor() {
    this.base = null;            // TCP seq corresponding to buf[0]
    this.buf = new Uint8Array(0);
    this.parsePos = 0;
    this.prefaceChecked = false;
    this.pending = new Map();    // relSeq -> Uint8Array (out-of-order segments)
  }
}

export class Reassembler {
  // onMessage({ saddr, daddr, sport, dport, dir, streamId, compressed, payload })
  constructor(onMessage) {
    this.flows = new Map();
    this.onMessage = onMessage;
  }

  push(ev, payload) {
    const key = `${ev.saddr}:${ev.sport}>${ev.daddr}:${ev.dport}`;
    let f = this.flows.get(key);
    if (!f) { f = new Flow(); this.flows.set(key, f); }

    if (f.base === null) f.base = ev.seq;
    let rel = (ev.seq - f.base) >>> 0;

    // Huge jump → almost certainly a new connection reusing the tuple. Reset.
    if (rel > f.buf.length + (32 << 20)) {
      f.base = ev.seq; rel = 0;
      f.buf = new Uint8Array(0); f.parsePos = 0;
      f.prefaceChecked = false; f.pending.clear();
    }

    this._place(f, rel, payload);
    this._parse(f, ev);
  }

  _place(f, rel, payload) {
    if (rel === f.buf.length) {
      f.buf = concat(f.buf, payload);
    } else if (rel < f.buf.length) {
      // overlap / retransmit / duplicate — append only bytes past current end
      const end = rel + payload.length;
      if (end > f.buf.length) f.buf = concat(f.buf, payload.subarray(f.buf.length - rel));
    } else {
      f.pending.set(rel, payload);  // gap — stash until it fills
    }
    // drain anything now contiguous
    let progressed = true;
    while (progressed) {
      progressed = false;
      for (const [r, p] of f.pending) {
        if (r <= f.buf.length) {
          const end = r + p.length;
          if (end > f.buf.length) f.buf = concat(f.buf, p.subarray(f.buf.length - r));
          f.pending.delete(r);
          progressed = true;
        }
      }
    }
  }

  _parse(f, ev) {
    if (!f.prefaceChecked) {
      if (prefacePrefix(f.buf)) {
        if (f.buf.length < PREFACE.length) return;   // wait — might be the preface
        f.parsePos = PREFACE.length;                 // full preface, skip it
      }
      // else: not a client stream (server side starts with SETTINGS) → parse at 0
      f.prefaceChecked = true;
    }

    while (f.buf.length - f.parsePos >= 9) {
      const p = f.parsePos;
      const len = read24(f.buf, p);
      const type = f.buf[p + 3];
      const flags = f.buf[p + 4];
      const streamId = read31(f.buf, p + 5);
      if (f.buf.length - (p + 9) < len) break;       // frame not fully arrived

      if (type === FRAME_DATA && streamId > 0 && len > 0) {
        let s = p + 9, e = p + 9 + len;
        if (flags & FLAG_PADDED) { const pad = f.buf[s]; s += 1; e -= pad; }
        if (s < e) this._extractGrpc(f.buf.subarray(s, e), streamId, ev);
      }
      f.parsePos = p + 9 + len;
    }

    if (f.parsePos > 0) {                            // compact consumed prefix
      f.buf = f.buf.slice(f.parsePos);
      f.base = (f.base + f.parsePos) >>> 0;
      f.parsePos = 0;
    }
  }

  // gRPC framing inside a DATA payload: 1-byte compressed flag + 4-byte BE length + body.
  _extractGrpc(payload, streamId, ev) {
    let pos = 0;
    while (pos + 5 <= payload.length) {
      const compressed = payload[pos];
      const msgLen = read32(payload, pos + 1);
      if (compressed > 1) break;
      if (msgLen > payload.length - (pos + 5)) break;  // body spans frames — skip (rare for unary)
      if (msgLen > 0) {
        this.onMessage({
          saddr: ev.saddr, daddr: ev.daddr, sport: ev.sport, dport: ev.dport,
          dir: ev.dir, streamId, compressed: compressed === 1,
          payload: payload.subarray(pos + 5, pos + 5 + msgLen),
        });
      }
      pos += 5 + msgLen;
    }
  }
}

export function fmtIp(u32) {
  return `${u32 & 0xff}.${(u32 >> 8) & 0xff}.${(u32 >> 16) & 0xff}.${(u32 >>> 24) & 0xff}`;
}
