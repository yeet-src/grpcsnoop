// Protobuf wire-format decoder. No schema required — produces field numbers
// and typed values. Nested messages are decoded recursively.

const WIRE_VARINT  = 0;
const WIRE_FIXED64 = 1;
const WIRE_LEN     = 2;
const WIRE_FIXED32 = 5;

function decodeVarint(buf, pos) {
  let lo = 0, hi = 0, shift = 0;
  while (pos < buf.length) {
    const b = buf[pos++];
    if (shift < 28) {
      lo |= (b & 0x7f) << shift;
    } else if (shift === 28) {
      lo |= (b & 0x0f) << 28;
      hi |= (b >> 4) & 0x07;
    } else {
      hi |= (b & 0x7f) << (shift - 32);
    }
    shift += 7;
    if (!(b & 0x80)) break;
    if (shift > 63) break;
  }
  return { lo: lo >>> 0, hi: hi >>> 0, pos };
}

function varintStr(lo, hi) {
  if (hi === 0) return String(lo);
  return String(BigInt(lo) | (BigInt(hi) << 32n));
}

// Try to decode buf as valid UTF-8. Returns the string on success, null on failure.
// Treats control chars (except tab/LF/CR) as invalid.
function tryUtf8(buf) {
  let s = '';
  let i = 0;
  while (i < buf.length) {
    const b = buf[i];
    if (b < 0x80) {
      if (b < 0x20 && b !== 0x09 && b !== 0x0a && b !== 0x0d) return null;
      s += String.fromCharCode(b);
      i++;
    } else if ((b & 0xe0) === 0xc0) {
      if (i + 1 >= buf.length) return null;
      const c = buf[i + 1];
      if ((c & 0xc0) !== 0x80) return null;
      const cp = ((b & 0x1f) << 6) | (c & 0x3f);
      if (cp < 0x80) return null;
      s += String.fromCharCode(cp);
      i += 2;
    } else if ((b & 0xf0) === 0xe0) {
      if (i + 2 >= buf.length) return null;
      const c = buf[i + 1], d = buf[i + 2];
      if ((c & 0xc0) !== 0x80 || (d & 0xc0) !== 0x80) return null;
      const cp = ((b & 0x0f) << 12) | ((c & 0x3f) << 6) | (d & 0x3f);
      if (cp < 0x800 || (cp >= 0xd800 && cp <= 0xdfff)) return null;
      s += String.fromCharCode(cp);
      i += 3;
    } else if ((b & 0xf8) === 0xf0) {
      if (i + 3 >= buf.length) return null;
      const c = buf[i + 1], d = buf[i + 2], e = buf[i + 3];
      if ((c & 0xc0) !== 0x80 || (d & 0xc0) !== 0x80 || (e & 0xc0) !== 0x80) return null;
      const cp = ((b & 0x07) << 18) | ((c & 0x3f) << 12) | ((d & 0x3f) << 6) | (e & 0x3f);
      if (cp < 0x10000 || cp > 0x10ffff) return null;
      const hi = 0xd800 + ((cp - 0x10000) >> 10);
      const lo = 0xdc00 + ((cp - 0x10000) & 0x3ff);
      s += String.fromCharCode(hi) + String.fromCharCode(lo);
      i += 4;
    } else {
      return null;
    }
  }
  return s;
}

function toHex(buf, maxBytes = 48) {
  const shown = buf.slice(0, maxBytes);
  const hex = Array.from(shown).map(b => b.toString(16).padStart(2, '0')).join(' ');
  return hex + (buf.length > maxBytes ? ` … (+${buf.length - maxBytes} more)` : '');
}

// Decode a protobuf wire-format buffer. Returns an array of field descriptors.
// maxDepth guards against malformed data causing infinite recursion.
export function decodeProto(buf, maxDepth = 6) {
  if (!buf || buf.length === 0 || maxDepth <= 0) return [];
  const fields = [];
  let pos = 0;

  try {
    while (pos < buf.length) {
      const tagV = decodeVarint(buf, pos);
      if (tagV.pos === pos) break;
      pos = tagV.pos;

      const wireType = tagV.lo & 0x7;
      const fieldNum = tagV.lo >>> 3;

      if (fieldNum === 0) return fields;

      switch (wireType) {
        case WIRE_VARINT: {
          const v = decodeVarint(buf, pos);
          pos = v.pos;
          fields.push({ field: fieldNum, type: 'varint', value: varintStr(v.lo, v.hi) });
          break;
        }
        case WIRE_FIXED64: {
          if (pos + 8 > buf.length) return fields;
          let lo = 0, hi = 0;
          for (let k = 0; k < 4; k++) lo |= buf[pos + k] << (k * 8);
          for (let k = 0; k < 4; k++) hi |= buf[pos + 4 + k] << (k * 8);
          pos += 8;
          fields.push({ field: fieldNum, type: 'fixed64', value: varintStr(lo >>> 0, hi >>> 0) });
          break;
        }
        case WIRE_LEN: {
          const lenV = decodeVarint(buf, pos);
          pos = lenV.pos;
          const len = lenV.lo;
          if (len > buf.length - pos) return fields;
          const data = buf.slice(pos, pos + len);
          pos += len;

          if (len === 0) {
            fields.push({ field: fieldNum, type: 'bytes', value: '(empty)' });
            break;
          }

          const str = tryUtf8(data);
          if (str !== null) {
            fields.push({ field: fieldNum, type: 'string', value: str });
          } else {
            const nested = decodeProto(data, maxDepth - 1);
            if (nested.length > 0) {
              fields.push({ field: fieldNum, type: 'message', value: nested });
            } else {
              fields.push({ field: fieldNum, type: 'bytes', value: toHex(data) });
            }
          }
          break;
        }
        case WIRE_FIXED32: {
          if (pos + 4 > buf.length) return fields;
          let v = 0;
          for (let k = 0; k < 4; k++) v |= buf[pos + k] << (k * 8);
          pos += 4;
          fields.push({ field: fieldNum, type: 'fixed32', value: String(v >>> 0) });
          break;
        }
        default:
          return fields;
      }
    }
  } catch (_) {
    // Return whatever we decoded so far on any error.
  }
  return fields;
}

// Format decoded fields as styled lines. Uses the yeet `style` global.
export function renderFields(fields, depth = 0) {
  const indent = '  '.repeat(depth + 1);
  const lines = [];
  for (const f of fields) {
    if (f.type === 'message') {
      lines.push(`${indent}${style.dim('field ' + f.field)} {`);
      for (const l of renderFields(f.value, depth + 1)) lines.push(l);
      lines.push(`${indent}}`);
    } else {
      const tag = style.dim(`field ${f.field}`);
      const typ = style.dim(`(${f.type})`);
      const val = f.type === 'string' ? style.green(`"${f.value}"`)
                : f.type === 'bytes'  ? style.dim(f.value)
                :                       style.cyan(f.value);
      lines.push(`${indent}${tag} ${typ} ${val}`);
    }
  }
  return lines;
}

// ───────────────────────────── schema-aware decoding ─────────────────────────
//
// Given a schema (from a generated schema.js — see tools/gen-schema.py), label
// fields by NAME and decode scalars to their real types (e.g. a double shows as
// 9.99, not a raw fixed64). The message type isn't on the wire, so we best-fit:
// score each RPC message type by how well the blob's field numbers/wire-types
// match, and pick the cleanest. Falls back to schema-free when nothing fits.

const SCALAR_WT = {
  double: WIRE_FIXED64, fixed64: WIRE_FIXED64, sfixed64: WIRE_FIXED64,
  float: WIRE_FIXED32, fixed32: WIRE_FIXED32, sfixed32: WIRE_FIXED32,
  int32: WIRE_VARINT, int64: WIRE_VARINT, uint32: WIRE_VARINT, uint64: WIRE_VARINT,
  sint32: WIRE_VARINT, sint64: WIRE_VARINT, bool: WIRE_VARINT,
  string: WIRE_LEN, bytes: WIRE_LEN,
};

const shortName = (fq) => fq.slice(fq.lastIndexOf('.') + 1);

// Low-level parse: each entry is { num, wt, lo/hi (varint) | bytes (len/fixed) }.
function rawFields(buf) {
  const out = [];
  let pos = 0;
  while (pos < buf.length) {
    const t = decodeVarint(buf, pos);
    if (t.pos === pos) break;
    pos = t.pos;
    const wt = t.lo & 0x7, num = t.lo >>> 3;
    if (num === 0) break;
    if (wt === WIRE_VARINT) {
      const v = decodeVarint(buf, pos); pos = v.pos;
      out.push({ num, wt, lo: v.lo, hi: v.hi });
    } else if (wt === WIRE_FIXED64) {
      if (pos + 8 > buf.length) break;
      out.push({ num, wt, bytes: buf.slice(pos, pos + 8) }); pos += 8;
    } else if (wt === WIRE_LEN) {
      const l = decodeVarint(buf, pos); pos = l.pos;
      if (l.lo > buf.length - pos) break;
      out.push({ num, wt, bytes: buf.slice(pos, pos + l.lo) }); pos += l.lo;
    } else if (wt === WIRE_FIXED32) {
      if (pos + 4 > buf.length) break;
      out.push({ num, wt, bytes: buf.slice(pos, pos + 4) }); pos += 4;
    } else break;
  }
  return out;
}

function wtCompatible(wt, def) {
  if (def.kind === 'message') return wt === WIRE_LEN;
  if (def.kind === 'enum') return wt === WIRE_VARINT || (def.repeated && wt === WIRE_LEN);
  const swt = SCALAR_WT[def.type];
  if (swt === undefined) return true;
  if (swt === WIRE_LEN) return wt === WIRE_LEN;
  return wt === swt || (def.repeated && wt === WIRE_LEN);   // allow packed repeated
}

// Does `buf` parse as a complete protobuf message (every byte consumed, all
// wire types valid)? Used to tell a nested-message field from a string field
// when they share a wire type — garbage rarely consumes the whole buffer.
function parsesAsMessage(buf) {
  if (!buf || buf.length === 0) return false;
  let pos = 0, n = 0;
  while (pos < buf.length) {
    const t = decodeVarint(buf, pos);
    if (t.pos === pos) return false;
    pos = t.pos;
    const wt = t.lo & 0x7, num = t.lo >>> 3;
    if (num === 0) return false;
    if (wt === WIRE_VARINT) { const v = decodeVarint(buf, pos); if (v.pos === pos) return false; pos = v.pos; }
    else if (wt === WIRE_FIXED64) { if (pos + 8 > buf.length) return false; pos += 8; }
    else if (wt === WIRE_LEN) { const l = decodeVarint(buf, pos); pos = l.pos; if (l.lo > buf.length - pos) return false; pos += l.lo; }
    else if (wt === WIRE_FIXED32) { if (pos + 4 > buf.length) return false; pos += 4; }
    else return false;
    n++;
  }
  return n > 0 && pos === buf.length;
}

// Score how well a matched field's *content* fits its schema type, so look-alike
// wire signatures (string-vs-message at the same field number) disambiguate.
function fieldPoints(f, def) {
  if (f.wt === WIRE_LEN && f.bytes) {
    if (def.kind === 'message') return parsesAsMessage(f.bytes) ? 2 : 0.1;
    if (def.type === 'string') return tryUtf8(f.bytes) !== null ? 1.5 : 0.1;
  }
  return 1;
}

// Pick the message type whose fields best fit this blob. Candidates are the
// RPC request/response types (nested types are reached via recursion).
function bestFit(raw, schema) {
  const cands = (schema.rpcTypes && schema.rpcTypes.length)
    ? schema.rpcTypes : Object.keys(schema.messages);
  let best = null, bestScore = 0;
  for (const tn of cands) {
    const m = schema.messages[tn];
    if (!m) continue;
    let known = 0, unknown = 0, incompat = 0;
    for (const f of raw) {
      const def = m.fields[String(f.num)];
      if (!def) { unknown++; continue; }
      if (wtCompatible(f.wt, def)) known += fieldPoints(f, def); else incompat++;
    }
    if (incompat > 0) continue;
    const score = known - 0.25 * unknown;
    if (known > 0 && score > bestScore) { bestScore = score; best = tn; }
  }
  return best;
}

function f64(b) { return new DataView(b.buffer, b.byteOffset, 8).getFloat64(0, true); }
function f32(b) { return new DataView(b.buffer, b.byteOffset, 4).getFloat32(0, true); }
function u32(b) { return new DataView(b.buffer, b.byteOffset, 4).getUint32(0, true) >>> 0; }
function u64s(b) {
  const dv = new DataView(b.buffer, b.byteOffset, 8);
  return varintStr(dv.getUint32(0, true) >>> 0, dv.getUint32(4, true) >>> 0);
}

function formatScalar(type, f) {
  switch (type) {
    case 'string': { const s = tryUtf8(f.bytes); return s !== null ? style.green(`"${s}"`) : style.dim(toHex(f.bytes)); }
    case 'bytes':  return style.dim(toHex(f.bytes));
    case 'bool':   return style.cyan((f.lo || f.hi) ? 'true' : 'false');
    case 'int32':  return style.cyan(String(f.lo | 0));
    case 'uint32': return style.cyan(String(f.lo >>> 0));
    case 'sint32': { const n = f.lo >>> 0; return style.cyan(String((n >>> 1) ^ -(n & 1))); }
    case 'int64': case 'uint64': case 'sint64': return style.cyan(varintStr(f.lo, f.hi));
    case 'double':   return style.cyan(String(f64(f.bytes)));
    case 'float':    return style.cyan(String(f32(f.bytes)));
    case 'fixed32': case 'sfixed32': return style.cyan(String(u32(f.bytes)));
    case 'fixed64': case 'sfixed64': return style.cyan(u64s(f.bytes));
    default:       return style.dim(f.bytes ? toHex(f.bytes) : varintStr(f.lo, f.hi));
  }
}

function renderMessage(typeName, raw, schema, depth) {
  const m = schema.messages[typeName];
  const indent = '  '.repeat(depth + 1);
  const lines = [];
  for (const f of raw) {
    const def = m && m.fields[String(f.num)];
    if (!def) {                                   // unknown field → number + raw value
      const val = f.bytes
        ? (tryUtf8(f.bytes) !== null ? style.green(`"${tryUtf8(f.bytes)}"`) : style.dim(toHex(f.bytes)))
        : style.cyan(varintStr(f.lo, f.hi));
      lines.push(`${indent}${style.dim('#' + f.num)} ${val}`);
      continue;
    }
    if (def.kind === 'message') {
      lines.push(`${indent}${def.name} ${style.dim(shortName(def.type))} {`);
      for (const l of renderMessage(def.type, rawFields(f.bytes), schema, depth + 1)) lines.push(l);
      lines.push(`${indent}}`);
    } else if (def.kind === 'enum') {
      const names = schema.enums[def.type] || {};
      const n = f.lo >>> 0;
      const nm = names[String(n)];
      lines.push(`${indent}${def.name} ${style.dim('(' + shortName(def.type) + ')')} ${style.cyan(nm || String(n))}`);
    } else {
      lines.push(`${indent}${def.name} ${style.dim('(' + def.type + ')')} ${formatScalar(def.type, f)}`);
    }
  }
  return lines;
}

// Returns { typeName, lines } when a schema type fits, else null (caller should
// fall back to schema-free decodeProto/renderFields).
export function decodeNamed(buf, schema) {
  if (!schema || !schema.messages) return null;
  if (!buf || buf.length === 0) return null;
  const raw = rawFields(buf);
  if (raw.length === 0) return null;
  const tn = bestFit(raw, schema);
  if (!tn) return null;
  return { typeName: shortName(tn), lines: renderMessage(tn, raw, schema, 0) };
}
