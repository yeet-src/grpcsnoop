// Output helpers. Falls back to console.log when no PTY is attached.

let hasTty = false;
try { tty.write(''); hasTty = true; } catch (_) {}

export function output(line) {
  if (hasTty) console.log(line);
  else        console.log(line);
}

// Format bytes as a compact hex dump.
export function hexDump(buf, maxBytes = 64) {
  const shown = buf.length > maxBytes ? buf.slice(0, maxBytes) : buf;
  let out = '';
  for (let off = 0; off < shown.length; off += 16) {
    const chunk = shown.slice(off, off + 16);
    const hex = Array.from(chunk).map(b => b.toString(16).padStart(2, '0')).join(' ');
    const asc = Array.from(chunk).map(b => (b >= 0x20 && b < 0x7f) ? String.fromCharCode(b) : '.').join('');
    out += `  ${String(off).padStart(4)} │ ${hex.padEnd(47)} │ ${asc}\n`;
  }
  if (buf.length > maxBytes) out += `  … ${buf.length - maxBytes} more bytes\n`;
  return out;
}

// comm byte array → string (null-terminated).
export function commStr(comm) {
  let s = '';
  const vals = Object.values(comm ?? {});
  for (const b of vals) {
    if (b === 0) break;
    s += String.fromCharCode(b);
  }
  return s || '?';
}
