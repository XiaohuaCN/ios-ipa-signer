// Parse only curl's numeric progress rows. Never forward its raw stderr:
// errors and diagnostics can contain private URLs, headers or credentials.
const quantity = /^\d+(?:\.\d+)?[kMGTPE]?$/;
const duration = /^(?:\d+:\d{2}:\d{2}|--:--:--)$/;
function bytes(value) {
  if (!quantity.test(value)) return NaN;
  const suffix = value.at(-1), power = 'kMGTPE'.indexOf(suffix) + 1;
  return Number(power ? value.slice(0, -1) : value) * 1024 ** power;
}
export function parseCurlProgress(line, direction) {
  if (!['download', 'upload'].includes(direction) || line.length > 1024) return null;
  const fields = line.trim().split(/\s+/);
  if (fields.length !== 12 || [0, 2, 4].some(i => !/^\d{1,3}$/.test(fields[i]) || Number(fields[i]) > 100) ||
      [1, 3, 5, 6, 7, 11].some(i => !quantity.test(fields[i])) || [8, 9, 10].some(i => !duration.test(fields[i]))) return null;
  return { transferred: bytes(fields[direction === 'download' ? 3 : 5]), total: bytes(fields[1]),
    percent: Number(fields[direction === 'download' ? 2 : 4]), speed: bytes(fields[11]), elapsed: fields[9], remaining: fields[10] };
}
export function createTransferProgress(direction, { total = 0, log = console.error, intervalMs = 5000, now = Date.now } = {}) {
  if (!['download', 'upload'].includes(direction)) throw new Error('Invalid transfer direction');
  let buffer = '', oversized = false, latest, lastAt = -Infinity, lastLine = '';
  function emit(force = false) {
    if (!latest || (!force && now() - lastAt < intervalMs)) return;
    const length = Number(total) > 0 ? Number(total) : latest.total;
    const percent = length > 0 ? Math.min(100, Math.floor(latest.transferred / length * 100)) + '%' : '--%';
    const transferred = (latest.transferred / 1048576).toFixed(2);
    const size = length > 0 ? (length / 1048576).toFixed(2) : '?';
    const label = direction === 'upload' ? 'OSS upload' : 'Source download';
    const line = `${label}: ${percent} | ${transferred}/${size} MiB | ${(latest.speed / 1048576).toFixed(2)} MiB/s | elapsed ${latest.elapsed} | ETA ${latest.remaining}`;
    if (force && line === lastLine) return;
    log(line); lastAt = now(); lastLine = line;
  }
  function accept() { const parsed = !oversized && parseCurlProgress(buffer, direction); if (parsed) { latest = parsed; emit(); } buffer = ''; oversized = false; }
  return {
    push(chunk) {
      for (const char of chunk.toString('utf8')) {
        if (char === '\r' || char === '\n') accept();
        else if (buffer.length < 1024 && !oversized) buffer += char;
        else { buffer = ''; oversized = true; }
      }
    },
    end() { if (buffer || oversized) accept(); emit(true); },
  };
}
