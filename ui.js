import { createRequire } from 'module';
import cliProgress from 'cli-progress';

const _pkg = createRequire(import.meta.url)('../package.json');

const C = {
  reset:  '\x1b[0m',
  bold:   '\x1b[1m',
  green:  '\x1b[32m',
  yellow: '\x1b[33m',
  red:    '\x1b[31m',
  cyan:   '\x1b[36m',
  gray:   '\x1b[90m',
  white:  '\x1b[97m',
};

const isTTY = process.stdout.isTTY;

export const fmt = {
  bold:   s => isTTY ? `${C.bold}${s}${C.reset}`   : s,
  gray:   s => isTTY ? `${C.gray}${s}${C.reset}`   : s,
  green:  s => isTTY ? `${C.green}${s}${C.reset}`  : s,
  yellow: s => isTTY ? `${C.yellow}${s}${C.reset}` : s,
  red:    s => isTTY ? `${C.red}${s}${C.reset}`    : s,
  cyan:   s => isTTY ? `${C.cyan}${s}${C.reset}`   : s,
  white:  s => isTTY ? `${C.white}${s}${C.reset}`  : s,
};

export const sym = {
  tick:  fmt.green('✔'),
  cross: fmt.red('✖'),
  warn:  fmt.yellow('⚠'),
  info:  fmt.cyan('ℹ'),
};

export function fmtBytes(n) {
  if (n == null) return '—';
  if (n < 1024)         return `${n} B`;
  if (n < 1024 ** 2)   return `${(n / 1024).toFixed(1)} KB`;
  if (n < 1024 ** 3)   return `${(n / 1024 ** 2).toFixed(1)} MB`;
  return `${(n / 1024 ** 3).toFixed(2)} GB`;
}

export function fmtDate(iso) {
  if (!iso) return '—';
  const d   = new Date(iso);
  const pad = n => String(n).padStart(2, '0');
  return `${d.getFullYear()}-${pad(d.getMonth()+1)}-${pad(d.getDate())} ${pad(d.getHours())}:${pad(d.getMinutes())}`;
}

export function friendlyType(name, chunked) {
  const ext = (name || '').split('.').pop().toLowerCase();
  const map = {
    pdf:'PDF',   png:'PNG',  jpg:'JPEG', jpeg:'JPEG', gif:'GIF',
    webp:'WebP', svg:'SVG',  bmp:'BMP',  ico:'ICO',
    mp4:'MP4',   webm:'WebM',mp3:'MP3',  wav:'WAV',   ogg:'OGG',   flac:'FLAC',
    zip:'ZIP',   tar:'TAR',  gz:'GZip',  rar:'RAR',   '7z':'7Z',
    txt:'Text',  md:'Markdown', html:'HTML', css:'CSS',
    js:'JS',     mjs:'JS',   ts:'TS',    jsx:'JSX',   tsx:'TSX',
    json:'JSON', xml:'XML',  yaml:'YAML',yml:'YAML',  toml:'TOML',
    csv:'CSV',   sql:'SQL',
    py:'Python', sh:'Shell', bash:'Shell',
    c:'C',       cpp:'C++',  h:'C',       java:'Java', go:'Go',
    rs:'Rust',   rb:'Ruby',  php:'PHP',   swift:'Swift',
    doc:'Word',  docx:'Word',xls:'Excel', xlsx:'Excel',ppt:'PPT', pptx:'PPT',
    ttf:'Font',  otf:'Font', woff:'Font', woff2:'Font',
    apk:'APK',   exe:'EXE',  dmg:'DMG',
  };
  const label = map[ext] || (ext ? ext.toUpperCase() : 'File');
  return chunked ? `${label}·C` : label;
}

export function printTable(rows, cols) {
  const termWidth = (process.stdout.columns || 100) - 4;
  const natural   = cols.map((c, i) =>
    Math.max(c.label.length, ...rows.map(r => String(r[i] ?? '').replace(/\x1b\[[0-9;]*m/g, '').length))
  );
  const widths = natural.map((w, i) => Math.min(w, cols[i].maxWidth || 36));
  const gap    = cols.length * 2;
  const tot    = widths.reduce((s, w) => s + w, 0) + gap;
  if (tot > termWidth) {
    const wi = cols.findIndex(c => c.wrap);
    if (wi >= 0) widths[wi] = Math.max(12, widths[wi] - (tot - termWidth));
  }

  const sep    = widths.map(w => '─'.repeat(w)).join('  ');
  const header = cols.map((c, i) => fmt.bold(c.label.padEnd(widths[i]))).join('  ');
  console.log('\n  ' + header);
  console.log('  ' + sep);

  for (const row of rows) {
    const cells = cols.map((c, i) => {
      const raw = String(row[i] ?? '');
      const vis = raw.replace(/\x1b\[[0-9;]*m/g, '');
      const max = widths[i];
      if (vis.length <= max) {
        const pad = ' '.repeat(max - vis.length);
        return [c.right ? pad + raw : raw + pad];
      }
      if (c.wrap) {
        const lines = [];
        let rem = vis;
        while (rem.length > max) {
          let cut = rem.lastIndexOf(' ', max);
          if (cut < Math.floor(max * 0.4)) cut = max;
          lines.push(rem.slice(0, cut).padEnd(max));
          rem = rem.slice(cut).replace(/^ /, '');
        }
        lines.push(rem.padEnd(max));
        return lines;
      }
      return [(vis.slice(0, max - 1) + '…').padEnd(max)];
    });

    const lineCount = Math.max(...cells.map(c => c.length));
    for (let li = 0; li < lineCount; li++) {
      if (li === 0) {
        console.log('  ' + cols.map((_, i) => cells[i][0]).join('  '));
      } else {
        console.log('  ' + cols.map((c, i) =>
          c.wrap ? (cells[i][li] || '').padEnd(widths[i]) : ' '.repeat(widths[i])
        ).join('  '));
      }
    }
  }
}

export function ok(msg)   { console.log(`${sym.tick}  ${msg}`); }
export function fail(msg) { console.error(`${sym.cross}  ${msg}`); }
export function warn(msg) { console.log(`${sym.warn}  ${msg}`); }
export function info(msg) { console.log(`${sym.info}  ${msg}`); }

export function banner() {
  if (!isTTY) return;
  const v = `v${_pkg.version}`;
  console.log(fmt.cyan(fmt.bold(
    `╔══════════════════════════════════════════╗\n` +
    `║  StoreGit CLI  ${v.padEnd(26)}║\n` +
    `║  github-backed personal file storage    ║\n` +
    `╚══════════════════════════════════════════╝`
  )));
  console.log();
}

export function makeBar(label, total) {
  const truncated = label.length > 24 ? label.slice(0, 22) + '…' : label;
  const known     = total && isFinite(total) && total > 0;
  const bar = new cliProgress.SingleBar({
    format: known
      ? `  ${fmt.cyan(truncated.padEnd(26))} {bar} {percentage}%  {value} / {total}  {speed}`
      : `  ${fmt.cyan(truncated.padEnd(26))} {bar}  {value}  {speed}`,
    barCompleteChar:   '█',
    barIncompleteChar: '░',
    barsize:           26,
    hideCursor:        true,
    clearOnComplete:   false,
    formatValue(v, opts, type) {
      if (type === 'value' || type === 'total') return fmtBytes(Number(v)).padStart(9);
      if (type === 'percentage')                return String(v).padStart(3);
      return v;
    },
  }, cliProgress.Presets.shades_classic);
  bar.start(known ? total : 1, 0, { speed: '' });
  return {
    update(bytes, speedBps) {
      const payload = { speed: speedBps ? fmtBytes(speedBps) + '/s' : '' };
      if (known) bar.update(bytes, payload);
      else { bar.setTotal(Math.max(bytes + 1, 1)); bar.update(bytes, payload); }
    },
    complete(bytes) {
      const t = known ? total : bytes;
      bar.setTotal(t); bar.update(t, { speed: '' }); bar.stop();
    },
    stop() { bar.stop(); },
  };
}

export async function confirm(question) {
  if (!isTTY) return true;
  const { createInterface } = await import('readline');
  const rl = createInterface({ input: process.stdin, output: process.stdout });
  return new Promise(resolve => {
    rl.question(`${sym.warn}  ${question}  [y/N]: `, answer => {
      rl.close();
      resolve(answer.trim().toLowerCase() === 'y');
    });
  });
}
