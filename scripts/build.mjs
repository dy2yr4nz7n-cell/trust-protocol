import { mkdir, cp, rm, readFile, writeFile } from 'node:fs/promises';
import { fileURLToPath } from 'node:url';
import { join } from 'node:path';
import { execFileSync } from 'node:child_process';
import { copyProtocolAssets } from './protocol-assets.mjs';

const root = fileURLToPath(new URL('../', import.meta.url));
const out = join(root, 'dist/public');
await rm(out, { recursive: true, force: true });
await mkdir(join(out, 'protocol'), { recursive: true });
await cp(join(root, 'web'), out, { recursive: true });
execFileSync(process.execPath, [join(root, 'node_modules/tailwindcss/lib/cli.js'), '--content', join(root, 'web/simulator/index.html'), '--output', join(out, 'simulator/tailwind.css'), '--minify'], { cwd: root, stdio: 'inherit' });
await copyProtocolAssets(root, join(out, 'protocol'));
// Service workers are not installed in the embedded preview.
const protocol = join(out, 'protocol/index.html');
await writeFile(protocol, (await readFile(protocol, 'utf8')).replace('navigator.serviceWorker.register("sw.js").catch(() => {});', '/* No service worker in the combined app. */'));
await cp(join(root, 'apps/verifier/public'), join(out, 'verifier'), { recursive: true });
if (process.argv.includes('--preview')) {
  const client = join(out, 'verifier/app.js');
  await writeFile(client, (await readFile(client, 'utf8')).replace("fetch('/api/verify'", "fetch('__PORT_3001__/api/verify'"));
  const inspection = join(out, 'inspection/index.html');
  await writeFile(inspection, (await readFile(inspection, 'utf8')).replace("'/api/inspection'", "'__PORT_3001__/api/inspection'").replace("fetch('/health')", "fetch('__PORT_3001__/health')"));
}
console.log('Built dist/public: workspace, protocol, simulator and verifier');
