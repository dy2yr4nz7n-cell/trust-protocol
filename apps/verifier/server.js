import { createApp } from './app.js';
import { createAuth } from './auth.js';
import { createC2paService } from './c2pa.js';

createAuth();
const port = Number(process.env.PORT || 3000);
if (!Number.isInteger(port) || port < 1 || port > 65535) throw new Error('Invalid PORT');
const service = await createC2paService();
let app;
try { app = createApp({ service, origin: process.env.PUBLIC_ORIGIN || `http://127.0.0.1:${port}` }); }
catch (error) { await service.close(); throw error; }
const server = app.listen(port, process.env.HOST || '127.0.0.1', () => {
  console.log(`TRUST verifier listening on port ${port}`);
  console.log(JSON.stringify(service.status()));
});
server.requestTimeout = 30000;
server.headersTimeout = 15000;
server.on('error', async error => { console.error(error.code || 'SERVER_ERROR'); await service.close(); process.exitCode = 1; });
let stopping = false;
function stop() {
  if (stopping) return;
  stopping = true;
  server.close(async () => { await service.close(); });
}
process.on('SIGINT', stop);
process.on('SIGTERM', stop);
