import { createAuth } from './auth.js';
const id = process.argv[2];
if (!id) { console.error('Usage: npm run token -- USER_ID'); process.exitCode = 1; }
else console.log(createAuth().createAccessToken({ id }));
