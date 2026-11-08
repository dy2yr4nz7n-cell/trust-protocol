import { mkdtemp, open, rename, rm } from 'node:fs/promises';
import { dirname, join, resolve } from 'node:path';

export async function writePrivateFile(filename, contents) {
  const destination = resolve(filename);
  const temporary = await mkdtemp(join(dirname(destination), '.trust-private-'));
  try {
    const staged = join(temporary, 'content');
    const file = await open(staged, 'wx', 0o600);
    try {
      await file.writeFile(contents, { encoding: 'utf8' });
      await file.sync();
    } finally {
      await file.close();
    }
    await rename(staged, destination);
  } finally {
    await rm(temporary, { recursive: true, force: true });
  }
}
