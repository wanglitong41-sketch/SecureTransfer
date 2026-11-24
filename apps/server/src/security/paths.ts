import { lstatSync, realpathSync } from 'node:fs';
import { isAbsolute, relative } from 'node:path';
import { ProtocolError } from '@securetransfer/protocol';

export function requireRegularFile(root: string, path: string) {
  const metadata = lstatSync(path);
  const location = relative(realpathSync(root), realpathSync(path));
  if (
    !metadata.isFile() ||
    metadata.isSymbolicLink() ||
    location.startsWith('..') ||
    isAbsolute(location)
  ) {
    throw new ProtocolError('File is outside its allowed directory', 'FORBIDDEN');
  }
}
