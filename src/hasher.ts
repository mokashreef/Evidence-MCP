import crypto from 'node:crypto';
import fs from 'node:fs';

export interface FileHashResult {
  sha256: string;
  sizeBytes: number;
}

/**
 * Computes SHA-256 and byte size for a given file on disk using a stream.
 */
export async function computeFileSha256AndSize(absolutePath: string): Promise<FileHashResult> {
  if (!fs.existsSync(absolutePath)) {
    throw new Error(`File does not exist: ${absolutePath}`);
  }

  const stat = await fs.promises.stat(absolutePath);
  if (!stat.isFile()) {
    throw new Error(`Target is not a regular file: ${absolutePath}`);
  }

  return new Promise<FileHashResult>((resolve, reject) => {
    const hash = crypto.createHash('sha256');
    const stream = fs.createReadStream(absolutePath);

    stream.on('data', (chunk: Buffer | string) => hash.update(chunk));
    stream.on('error', (err: Error) => reject(new Error(`Failed to read file for hashing: ${err.message}`)));
    stream.on('end', () => {
      resolve({
        sha256: hash.digest('hex'),
        sizeBytes: stat.size,
      });
    });
  });
}

/**
 * Computes SHA-256 hash for arbitrary buffer or string content.
 */
export function computeSha256(content: Buffer | string): string {
  return crypto.createHash('sha256').update(content).digest('hex');
}
