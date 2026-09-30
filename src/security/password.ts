import { randomBytes, scrypt, timingSafeEqual, type ScryptOptions } from 'node:crypto';

// Node's built-in scrypt: memory-hard, no native dependency to compile.
const N = 2 ** 15, R = 8, P = 1, KEYLEN = 64;

function derive(password: string, salt: Buffer, n: number, r: number, p: number): Promise<Buffer> {
  const opts: ScryptOptions = { N: n, r, p, maxmem: 128 * n * r * 2 };
  return new Promise((resolve, reject) =>
    scrypt(password, salt, KEYLEN, opts, (err, key) => (err ? reject(err) : resolve(key))));
}

export async function hashPassword(password: string): Promise<string> {
  const salt = randomBytes(16);
  const key = await derive(password, salt, N, R, P);
  return ['scrypt', N, R, P, salt.toString('base64'), key.toString('base64')].join('$');
}

// Verified against when the account doesn't exist (or is OAuth-only), so response time
// doesn't reveal which emails are registered.
const DUMMY_HASH = `scrypt$${N}$${R}$${P}$${Buffer.alloc(16).toString('base64')}$${Buffer.alloc(KEYLEN).toString('base64')}`;

export async function verifyPassword(password: string, stored: string | null): Promise<boolean> {
  const [scheme, n, r, p, salt, hash] = (stored ?? DUMMY_HASH).split('$');
  if (scheme !== 'scrypt') return false;
  const expected = Buffer.from(hash!, 'base64');
  const actual = await derive(password, Buffer.from(salt!, 'base64'), Number(n), Number(r), Number(p));
  return timingSafeEqual(actual, expected) && stored !== null;
}
