export interface BasicCredentials {
  username: string;
  password: string;
}
const ALPHABET = 'ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/';
const MAX_CREDENTIAL_BYTES = 16_384;

function encode64(bytes: Uint8Array): string {
  let out = '';
  for (let i = 0; i < bytes.length; i += 3) {
    const a = bytes[i]!,
      b = bytes[i + 1],
      c = bytes[i + 2];
    out += ALPHABET[a >> 2]! + ALPHABET[((a & 3) << 4) | ((b ?? 0) >> 4)]!;
    out +=
      b === undefined
        ? '=='
        : c === undefined
          ? ALPHABET[(b & 15) << 2]! + '='
          : ALPHABET[((b & 15) << 2) | (c >> 6)]! + ALPHABET[c & 63]!;
  }
  return out;
}

function decode64(input: string): Uint8Array {
  if (
    !input ||
    input.length % 4 !== 0 ||
    !/^(?:[A-Za-z0-9+/]{4})*(?:[A-Za-z0-9+/]{2}==|[A-Za-z0-9+/]{3}=)?$(?![\s\S])/.test(input)
  )
    throw new TypeError('Malformed Basic credentials base64.');
  const bytes: number[] = [];
  for (let i = 0; i < input.length; i += 4) {
    const a = ALPHABET.indexOf(input[i]!),
      b = ALPHABET.indexOf(input[i + 1]!);
    const c = input[i + 2] === '=' ? 0 : ALPHABET.indexOf(input[i + 2]!);
    const d = input[i + 3] === '=' ? 0 : ALPHABET.indexOf(input[i + 3]!);
    bytes.push((a << 2) | (b >> 4));
    if (input[i + 2] !== '=') bytes.push(((b & 15) << 4) | (c >> 2));
    if (input[i + 3] !== '=') bytes.push(((c & 3) << 6) | d);
  }
  if (bytes.length > MAX_CREDENTIAL_BYTES) throw new RangeError('Basic credentials are too long.');
  const result = new Uint8Array(bytes);
  if (encode64(result) !== input) throw new TypeError('Noncanonical Basic credentials base64.');
  return result;
}

export function encodeBasicCredentials(username: string, password: string): string {
  if (
    typeof username !== 'string' ||
    typeof password !== 'string' ||
    !username ||
    username.includes(':') ||
    /[\0-\x1f\x7f]/.test(username + password)
  )
    throw new TypeError('Invalid RFC 7617 username or password.');
  const bytes = new TextEncoder().encode(`${username}:${password}`);
  if (new TextDecoder('utf-8', { fatal: true }).decode(bytes) !== `${username}:${password}`)
    throw new TypeError('Credentials contain an unpaired UTF-16 surrogate.');
  if (bytes.length > MAX_CREDENTIAL_BYTES) throw new RangeError('Basic credentials are too long.');
  return `Basic ${encode64(bytes)}`;
}

export function decodeBasicCredentials(header: string): BasicCredentials {
  if (typeof header !== 'string' || header.length > 22_000 || /[\r\n\0]/.test(header))
    throw new TypeError('Invalid Authorization field.');
  const match = /^Basic ([A-Za-z0-9+/]+={0,2})$(?![\s\S])/i.exec(header);
  if (!match) throw new TypeError('Expected a Basic authorization scheme.');
  let decoded: string;
  try {
    decoded = new TextDecoder('utf-8', { fatal: true }).decode(decode64(match[1]!));
  } catch {
    throw new TypeError('Basic credentials are not valid UTF-8.');
  }
  const colon = decoded.indexOf(':');
  if (colon < 0) throw new TypeError('Basic credentials must contain a colon.');
  const username = decoded.slice(0, colon),
    password = decoded.slice(colon + 1);
  if (!username || /[\0-\x1f\x7f]/.test(decoded))
    throw new TypeError('Invalid Basic credentials text.');
  return { username, password };
}
