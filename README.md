# @lp-labs/basic-auth-codec

Browser-free RFC 7617-style Basic credentials codec with explicit UTF-8 interpretation and
strict Base64. It only encodes/decodes credentials; it never authenticates or logs them.
Independent, with zero runtime or peer dependencies.

## Install and quickstart

```bash
npm install @lp-labs/basic-auth-codec
```

```js
import { encodeBasicCredentials, decodeBasicCredentials } from '@lp-labs/basic-auth-codec';

const header = encodeBasicCredentials('demo', 'secret:part');
const credentials = decodeBasicCredentials(header);
if (credentials.password !== 'secret:part') throw new Error('Credential roundtrip failed');
```

## API and semantics

- `encodeBasicCredentials(username, password): string` returns the complete `Basic ...` header
  value. Both strings are UTF-8 encoded.
- `decodeBasicCredentials(header): BasicCredentials` accepts the Basic scheme case-insensitively
  and returns `{ username, password }`.
- `BasicCredentials` has string `username` and `password` fields.

The username must be nonempty and contain no colon; passwords may contain colons. The decoder
splits at the first colon. This implementation always uses UTF-8 and does not implement a
`charset` challenge parameter or legacy default-encoding mode. Control characters, invalid UTF-8,
malformed/noncanonical Base64, missing separators and oversized values are rejected. Payloads are
limited to 16,384 bytes. Failures throw `TypeError` or `RangeError`.

Encoding/decoding is O(n) in credential length. This format is reversible, not encryption:
applications must use TLS and must not treat Base64 as confidentiality. The codec has no
credential store, password verification, challenge generation, or authorization policy.

Runtime exports: `encodeBasicCredentials`, `decodeBasicCredentials`. Type export:
`BasicCredentials`. ESM/CommonJS declarations; Node.js 18+, ES2022 and TextEncoder/TextDecoder
support, no browser globals.

## Support

If this library is useful to you, consider supporting its maintenance with a [donation via PayPal](https://www.paypal.me/LibinPrasanth).

## Author

Created by [Libin Prasanth](https://www.linkedin.com/in/libinprasanth/). Connect on LinkedIn for updates and discussion.
