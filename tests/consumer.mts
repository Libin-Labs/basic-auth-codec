import {
  decodeBasicCredentials,
  encodeBasicCredentials,
  type BasicCredentials,
} from '@lp-labs/basic-auth-codec';
const credentials: BasicCredentials = decodeBasicCredentials(encodeBasicCredentials('u', 'p'));
// @ts-expect-error usernames and passwords are strings.
encodeBasicCredentials('u', 42);
void credentials;
