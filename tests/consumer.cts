import api = require('@lp-labs/basic-auth-codec');
const header: string = api.encodeBasicCredentials('user', 'pass');
void header;
