import { Buffer } from "https://deno.land/std@0.175.0/node/buffer.ts";

import { sha256Hash, sha256Hmac, aes256CBCDecrypt, PBKDF2Sha256 } from './aes.ts';
import { convertV3TokenDate } from './date.ts';
import { Token } from './index.ts';
import { computeCode } from './code.ts';

export const v4 = async (rawToken: string, password = '', deviceId = '')=> await decrypt(parse(rawToken), password, deviceId);
export default v4;

const decrypt = async (token: ReturnType<typeof parse>, password = '', deviceId = '') => {
    if (!password && token.flags.passwordIsRequired) throw new Error('Missing password');
    if (!deviceId && token.flags.deviceIdIsRequired) throw new Error('Missing deviceId');

    const deviceIdClean = deviceId.replace(/[^\da-f]/gi, "").toUpperCase();

    let hash = await computeHash('', deviceIdClean, token._nonce);
    if (hash.compare(token._nonce_devid_hash) != 0) throw new Error('Mismatching _nonce_devid_hash');

    hash = await computeHash(password, deviceIdClean, token._nonce);
    if (hash.compare(token._nonce_devid_pass_hash) != 0) throw new Error('Mismatching _nonce_devid_pass_hash');

    const hmacKey = deriveKey(password, deviceIdClean, token._nonce, 0);
    
    hash = sha256Hmac(hmacKey, toBytes(token, false));
    if (hash.compare(token._mac) != 0) throw new Error('Mismatching _mac');

    hash = deriveKey(password, deviceIdClean, token._nonce, 1);
    const payload = aes256CBCDecrypt(hash.slice(0, 32), token._enc_payload, token._nonce);
    if (payload.length < 160) throw new Error('Payload too short');

    const parsedToken: Partial<Token> = {
        version: 4
    };

    let payloadIndex = 0;

    parsedToken.serial = payload.toString('utf8', payloadIndex, 12).trim();
    payloadIndex += 16;

    parsedToken.decryptedSeed = payload.slice(payloadIndex, payloadIndex + 16);
    payloadIndex += 18;

    token.flags.mode = Boolean(payload[payloadIndex++] > 0);

    parsedToken.digits = payload[payloadIndex++];

    token.flags.pinIsRequired = payload[payloadIndex++] != 0x1f;

    if (payload[payloadIndex] != 30 && payload[payloadIndex] != 60) throw new Error('Invalid interval') 
    parsedToken.intervalInSeconds = payload[payloadIndex++] == 30 ? 30 : 60;

    payloadIndex += 2;

    parsedToken.createdAt = convertV3TokenDate(payload.slice(payloadIndex, payloadIndex + 5));
    payloadIndex += 8;

    parsedToken.expiresAt = convertV3TokenDate(payload.slice(payloadIndex, payloadIndex + 5));

    token.flags.usesAppDerivedSeeds = true;
    token.flags.usesTimeDerivedSeeds = false;
    token.flags.keyIs128Bit = true;

    parsedToken.flags = token.flags as Token["flags"];

    parsedToken.computeCode = computeCode.bind(null, parsedToken as Token);
    return parsedToken as Token;
}

const parse = (rawToken: string) => {
    const token = decodeURIComponent(new URL(rawToken).searchParams.get('ctfData')!);

    const data = Buffer.from(token, 'base64');
    if (data.length < 291) throw new Error('Token too short');

    let dataIndex = 0;
    const version = data[dataIndex++];
    if (version != 4) throw new Error('Expected token version 4 but got ' + version);

    const flags: Partial<Token["flags"]> = {};
    flags.passwordIsRequired = (data[dataIndex++] > 0);
    flags.deviceIdIsRequired = (data[dataIndex++] > 0);

    const _nonce_devid_hash = data.slice(dataIndex, dataIndex + 32);
    dataIndex += 32;

    const _nonce_devid_pass_hash = data.slice(dataIndex, dataIndex + 32);
    dataIndex += 32;

    const _nonce = data.slice(dataIndex, dataIndex + 16);
    dataIndex += 16;

    const _enc_payload = data.slice(dataIndex, dataIndex + 176);
    dataIndex += 176;

    const _mac = data.slice(dataIndex, dataIndex + 32);

    return {
        version,
        _nonce_devid_hash,
        _nonce_devid_pass_hash,
        _nonce,
        _enc_payload,
        _mac,
        flags
    }
}

const computeHash = async (password = '', deviceId = '', salt: Buffer) => {
    if (!salt) throw new Error('Missing salt');
    
    const hash_buf = Buffer.alloc(salt.length + 48 + password.length, 0);
    
    salt.copy(hash_buf, 0, 0, salt.length);
    
    if (deviceId) hash_buf.write(deviceId, salt.length, 48);
    if (password) hash_buf.write(password, salt.length + 48, password.length);

    return await sha256Hash(hash_buf);
}

const toBytes = (token: ReturnType<typeof parse>, includeMac: boolean) => {
    let iPos = 0;
    const tokenBytes = Buffer.alloc(3 + token._nonce_devid_hash.length + token._nonce_devid_pass_hash.length + token._nonce.length + token._enc_payload.length + (includeMac ? token._mac.length : 0));
    tokenBytes[iPos++] = token.version;
    tokenBytes[iPos++] = token.flags.passwordIsRequired ? 1 : 0;
    tokenBytes[iPos++] = token.flags.deviceIdIsRequired ? 1 : 0;

    token._nonce_devid_hash.copy(tokenBytes, iPos, 0, token._nonce_devid_hash.length);
    iPos += token._nonce_devid_hash.length;

    token._nonce_devid_pass_hash.copy(tokenBytes, iPos, 0, token._nonce_devid_pass_hash.length);
    iPos += token._nonce_devid_pass_hash.length;

    token._nonce.copy(tokenBytes, iPos, 0, token._nonce.length);
    iPos += token._nonce.length;

    token._enc_payload.copy(tokenBytes, iPos, 0, token._enc_payload.length);
    iPos += token._enc_payload.length;

    if (includeMac) {
        token._mac.copy(tokenBytes, iPos, 0, token._mac.length);
        iPos += token._mac.length;
    }

    return tokenBytes;
}

const deriveKey = (pass = '', devid = '', salt: Buffer, keyId: 0 | 1) => {
    if (keyId < 0 || keyId > 1) throw new Error("keyId must be 0 or 1.");
    if (!salt) throw new Error('Missing salt');

    const key0 = [ 0xd0, 0x14, 0x43, 0x3c, 0x6d, 0x17, 0x9f, 0xeb, 0xda, 0x09, 0xab, 0xfc, 0x32, 0x49, 0x63, 0x4c ];
    const key1 = [ 0x3b, 0xaf, 0xff, 0x4d, 0x91, 0x8d, 0x89, 0xb6, 0x81, 0x60, 0xde, 0x44, 0x4e, 0x05, 0xc0, 0xdd ];
    const key = Buffer.from((keyId > 0) ? key1 : key0);

    const buf0 = Buffer.alloc(48 + key.length + salt.length + pass.length, 0);

    if (pass) buf0.write(pass);

    if (devid.length > 0) buf0.write(devid, pass.length, 48);

    key.copy(buf0, pass.length + 48, 0, key.length);
    salt.copy(buf0, pass.length + 48 + key.length, 0, salt.length);

    return PBKDF2Sha256(32, buf0, salt, 1000);
}