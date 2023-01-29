import { Buffer } from "https://deno.land/std@0.175.0/node/buffer.ts";

import v2 from './v2.ts'
import v3 from './v3.ts'
import v4 from './v4.ts'
import deviceId from './deviceId.ts';
import computeCode from './code.ts';
export { v2, v3, v4, deviceId, computeCode };

export interface Token {
    version: 2 | 3 | 4,
    serial: string,
    digits: number
    intervalInSeconds: 30 | 60,
    createdAt: Date,
    expiresAt: Date,
    decryptedSeed: Buffer,
    flags: {
        mode: boolean,
        pinIsRequired: boolean,
        passwordIsRequired: boolean,
        deviceIdIsRequired: boolean,
        usesAppDerivedSeeds: boolean,
        usesTimeDerivedSeeds: boolean,
        keyIs128Bit: boolean,
        pinIsLocal: boolean //v2 only
    },
    /**
     * Computes a code for this token
     * @param pin The pin to use to generate the code
     * @param date The instant to generate the token for
     * @returns Object containg code details
     */
    computeCode: (pin?: string | number, date?: Date) => Code
}

export interface Code {
    validFrom: Date,
    expiresAt: Date,
    code: string
}