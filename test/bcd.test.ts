import { Buffer } from "https://deno.land/std@0.175.0/node/buffer.ts";

import { dateBCD, intBCD } from '../src/bcd.ts'
import { assertEquals } from "https://deno.land/std@0.175.0/testing/asserts.ts";

Deno.test('dateBCD - ignores seconds', () => {
    assertEquals(dateBCD(new Date(Date.UTC(2020, 1, 1, 1, 1, 1, 1))), dateBCD(new Date(Date.UTC(2020, 1, 1, 1, 1))));
});

Deno.test('dateBCD - calculates examples correctly', () => {
    assertEquals(dateBCD(new Date(Date.UTC(2020, 6, 14, 17, 42))), Buffer.from([0x20, 0x20, 0x7, 0x14, 0x17, 0x42]));
    assertEquals(dateBCD(new Date(Date.UTC(2120, 6, 14, 17, 42))), Buffer.from([0x21, 0x20, 0x7, 0x14, 0x17, 0x42]));
    assertEquals(dateBCD(new Date(Date.UTC(2021, 6, 14, 17, 42))), Buffer.from([0x20, 0x21, 0x7, 0x14, 0x17, 0x42]));
    assertEquals(dateBCD(new Date(Date.UTC(2020, 7, 14, 17, 42))), Buffer.from([0x20, 0x20, 0x8, 0x14, 0x17, 0x42]));
    assertEquals(dateBCD(new Date(Date.UTC(2020, 6, 15, 17, 42))), Buffer.from([0x20, 0x20, 0x7, 0x15, 0x17, 0x42]));
    assertEquals(dateBCD(new Date(Date.UTC(2020, 6, 14, 18, 42))), Buffer.from([0x20, 0x20, 0x7, 0x14, 0x18, 0x42]));
    assertEquals(dateBCD(new Date(Date.UTC(2020, 6, 14, 17, 43))), Buffer.from([0x20, 0x20, 0x7, 0x14, 0x17, 0x43]));
});

Deno.test('intBCD - handles numbers', () => {
    assertEquals(intBCD(0), Buffer.from([0]));
    assertEquals(intBCD(1), Buffer.from([1]));
    assertEquals(intBCD(10), Buffer.from([0x10]));
    assertEquals(intBCD(16), Buffer.from([0x16]));
    assertEquals(intBCD(17), Buffer.from([0x17]));
    assertEquals(intBCD(99), Buffer.from([0x99]));
    assertEquals(intBCD(100), Buffer.from([0x1, 0x00]));
    assertEquals(intBCD(1000), Buffer.from([0x10, 0x00]));
    assertEquals(intBCD(9999), Buffer.from([0x99, 0x99]));
    assertEquals(intBCD(1e10), Buffer.from([0x1, 0x00, 0x00, 0x00, 0x00, 0x00]));
    assertEquals(intBCD(1e20), Buffer.from([0x1, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00]));
});