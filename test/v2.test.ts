import { v2 } from '../src/v2.ts'
import { assertEquals } from "https://deno.land/std@0.175.0/testing/asserts.ts";

Deno.test('test token 1', () => {
    const token = v2('268761584121121501057537215301771044751053314520620437364173136510454342716753365');
    
    assertEquals(token.computeCode('1234', new Date(Date.UTC(2020, 6, 28, 18, 5))).code, '31478955');
    assertEquals(token.computeCode('1234', new Date(Date.UTC(2020, 6, 13, 22, 42))).code, '99423625');
    assertEquals(token.computeCode('1234', new Date(Date.UTC(2020, 6, 14, 17, 15))).code, '32554647');
    assertEquals(token.computeCode('0000', new Date(Date.UTC(2020, 6, 14, 17, 15))).code, '32553413');
    assertEquals(token.computeCode('1234', new Date(Date.UTC(2020, 6, 14, 17, 16))).code, '22721590');
    assertEquals(token.computeCode('1235', new Date(Date.UTC(2020, 6, 14, 17, 16))).code, '22721591');
    assertEquals(token.computeCode('12345678', new Date(Date.UTC(2020, 6, 14, 17, 16))).code, '34065934');
    assertEquals(token.computeCode('1234', new Date(Date.UTC(2020, 6, 14, 17, 17))).code, '25765781');
    assertEquals(token.computeCode('1234', new Date(Date.UTC(2020, 6, 14, 17, 19))).code, '67905799');
});

Deno.test('test token 1 - URL', () => {
    const token = v2('http://127.0.0.1/securid/ctf?ctfData=268761584121121501057537215301771044751053314520620437364173136510454342716753365');

    assertEquals(token.computeCode('1234', new Date(Date.UTC(2020, 6, 28, 18, 5))).code, '31478955');
    assertEquals(token.computeCode('1234', new Date(Date.UTC(2020, 6, 13, 22, 42))).code, '99423625');
    assertEquals(token.computeCode('1234', new Date(Date.UTC(2020, 6, 14, 17, 15))).code, '32554647');
    assertEquals(token.computeCode('0000', new Date(Date.UTC(2020, 6, 14, 17, 15))).code, '32553413');
    assertEquals(token.computeCode('1234', new Date(Date.UTC(2020, 6, 14, 17, 16))).code, '22721590');
    assertEquals(token.computeCode('1235', new Date(Date.UTC(2020, 6, 14, 17, 16))).code, '22721591');
    assertEquals(token.computeCode('12345678', new Date(Date.UTC(2020, 6, 14, 17, 16))).code, '34065934');
    assertEquals(token.computeCode('1234', new Date(Date.UTC(2020, 6, 14, 17, 17))).code, '25765781');
    assertEquals(token.computeCode('1234', new Date(Date.UTC(2020, 6, 14, 17, 19))).code, '67905799');
});

Deno.test('test token 2', () => {
    const token = v2('265718421982147620421361233751302667731732163701346667424173135550032152716723337');

    assertEquals(token.computeCode('0000', new Date(Date.UTC(2020, 6, 28, 18, 9))).code, '35507896');
    assertEquals(token.computeCode('1234', new Date(Date.UTC(2020, 6, 28, 18, 9))).code, '35508020');
    assertEquals(token.computeCode('0000', new Date(Date.UTC(2020, 6, 28, 18, 10))).code, '08611720');
    assertEquals(token.computeCode('9999', new Date(Date.UTC(2020, 6, 28, 18, 10))).code, '08610619');
});

Deno.test('test token 2 - android', () => {
    const token = v2('265718421982147620421361233751302667731732163701346667424173135550032156671614046');

    assertEquals(token.computeCode('0000', new Date(Date.UTC(2020, 6, 28, 18, 9))).code, '35507896');
    assertEquals(token.computeCode('1234', new Date(Date.UTC(2020, 6, 28, 18, 9))).code, '35508020');
    assertEquals(token.computeCode('0000', new Date(Date.UTC(2020, 6, 28, 18, 10))).code, '08611720');
    assertEquals(token.computeCode('9999', new Date(Date.UTC(2020, 6, 28, 18, 10))).code, '08610619');
});

Deno.test('test token 3', () => {
    const token = v2('205182420547406073217162237716772535444656056374636571404173135644226122716750274');

    assertEquals(token.computeCode('0000', new Date(Date.UTC(2020, 6, 28, 18, 16))).code, '29687245');
    assertEquals(token.computeCode('1234', new Date(Date.UTC(2020, 6, 28, 18, 16))).code, '29688479');
    assertEquals(token.computeCode('0000', new Date(Date.UTC(2020, 6, 28, 18, 17))).code, '10932411');
    assertEquals(token.computeCode('9999', new Date(Date.UTC(2020, 6, 28, 18, 17))).code, '10931300');
});

Deno.test('test token 3 - android', () => {
    const token = v2('205182420547406073217162237716772535444656056374636571404173135644226126671620603');

    assertEquals(token.computeCode('0000', new Date(Date.UTC(2020, 6, 28, 18, 16))).code, '29687245');
    assertEquals(token.computeCode('1234', new Date(Date.UTC(2020, 6, 28, 18, 16))).code, '29688479');
    assertEquals(token.computeCode('0000', new Date(Date.UTC(2020, 6, 28, 18, 17))).code, '10932411');
    assertEquals(token.computeCode('9999', new Date(Date.UTC(2020, 6, 28, 18, 17))).code, '10931300');
});