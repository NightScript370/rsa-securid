import { v3 } from '../src/v3.ts'
import { assertEquals } from "https://deno.land/std@0.175.0/testing/asserts.ts";

Deno.test('test token 1', () => {
    const token = v3('http://127.0.0.1/securid/ctf?ctfData=AwAA6fnJ%2FjXsB5gzMvmXLFf7Vwv7dock0eY9e0Tw9mZrravp%2Bcn%2BNewHmDMy%2BZcsV%2FtXC%2Ft2hyTR5j17RPD2Zmutq5tKvxjTjjScj%2BfbyBikrAwASsH8yed36FZqg%2BePO3mM3ybiR8fkenVhN5ERXVEqiNBKDEDhUh6iq%2BnKSPz752vJl3BD5CFyWfhijcJsH8DGymewRd2owRBXx6Jjm4ugl%2BKJte5TB4prrMdOuxwolL0SOEgVAM1AF3XGtxMK0R1jQwaxTSHGVZYxtnPX6m7E5BSZJrhz4YxQSc2VZwRdEhQWkv48MYiKUO%2BMz18dvOEgrWuFRcQGLIB4BM8C2eZJAro4sKa5V2meplLRY9xZruwSHXpdVWzpZ8B5Ko8ZD9Ei');

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
    const token = v3('http://127.0.0.1/securid/ctf?ctfData=AwAAW1Miv490jp4BICEH%2BrgIZUVV9vkRaSPGQDK78L7kVF1bUyK%2Fj3SOngEgIQf6uAhlRVX2%2BRFpI8ZAMrvwvuRUXfcOaNMiTp0NRL6hiOYvYDdBY%2BnhoRhpEKfFPtMSlsMUsBMSQC%2FoUIIw52i15v0cYIeDm7rueuVOy%2FP6MIy%2Fg1L%2BR22VoKcJ54pmKIdQ5vXSY9ezEQXbNNiVIb%2BVQD8fUZnGByi5meQLsg4YRMWCo3LUc3dFDsTNcdbuEPHTMdt0R9IYPHOpq912sFm6uYa%2FN9AeGslS4xVlEVjKAofAGgWPmdV8vgijUAVY9fz6FumJ8LKpg4vrw5qvq69Jk0B7NLLyBmlXszzAupJJiT6EiWHUAn%2F3dcWYMHOPJRhjorUg');

    assertEquals(token.computeCode('0000', new Date(Date.UTC(2020, 6, 28, 18, 9))).code, '35507896');
    assertEquals(token.computeCode('1234', new Date(Date.UTC(2020, 6, 28, 18, 9))).code, '35508020');
    assertEquals(token.computeCode('0000', new Date(Date.UTC(2020, 6, 28, 18, 10))).code, '08611720');
    assertEquals(token.computeCode('9999', new Date(Date.UTC(2020, 6, 28, 18, 10))).code, '08610619');
});

Deno.test('test token 3', () => {
    const token = v3('http://127.0.0.1/securid/ctf?ctfData=AwAAMgRRiXXanc8kI1VkP7DvG8NrxvneSuvvVaCvHtUH1EsyBFGJddqdzyQjVWQ%2FsO8bw2vG%2Bd5K6%2B9VoK8e1QfUS%2BeYVWyxC7Z74UDpuszaICqqmHicGuO1kJJsAnHdcaXcyTOWuf5b8lTc%2BEC5hGy%2BQwE49%2Bfnma4P9spkqwMPJXDNJmBbbhG4MqaItdoRwnT2i0oDszIAML6DN2zrrD21xGZz8uWN%2BbIBk7F6ZGeEeBXTClXS7lcHGezCQ%2BCNrabode%2Bdt8ueCCbENT9tu7dUTPEtOfbgKbIRrZE6uTZqElFrsdkb%2Faxcw9CdBWVIUsN%2Fb0UvO9faAwNaYsyM10cs88aOj7YyuNrAJbptxAQ3IDPzqKIovIJJajtWm3Qygsm3');

    assertEquals(token.computeCode('0000', new Date(Date.UTC(2020, 6, 28, 18, 16))).code, '29687245');
    assertEquals(token.computeCode('1234', new Date(Date.UTC(2020, 6, 28, 18, 16))).code, '29688479');
    assertEquals(token.computeCode('0000', new Date(Date.UTC(2020, 6, 28, 18, 17))).code, '10932411');
    assertEquals(token.computeCode('9999', new Date(Date.UTC(2020, 6, 28, 18, 17))).code, '10931300');
})