import {Encrypter} from "@src/Encrypter";
import {secret} from "@pallad/secret";
import {createSecretKey, randomBytes} from 'crypto';

describe('Encrypter', () => {
    let encoder: Encrypter;
    beforeEach(() => {
        encoder = new Encrypter(secret(randomBytes(32)))
    });

    it.each([
        ['somerandomstring'],
        [JSON.stringify({some: {random: "data"}})]
    ])('encodes and decodes data', input => {
        const encoded = encoder.encode(secret(input));
        const decoded = encoder.decode(encoded);
        expect(decoded.getValue())
            .toEqual(input);
    });
});