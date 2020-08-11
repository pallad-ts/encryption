import {Encrypter} from "@src/Encrypter";
import {Secret, secret} from "@pallad/secret";
import {createSecretKey, KeyObject, randomBytes} from 'crypto';

describe('Encrypter', () => {
    let encrypter: Encrypter;
    beforeEach(() => {
        encrypter = new Encrypter(secret(randomBytes(32)))
    });

    function assertEncodesAndDecodes(encrypter: Encrypter, input: string = 'foobar') {
        const encoded = encrypter.encode(secret(input));
        const decoded = encrypter.decode(encoded);
        expect(decoded.getValue())
            .toEqual(input);
    }

    function assertSecretToBeSecret(encrypter: Encrypter) {
        expect(encrypter['options']['secret'])
            .toBeInstanceOf(Secret);
    }

    function assertSecretToBeKeyObject(encrypter: Encrypter) {
        expect(encrypter['options']['secret'])
            .toBeInstanceOf(KeyObject);
    }

    function assertAlgorithm(encrypter: Encrypter, algorithm: string = 'aes-256-cbc') {
        expect(encrypter['options']['algorithm'])
            .toBe(algorithm)
    }

    it.each([
        ['somerandomstring'],
        [JSON.stringify({some: {random: "data"}})]
    ])('encodes and decodes data', input => {
        assertEncodesAndDecodes(encrypter, input);
    });

    describe('creating', () => {

        describe('constructor', () => {
            it('using KeyObject', () => {
                const encrypter = new Encrypter(
                    createSecretKey(randomBytes(32))
                );
                assertEncodesAndDecodes(encrypter);
                assertSecretToBeKeyObject(encrypter);
                assertAlgorithm(encrypter);
            });

            it('using @pallad/secret', () => {
                const encrypter = new Encrypter(
                    secret(randomBytes(32))
                );
                assertEncodesAndDecodes(encrypter);
                assertSecretToBeSecret(encrypter);
                assertAlgorithm(encrypter);
            });

            it('using different algorithm', () => {
                const encrypter = new Encrypter({
                    secret: createSecretKey(randomBytes(16)),
                    algorithm: 'aes-128-cbc'
                });
                assertEncodesAndDecodes(encrypter);
                assertSecretToBeKeyObject(encrypter);
                assertAlgorithm(encrypter, 'aes-128-cbc');
            });
        });

        describe('from raw', () => {
            it('using string', () => {
                const encrypter = Encrypter.fromRaw(randomBytes(16).toString('hex'));
                assertEncodesAndDecodes(encrypter);
                assertSecretToBeSecret(encrypter);
                assertAlgorithm(encrypter);
            });

            it('using KeyObject', () => {
                const encrypter = Encrypter.fromRaw(createSecretKey(randomBytes(32)));
                assertEncodesAndDecodes(encrypter);
                assertSecretToBeKeyObject(encrypter);
                assertAlgorithm(encrypter);
            });

            it('using buffer', () => {
                const encrypter = Encrypter.fromRaw(randomBytes(32));
                assertEncodesAndDecodes(encrypter);
                assertSecretToBeSecret(encrypter);
                assertAlgorithm(encrypter);
            });

            it('using custom algorithm', () => {
                const encrypter = Encrypter.fromRaw({
                    secret: randomBytes(16),
                    algorithm: 'aes-128-cbc'
                });
                assertEncodesAndDecodes(encrypter);
                assertSecretToBeSecret(encrypter);
                assertAlgorithm(encrypter, 'aes-128-cbc');
            });
        });
    });
});