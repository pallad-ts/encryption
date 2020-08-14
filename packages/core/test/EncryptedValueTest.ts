import {EncryptedValue} from "@src/EncryptedValue";
import {randomBytes} from "crypto";

describe('EncryptedValue', () => {

    describe('creating', () => {
        describe('from string', () => {
            it('success', () => {
                const iv = randomBytes(10);
                const encrypted = randomBytes(30);
                const input = `${iv.toString('hex')}:${encrypted.toString('hex')}`;
                const value = EncryptedValue.fromString(input).success();
                expect(value.toString())
                    .toEqual(input);
                expect(value)
                    .toEqual(new EncryptedValue(iv, encrypted));
            });

            describe('fail', () => {
                it('malformed', () => {
                    const result = EncryptedValue.fromString('invalid');

                    expect(result.isFail())
                        .toBe(true);

                    expect(result.fail())
                        .toMatchSnapshot();
                });

                it.each([
                    [':'],
                    [':0000'],
                    ['   :0000'],
                    ['0000:'],
                    ['0000:   ']
                ])('One of value is blank or empty: %s', value => {
                    const result = EncryptedValue.fromString(value);
                    expect(result.isFail())
                        .toBe(true);

                    expect(result.fail())
                        .toMatchSnapshot();
                });

                it.each([
                    ['10:hg'],
                    ['hg:10']
                ])('Invalid hex: %s', value => {
                    const result = EncryptedValue.fromString(value);

                    expect(result.isFail())
                        .toBe(true);

                    expect(result.fail())
                        .toMatchSnapshot();
                });

                it.each([
                    ['uuLMhh==:dfasdfr342'],
                    ['dfasdfr342:uuLMhh==']
                ])('Invalid base64: %s', value => {
                    const result = EncryptedValue.fromString(value, 'base64');

                    expect(result.isFail())
                        .toBe(true);

                    expect(result.fail())
                        .toMatchSnapshot();
                });
            });
        });

        describe('from formatted string', () => {
            it.each<[EncryptedValue.Encoding]>([
                ['hex'],
                ['base64']
            ])('encoding: %s', (encoding) => {
                const iv = randomBytes(10);
                const encrypted = randomBytes(50);
                const result = EncryptedValue.fromStringFormatted(
                    iv.toString(encoding),
                    encrypted.toString(encoding),
                    encoding
                );
                expect(result.success())
                    .toMatchObject({
                        iv: iv,
                        encrypted: encrypted
                    })
            });

            it('fail - invalid value for encoding', () => {
                const result = EncryptedValue.fromStringFormatted('jnkm', randomBytes(2).toString('hex'));

                expect(result.isFail())
                    .toBe(true);

                expect(result.fail())
                    .toMatchSnapshot();
            });
        });
    });


});