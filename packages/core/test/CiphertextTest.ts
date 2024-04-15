import { Ciphertext } from "@src/Ciphertext";
import { randomBytes } from "crypto";
import "@pallad/errors-dev";

describe("Ciphertext", () => {
    it("encoding", () => {
        const ciphertext = Ciphertext.schema.parse({
            keyId: "keyId",
            iv: Buffer.from("some_iv"),
            encrypted: Buffer.from("some_encrypted"),
        });

        expect(ciphertext.toString()).toEqual("BWtleUlkB3NvbWVfaXYADnNvbWVfZW5jcnlwdGVk");
    });

    describe("creating", () => {
        it("cannot be instantiated directly", () => {
            expect(() => {
                new Ciphertext();
            }).toThrowErrorMatchingSnapshot();
        });

        describe("from string", () => {
            describe("fail", () => {
                function* cases(): Generator<[string, Buffer]> {
                    const KEY = "some_key_id";
                    const bufferList: Buffer[] = [];

                    // key
                    yield ["empty string", Buffer.concat(bufferList)];
                    bufferList.push(Buffer.from([KEY.length]));
                    yield ["missing key id", Buffer.concat(bufferList)];
                    yield ["invalid key id length", Buffer.concat([...bufferList, randomBytes(4)])];
                    bufferList.push(Buffer.from(KEY, "ascii"));

                    // iv
                    yield ["missing iv length", Buffer.concat(bufferList)];
                    bufferList.push(Buffer.from([12]));
                    yield ["missing iv", Buffer.concat(bufferList)];
                    yield ["invalid iv length", Buffer.concat([...bufferList, randomBytes(4)])];
                    bufferList.push(randomBytes(12));

                    // encrypted
                    yield ["missing encrypted length", Buffer.concat(bufferList)];
                    const encryptedLength = Buffer.alloc(2);
                    encryptedLength.writeUInt16BE(50);
                    bufferList.push(encryptedLength);
                    yield ["missing encrypted", Buffer.concat(bufferList)];
                    yield ["invalid encrypted length", Buffer.concat([...bufferList, randomBytes(4)])];
                    bufferList.push(randomBytes(50));

                    // extra data
                    yield ["extra data", Buffer.concat([...bufferList, randomBytes(10)])];
                }

                it.each(Array.from(cases()))("malformed %s", (name, buffer) => {
                    const result = Ciphertext.fromString(buffer.toString("base64"));
                    expect(result.isLeft()).toBe(true);
                    expect(result.value).toMatchSnapshot();
                });
            });

            it("success", () => {
                const iv = randomBytes(10);
                const encrypted = randomBytes(50);
                const ciphertext = Ciphertext.schema.parse({ keyId: "key", iv, encrypted });

                const result = Ciphertext.fromString(ciphertext.toString());
                expect(result.value).toMatchObject({
                    keyId: "key",
                    iv: iv,
                    encrypted: encrypted,
                });
            });
        });
    });
});
