import { EncrypterAesGcm } from "@src/EncrypterAesGcm";
import { randomBytes } from "crypto";
import { Encrypter } from "@src/Encrypter";
import { KeyRing } from "@pallad/keyring";
import "@pallad/errors-dev";
import { ERRORS } from "@src/errors";
import { TextBufferView } from "@pallad/text-buffer-view";

describe("EncrypterAesGcm", () => {
    let encrypter: EncrypterAesGcm;
    beforeEach(() => {
        const keyRing = EncrypterAesGcm.createKeyRing();
        keyRing.addKey("key1", randomBytes(32));
        keyRing.addKey("key2", randomBytes(32));
        keyRing.addKey("key3", randomBytes(32));
        encrypter = new EncrypterAesGcm(keyRing);
    });

    async function assertEncodesAndDecodes(encrypter: Encrypter, input: string = "foobar") {
        const encryptedBuffer = await encrypter.encrypt(Buffer.from(input, "utf8"));
        const decryptedBuffer = await encrypter.decrypt(encryptedBuffer);
        const encryptedTextBufferView = await encrypter.encrypt(TextBufferView.fromString(input, "utf8"));
        const decryptedTextBufferView = await encrypter.decrypt(encryptedTextBufferView);
        expect(decryptedBuffer.toString('utf8')).toEqual(input);
        expect(decryptedTextBufferView.toString('utf8')).toEqual(input);
    }

    it.each([["somerandomstring"], [JSON.stringify({ some: { random: "data" } })]])(
        "encodes and decodes data",
        input => {
            return assertEncodesAndDecodes(encrypter, input);
        }
    );

    describe("creating", () => {
        it("fails when using keyring that is not created from EncrypterAesGcm.createKeyRing", () => {
            const keyRing = new KeyRing();
            keyRing.addKey("key1", randomBytes(32));
            expect(() => new EncrypterAesGcm(keyRing)).toThrowErrorWithCode(ERRORS.INVALID_KEYRING);
        });

        it("keyring will not accept keys with invalid size", () => {
            const keyRing = EncrypterAesGcm.createKeyRing();

            expect(() => {
                keyRing.addKey("key_invalid", Buffer.alloc(50));
            }).toThrowErrorMatchingSnapshot();
        });
    });
});
