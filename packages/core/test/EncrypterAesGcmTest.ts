import { EncrypterAesGcm } from "@src/EncrypterAesGcm";
import { randomBytes } from "crypto";
import { Encrypter } from "@src/Encrypter";
import { KeyRing } from "@pallad/keyring";
import "@pallad/errors-dev";
import { ERRORS } from "@src/errors";

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
        const encrypted = await encrypter.encryptFromString(input, "utf8");
        const decrypted = await encrypter.decryptToString(encrypted, "utf8");
        expect(decrypted).toEqual(input);
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
