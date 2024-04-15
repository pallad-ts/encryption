import { Ciphertext } from "./Ciphertext";
import { Encrypter } from "./Encrypter";
import { z } from "zod";
import { webcrypto } from "node:crypto";
import { KeyRing, KeyId } from "@pallad/keyring";
import { Range } from "@pallad/range";
import { left, right } from "@sweet-monads/either";
import { ERRORS } from "./errors";

const ALGORITHM = "AES-GCM";

const CRYPTO_KEY_MAP = new WeakMap<Buffer, Promise<CryptoKey>>();

const KEY_RING = Symbol("KeyRing");

function getCryptoKey(buffer: Buffer): Promise<CryptoKey> {
    let key = CRYPTO_KEY_MAP.get(buffer);
    if (!key) {
        key = webcrypto.subtle.importKey("raw", buffer, ALGORITHM, false, ["encrypt", "decrypt"]);
        CRYPTO_KEY_MAP.set(buffer, key);
    }
    return key;
}

export class EncrypterAesGcm extends Encrypter {
    readonly options: EncrypterAesGcm.Options;

    constructor(
        readonly keyRing: KeyRing,
        options?: EncrypterAesGcm.Options.FromUser
    ) {
        validateKeyRing(keyRing);
        super(keyRing);

        this.options = EncrypterAesGcm.OptionsSchema.parse({
            ivLength: 12,
            ...options,
        });
    }

    async encrypt(data: ArrayBuffer, keyId?: KeyId): Promise<Ciphertext> {
        const key = keyId ? this.keyRing.assertEntryById(keyId) : this.keyRing.getRandomKey();

        const [iv, cryptoKey] = await Promise.all([
            webcrypto.getRandomValues(Buffer.alloc(this.options.ivLength)),
            getCryptoKey(key.key.getValue()),
        ]);

        const encrypted = Buffer.from(
            await webcrypto.subtle.encrypt({ name: ALGORITHM, iv, tagLength: 128 }, cryptoKey, data)
        );
        return Ciphertext.schema.parse({ keyId: key.id, iv, encrypted });
    }

    async decrypt(data: Ciphertext): Promise<Buffer> {
        const { iv, encrypted } = data;
        const key = this.keyRing.assertKeyById(data.keyId);
        const cryptoKey = await getCryptoKey(key.getValue());
        return Buffer.from(await webcrypto.subtle.decrypt({ name: ALGORITHM, iv }, cryptoKey, encrypted));
    }

    static createKeyRing() {
        const keyRing = new KeyRing({
            keySize: Range.create(12),
            validation: validateKeyEntry,
        });

        (keyRing as any)[KEY_RING] = true;
        return keyRing;
    }
}

const ALLOWED_SIZES = new Set([128, 192, 256]);

function validateKeyEntry(entry: KeyRing.Entry) {
    const keySize = entry.key.getValue().length * 8;

    if (!ALLOWED_SIZES.has(keySize)) {
        return left(`Key size ${keySize} is not allowed`);
    }

    return right(entry);
}

function validateKeyRing(keyRing: KeyRing) {
    if ((keyRing as any)[KEY_RING] !== true) {
        throw ERRORS.INVALID_KEYRING.create();
    }
}

export namespace EncrypterAesGcm {
    export const OptionsSchema = z.object({
        ivLength: z.number().int().min(12).max(64),
    });
    export type Options = z.infer<typeof OptionsSchema>;

    export namespace Options {
        export type FromUser = Partial<Options>;
    }
}
