import { Ciphertext } from "./Ciphertext";
import { KeyRing } from "@pallad/keyring";
import { TextEncoding } from "./TextEncoding";

export abstract class Encrypter {
    constructor(readonly keyRing: KeyRing) {}

    abstract encrypt(data: Buffer): Promise<Ciphertext>;

    async encryptFromString(data: string, encoding: TextEncoding): Promise<Ciphertext> {
        const buffer = Buffer.from(data, encoding);
        return this.encrypt(buffer);
    }

    abstract decrypt(data: Ciphertext): Promise<Buffer>;

    async decryptToString(data: Ciphertext, encoding: TextEncoding): Promise<string> {
        const decrypted = await this.decrypt(data);
        return Buffer.from(decrypted).toString(encoding);
    }
}
