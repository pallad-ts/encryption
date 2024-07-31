import { Encrypter } from "@pallad/encryption";
import { KMSClient, EncryptCommand, DecryptCommand } from "@aws-sdk/client-kms";
import { TextBufferView } from "@pallad/text-buffer-view";

export class EncrypterAwsKms extends Encrypter {
    #client: KMSClient;
    #keyId: string;

    constructor(client: KMSClient, keyId: string) {
        super();
        this.#client = client;
        this.#keyId = keyId;
    }

    async encrypt(data: ArrayBuffer | Buffer | TextBufferView): Promise<TextBufferView> {
        const result = await this.#client.send(
            new EncryptCommand({
                Plaintext: new Uint8Array(data instanceof TextBufferView ? data.originalArrayBuffer : data),
                KeyId: this.#keyId,
            })
        );

        return TextBufferView.fromArrayBuffer(result.CiphertextBlob!);
    }

    async decrypt(data: Buffer | ArrayBuffer | TextBufferView): Promise<TextBufferView> {
        const cipherTextBlob: Uint8Array =
            data instanceof TextBufferView
                ? new Uint8Array(data.originalArrayBuffer)
                : Buffer.isBuffer(data)
                  ? data
                  : new Uint8Array(data);
        const result = await this.#client.send(
            new DecryptCommand({
                CiphertextBlob: cipherTextBlob,
                KeyId: this.#keyId,
            })
        );

        return TextBufferView.fromArrayBuffer(result.Plaintext!);
    }
}
