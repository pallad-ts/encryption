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

    async encrypt(data: ArrayBuffer | TextBufferView): Promise<TextBufferView> {
        const result = await this.#client.send(
            new EncryptCommand({
                Plaintext: new Uint8Array(data instanceof TextBufferView ? data.originalArrayBuffer : data),
                KeyId: this.#keyId,
            })
        );

        return TextBufferView.fromArrayBuffer(result.CiphertextBlob!);
    }

    async decrypt(data: TextBufferView): Promise<TextBufferView> {
        const result = await this.#client.send(
            new DecryptCommand({
                CiphertextBlob: new Uint8Array(data.originalArrayBuffer),
                KeyId: this.#keyId,
            })
        );

        return TextBufferView.fromArrayBuffer(result.Plaintext!);
    }
}
