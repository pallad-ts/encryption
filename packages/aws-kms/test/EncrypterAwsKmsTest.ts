import { LocalstackContainer } from "@testcontainers/localstack";
import { StartedLocalStackContainer } from "@testcontainers/localstack/build/localstack-container";
import { CreateAliasCommand, CreateKeyCommand, KMSClient } from "@aws-sdk/client-kms";
import { EncrypterAwsKms } from "@src/EncrypterAwsKms";
import { randomBytes } from "node:crypto";

describe("EncrypterAwsKms", () => {
    let container: StartedLocalStackContainer;
    let kmsClient: KMSClient;

    beforeAll(async () => {
        container = await new LocalstackContainer().start();
        kmsClient = new KMSClient({
            endpoint: container.getConnectionUri(),
        });

        const createdKey = await kmsClient.send(
            new CreateKeyCommand({
                KeyUsage: "ENCRYPT_DECRYPT",
            })
        );

        await kmsClient.send(
            new CreateAliasCommand({
                AliasName: "alias/my-key",
                TargetKeyId: createdKey.KeyMetadata?.KeyId!,
            })
        );
    }, 20000);

    afterAll(() => {
        return container.stop();
    });

    let encrypter: EncrypterAwsKms;
    beforeEach(() => {
        encrypter = new EncrypterAwsKms(kmsClient, "alias/my-key");
    });

    it("encrypts and decrypts data", async () => {
        const data = randomBytes(64);
        const encrypted = await encrypter.encrypt(data);
        const decrypted = await encrypter.decrypt(encrypted);
        expect(Buffer.from(decrypted.originalArrayBuffer)).toEqual(data);
    });
});
