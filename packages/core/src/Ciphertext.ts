import { Either, fromTry, left, right } from "@sweet-monads/either";
import { KeyId, KeyIdSchema } from "@pallad/keyring";
import { ERRORS } from "./errors";
import { z } from "zod";
import { Buffer } from "node:buffer";
import { EncryptionError } from "./EncryptionError";

const MAX_ENCRYPTED_SIZE = 2 ** 16 - 1;
const schema = z
    .object({
        keyId: KeyIdSchema,
        iv: z
            .instanceof(Buffer)
            .refine(value => value.length > 0, "IV cannot be empty")
            .refine(value => value.length < 256, "IV is too long"),
        encrypted: z
            .instanceof(Buffer)
            .refine(value => value.length > 0, "Encrypted data cannot be empty")
            .refine(value => value.length < MAX_ENCRYPTED_SIZE, "Encrypted data is too long"),
    })
    .transform(({ keyId, iv, encrypted }) => {
        return Object.freeze(
            Object.create(Ciphertext.prototype, {
                keyId: { value: keyId, enumerable: true },
                iv: { value: iv, enumerable: true },
                encrypted: { value: encrypted, enumerable: true },
            })
        ) as Ciphertext;
    });

export class Ciphertext {
    readonly keyId: KeyId;
    readonly iv: Buffer;
    readonly encrypted: Buffer;

    constructor() {
        throw new Error("Use Ciphertext.fromString or Ciphertext.schema.parse to create Ciphertext");
    }

    toString() {
        return Buffer.concat(Array.from(encode(this))).toString("base64");
    }

    static fromString(input: string): Either<string, Ciphertext> {
        return fromTry<EncryptionError, Ciphertext>(() => {
            const [keyId, iv, encrypted] = Array.from(decode(input));
            return Ciphertext.schema.parse({ keyId, iv, encrypted });
        }).mapLeft(error => error.message);
    }

    static schema = schema;
}

function* encode(input: Ciphertext): Generator<Buffer> {
    yield Buffer.from([input.keyId.length]);
    yield Buffer.from(input.keyId, "utf-8");
    yield Buffer.from([input.iv.length]);
    yield input.iv;
    const encryptedSizeBuffer = Buffer.alloc(2);
    encryptedSizeBuffer.writeUInt16BE(input.encrypted.length);
    yield encryptedSizeBuffer;
    yield input.encrypted;
}

const MALFORMED = "Malformed ciphertext";

function* decode(input: string) {
    const buffer = Buffer.from(input, "base64");

    let offset = 0;
    const keySize = readUInt8(buffer, offset++);
    yield readAscii(buffer, offset, keySize);
    offset += keySize;

    const ivSize = readUInt8(buffer, offset++);
    yield readBuffer(buffer, offset, ivSize);
    offset += ivSize;

    const encryptedSize = readUInt16(buffer, offset);
    offset += 2;
    yield readBuffer(buffer, offset, encryptedSize);
    offset += encryptedSize;

    if (offset !== buffer.length) {
        throw new EncryptionError("Invalid input length");
    }
}

function readUInt8(input: Buffer, offset: number) {
    if (input.length < offset + 1) {
        throw new EncryptionError(MALFORMED);
    }
    return input.readUInt8(offset);
}

function readUInt16(input: Buffer, offset: number) {
    if (input.length < offset + 2) {
        throw new EncryptionError(MALFORMED);
    }
    return input.readUInt16BE(offset);
}

function readAscii(input: Buffer, offset: number, length: number) {
    if (input.length < offset + length) {
        throw new EncryptionError(MALFORMED);
    }
    return input.toString("ascii", offset, offset + length);
}

function readBuffer(input: Buffer, offset: number, length: number) {
    if (input.length < offset + length) {
        throw new EncryptionError(MALFORMED);
    }
    return input.subarray(offset, offset + length);
}
