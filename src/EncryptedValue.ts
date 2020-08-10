import {Either, Validation} from "monet";
import * as is from 'predicates'

export class EncryptedValue {
    constructor(readonly iv: Buffer, readonly encrypted: Buffer) {
        Object.freeze(this);
    }

    toString(encoding: EncryptedValue.Encoding = 'hex') {
        return `${this.iv.toString(encoding)}:${this.encrypted.toString(encoding)}`;
    }

    asTuple(): [Buffer, Buffer] {
        return [
            this.iv,
            this.encrypted
        ];
    }

    static fromString(str: string, encoding: EncryptedValue.Encoding = 'hex'): Validation<string, EncryptedValue> {
        const result = str.split(':', 2);

        if (result.length !== 2) {
            return Validation.Fail('Malformed encrypted string');
        }

        if (is.blank(result[0]) || is.blank(result[1])) {
            return Validation.Fail('IV or Encrypted value are empty');
        }

        return Validation.Success(
            EncryptedValue.fromStringFormatted(result[0], result[1], encoding).success()
        );
    }

    static fromStringFormatted(iv: string, encrypted: string, encoding: EncryptedValue.Encoding = 'hex'): Validation<string, EncryptedValue> {
        return Either.fromTry(() => {
            return new EncryptedValue(
                Buffer.from(iv, encoding),
                Buffer.from(encrypted, encoding)
            )
        })
            .leftMap(x => x.message)
            .toValidation();
    }
}

export namespace EncryptedValue {
    export type Encoding = 'base64' | 'hex';
}