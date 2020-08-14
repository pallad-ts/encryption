import {Either, Validation} from "monet";
import * as is from 'predicates'

const _isBase64 = require('is-base64');

const HEX_PATTERN = /^([0-9a-f]+)$/
function isHex(value: string) {
    return HEX_PATTERN.test(value);
}

function isBase64(value: string) {
    return _isBase64(value, {
        allowEmpty: false
    });
}

export class EncryptedValue {
    constructor(readonly iv: Buffer, readonly encrypted: Buffer) {
        if (iv.length === 0 || encrypted.length === 0) {
            throw new Error('IV or Encrypted value are empty');
        }

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

        const isValidIv = encoding === 'hex' ? isHex(result[0]) : isBase64(result[0]);
        const isValidEncrypted = encoding === 'hex' ? isHex(result[1]) : isBase64(result[1]);

        if (!isValidIv || !isValidEncrypted) {
            return Validation.Fail(`Invalid value for encoding: ${encoding}`);
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