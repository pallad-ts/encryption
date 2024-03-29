import * as is from 'predicates'
import {Either, left, right} from '@sweet-monads/either';

const isBase64Internal = require('is-base64');

const HEX_PATTERN = /^([0-9a-f]+)$/

function isHex(value: string) {
    return HEX_PATTERN.test(value);
}

function isBase64(value: string) {
    return isBase64Internal(value, {
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

    static fromString(str: string, encoding: EncryptedValue.Encoding = 'hex'): Either<string, EncryptedValue> {
        const result = str.split(':', 2);

        if (result.length !== 2) {
            return left('Malformed encrypted string');
        }

        if (is.blank(result[0]) || is.blank(result[1])) {
            return left('IV or Encrypted value are empty');
        }

        const isValidIv = encoding === 'hex' ? isHex(result[0]) : isBase64(result[0]);
        const isValidEncrypted = encoding === 'hex' ? isHex(result[1]) : isBase64(result[1]);

        if (!isValidIv || !isValidEncrypted) {
            return left(`Invalid value for encoding: ${encoding}`);
        }

        return EncryptedValue.fromStringFormatted(result[0], result[1], encoding);
    }

    static fromStringFormatted(iv: string, encrypted: string, encoding: EncryptedValue.Encoding = 'hex'): Either<string, EncryptedValue> {
        return fromTry(() => {
            return new EncryptedValue(
                Buffer.from(iv, encoding),
                Buffer.from(encrypted, encoding)
            )
        })
            .mapLeft(x => x.message)
    }
}

function fromTry<T>(fn: () => T): Either<Error, T> {
    try {
        return right(fn());
    } catch (e) {
        return left(e as Error);
    }
}

export namespace EncryptedValue {
    export type Encoding = 'base64' | 'hex';
}
