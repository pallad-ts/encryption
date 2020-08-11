import {secret, Secret as _Secret} from "@pallad/secret";
import {EncryptedValue} from "./EncryptedValue";
import {CipherKey, createCipheriv, createDecipheriv, KeyObject, randomBytes} from "crypto";
import * as is from 'predicates'
import {TypeGuardPredicate} from "predicates/types";

const isDataView = is.struct({
    getBigInt64: Function,
    getBigUint64: Function,
    setBigInt64: Function,
    setBigUint64: Function
});

const isKeyObject: TypeGuardPredicate<KeyObject> = is.instanceOf(KeyObject);

const isCipherKeyPredicate = is.any(
    is.string,
    isKeyObject,
    is.instanceOf(Buffer),
    is.instanceOf(Uint8Array),
    is.instanceOf(Uint8ClampedArray),
    is.instanceOf(Uint16Array),
    is.instanceOf(Uint32Array),
    is.instanceOf(Int8Array),
    is.instanceOf(Int16Array),
    is.instanceOf(Int32Array),
    is.instanceOf(Float32Array),
    is.instanceOf(Float64Array),
    isDataView
);

function isCipherKey(value: any): value is CipherKey {
    return isCipherKeyPredicate(value);
}

function toSecret(value: Encrypter.Secret | Encrypter.Secret.Raw): Encrypter.Secret {
    if (isSecret(value)) {
        return value;
    }
    return secret(value);
}

function isSecret(value: any): value is Encrypter.Secret {
    return _Secret.is(value) || isKeyObject(value);
}

function getSecret(value: Encrypter.Secret) {
    return _Secret.is(value) ? value.getValue() : value;
}

export class Encrypter {
    private options: Encrypter.Options;

    constructor(optionsOrSecret: Encrypter.Options.FromUser | Encrypter.Secret) {
        this.options = Object.assign({},
            {
                algorithm: 'aes-256-cbc',
                ivLength: 16
            },
            isSecret(optionsOrSecret) ? {secret: optionsOrSecret} : optionsOrSecret,
        );
    }

    static fromRaw(optionsOrSecret: Encrypter.Options.Raw | Encrypter.Secret.Raw) {
        let secret: Encrypter.Secret;
        let opts: Omit<Encrypter.Options.Raw, 'secret'>;

        if (isCipherKey(optionsOrSecret)) {
            secret = toSecret(optionsOrSecret);
            opts = {};
        } else {
            const {secret: s, ...restOpts} = optionsOrSecret;
            secret = toSecret(s);
            opts = restOpts
        }
        return new Encrypter({
            secret,
            ...opts
        });
    }

    encode(data: _Secret<string>): EncryptedValue {
        const iv = randomBytes(this.options.ivLength);
        const cipher = createCipheriv(
            this.options.algorithm,
            getSecret(this.options.secret),
            iv
        );
        const encrypted = Buffer.concat([
            cipher.update(Buffer.from(data.getValue(), 'utf8')),
            cipher.final()
        ]);
        return new EncryptedValue(iv, encrypted);
    }

    decode(data: EncryptedValue): _Secret<string> {
        const [iv, encrypted] = data.asTuple();
        const decipher = createDecipheriv(
            this.options.algorithm,
            getSecret(this.options.secret),
            iv
        );

        let decoded = decipher.update(encrypted, undefined, 'utf8');
        decoded += decipher.final('utf8');
        return secret(decoded);
    }
}

export namespace Encrypter {
    export interface Options {
        secret: Secret;
        algorithm: string;
        ivLength: number;
    }

    export type Secret = _Secret<Exclude<CipherKey, KeyObject>> | KeyObject;

    export namespace Secret {
        export type Raw = CipherKey;
    }

    export namespace Options {
        export type FromUser = Pick<Options, 'secret'> & Partial<Omit<Options, 'secret'>>;

        export type Raw = { secret: Secret.Raw } & Omit<FromUser, 'secret'>;
    }
}