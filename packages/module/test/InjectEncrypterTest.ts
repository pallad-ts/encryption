import {Encrypter} from "@pallad/encryption";
import {InjectEncrypter} from "@src/InjectEncrypter";
import {getDefinitionForClass, reference, Service} from "alpha-dic";
import {Module} from "@src/Module";

describe('InjectEncrypter', () => {
    const NAME = 'foo';
    it('constructor injection', () => {
        @Service()
        class Foo {
            constructor(@InjectEncrypter(NAME) private encrypter: Encrypter) {
            }
        }

        const definition = getDefinitionForClass(Foo);
        expect(definition.args[0])
            .toStrictEqual(reference(Module.getServiceNameForEncrypterName(NAME)));
    });

    it('property injection', () => {
        @Service()
        class Foo {
            @InjectEncrypter(NAME)
            private encrypter!: Encrypter;
        }

        const definition = getDefinitionForClass(Foo);
        expect(definition.args[0])
            .toStrictEqual(reference(Module.getServiceNameForEncrypterName(NAME)));
    });
})