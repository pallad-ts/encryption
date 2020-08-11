import {Engine, StandardActions} from "@pallad/modules";
import {Container, Definition} from "alpha-dic";
import {Module} from "@src/Module";
import {createSecretKey, randomBytes} from "crypto";
import {Encrypter} from "@pallad/encryption";

describe('Module', () => {

    function assertDefinitionWithSettings(definition: Definition,
                                          settings: Encrypter.Options.FromUser | Encrypter.Secret) {
        expect(definition.args[0])
            .toStrictEqual(settings);
    }

    it('registering in container through module', async () => {
        const container = new Container()
        const engine = new Engine({container});

        const encrypters = {
            foo: createSecretKey(randomBytes(32)),
            bar: {
                secret: createSecretKey(randomBytes(32)),
                algorithm: 'aes-128-cbc'
            }
        };
        engine.registerModule(new Module(encrypters));
        await engine.runAction(StandardActions.INITIALIZATION);

        for (const [name, settings] of Object.entries(encrypters)) {
            const definition = container.findByName(Module.getServiceNameForEncrypterName(name))!;
            assertDefinitionWithSettings(
                definition,
                settings
            );

            const encrypter = await container.get(definition);
            expect(encrypter)
                .toBeInstanceOf(Encrypter);
        }
    });
});