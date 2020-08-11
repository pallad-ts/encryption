import {Container} from 'alpha-dic';
import {Module as _Module, StandardActions} from "@pallad/modules";
import {Encrypter} from "@pallad/encryption";

export class Module extends _Module<{ container: Container }> {
    constructor(private encrypters: Record<string, Encrypter.Options.FromUser | Encrypter.Secret>) {
        super('@pallad/encryption-module');
    }

    init() {
        this.registerAction(StandardActions.INITIALIZATION, context => {
            for (const [name, settings] of Object.entries(this.encrypters)) {
                context.container.definitionWithConstructor(
                    Module.getServiceNameForEncrypterName(name),
                    Encrypter
                )
                    .withArgs(settings);
            }
        })
    }

    static getServiceNameForEncrypterName(name: string) {
        return `@pallad/encryption-module/encrypter/${name}`
    };
}