import {Inject} from "alpha-dic";
import {referenceEncrypter} from "./referenceEncrypter";

export function InjectEncrypter(name: string): ParameterDecorator & PropertyDecorator {
    return function (target: Object, propertyKey: string | symbol, parameterIndex?: number) {
        Inject(referenceEncrypter(name))(target, propertyKey, parameterIndex as any);
    }
}

