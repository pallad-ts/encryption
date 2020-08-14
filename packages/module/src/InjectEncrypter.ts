import {Inject} from "alpha-dic";
import {referenceEncrypter} from "./referenceEncrypter";

export function InjectEncrypter(name: string) {
    return Inject(referenceEncrypter(name));
}

