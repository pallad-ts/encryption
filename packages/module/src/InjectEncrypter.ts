import {Inject} from "alpha-dic";
import {referenceEncrypter} from "./referenceEncrypter";

// eslint-disable-next-line @typescript-eslint/naming-convention
export function InjectEncrypter(name: string) {
    return Inject(referenceEncrypter(name));
}

