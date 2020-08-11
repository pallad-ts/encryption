import {reference} from "alpha-dic";
import {Module} from "./Module";

export function referenceEncrypter(name: string) {
    return reference(Module.getServiceNameForEncrypterName(name));
}