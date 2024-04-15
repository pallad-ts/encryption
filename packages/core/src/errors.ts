import { ErrorDescriptor, formatCodeFactory, Domain } from "@pallad/errors";
import { EncryptionError } from "./EncryptionError";

const code = formatCodeFactory("E_PALLAD_ENCRYPTION_%c");

export const ERRORS = new Domain().addErrorsDescriptorsMap({
    INVALID_KEYRING: ErrorDescriptor.useDefaultMessage(
        code(1),
        "Provided keyring is not the one configured by encrypter",
        EncryptionError
    ),
});
