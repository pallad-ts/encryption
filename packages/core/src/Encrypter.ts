import { TextBufferView } from "@pallad/text-buffer-view";

export abstract class Encrypter {
    abstract encrypt(data: ArrayBuffer | Buffer | TextBufferView): Promise<TextBufferView>;

    abstract decrypt(data: ArrayBuffer | Buffer | TextBufferView): Promise<TextBufferView>;
}
