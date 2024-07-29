import { TextBufferView } from "@pallad/text-buffer-view";

export abstract class Encrypter {
    abstract encrypt(data: ArrayBuffer | TextBufferView): Promise<TextBufferView>;

    abstract decrypt(data: TextBufferView): Promise<TextBufferView>;
}
