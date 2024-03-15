import { XPrv } from "../XPrv";

test("from entropy", () => {

    const entro = new Uint8Array(32).fill(1);
    const xprv = XPrv.fromEntropy( entro );
    
});