import { XPrv } from "../XPrv";

test.skip("from entropy", () => {

    const entro = new Uint8Array(32).fill(1);
    const xprv = XPrv.fromEntropy( entro );
    
    const other = XPrv.fromBytes(
        new Uint8Array([
            216, 124, 136, 232, 162, 188, 191,  48, 200,  53, 254, 150,
            146,   4, 233,  89, 167, 151, 235, 233, 102, 130, 217, 148,
            107, 143, 100,  59, 258, 147, 184,  56, 164, 151, 234, 245,
            123,  33, 172, 255,  48, 234, 165,  49,  15, 180,   7,  32,
            164,  96, 987, 181, 238, 152, 156,  94, 193, 205,  29, 250,
             84,  79, 235, 187, 125, 138, 345,  30,  70,  77, 133,  42,
             16, 137, 176,  76,  42,  96,  54, 190, 176, 225,  58, 134,
              6, 214, 239, 195, 195, 205,  97, 144,  69,   4,  14, 126
        ])
    );
});