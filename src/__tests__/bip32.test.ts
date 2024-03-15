import * as CardanoWasm from "@dcspark/cardano-multiplatform-lib-nodejs";
import { toHex } from "@harmoniclabs/uint8array-utils";
import { XPrv } from "../XPrv";


function harden(num: number): number {
    return 0x80000000 + num;
}

test("prv", () => {
    const xprv = "xprv17qx9vxm6060qjn5fgazfue9nwyf448w7upk60c3epln82vumg9r9kxzsud9uv5rfscxp382j2aku254zj3qfx9fx39t6hjwtmwq85uunsd8x0st3j66lzf5yn30hwq5n75zeuplepx8vxc502txx09ygjgx06n0p";
    //*
    const wasmRoot = CardanoWasm.Bip32PrivateKey.from_bech32( xprv );
    const root = XPrv.fromBech32( xprv );

    expect( toHex( root.bytes ) )
    .toEqual( toHex( wasmRoot.to_raw_bytes() ) );

    const myAccount = root
    .derive(harden(1852)) // purpose
    .derive(harden(1815)) // coin type
    .derive(harden(0)); // account #0

    const account = wasmRoot
    .derive(harden(1852))
    .derive(harden(1815))
    .derive(harden(0));
    
    expect( myAccount.bytes )
    .toEqual( new Uint8Array( account.to_raw_bytes() ) )

    const myPub = myAccount.public().derive(0).bytes;
    const pub = new Uint8Array( account.to_public().derive(0).to_raw_bytes() )

    expect( myPub )
    .toEqual(  pub );
})