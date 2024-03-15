import { toHex, writeUint32LE } from "@harmoniclabs/uint8array-utils";
import { add28mul8 } from "./add28mul8";
import { hmacSHA512, addPointsEdwards, bigpointToUint8Array, ed25519bigint, pointFromBytes, scalarMultBase, verifyEd25519Signature } from "@harmoniclabs/crypto";

export type XPubBytes = Uint8Array & { length: 64 }

export class XPub
{
    readonly bytes: XPubBytes

    constructor( bytes: Uint8Array )
    {
        if(!(
            bytes instanceof Uint8Array &&
            bytes.length === 64
        )) throw new TypeError("invalid bytes for 'XPub'");

        Object.defineProperty(
            this, "bytes", {
                value: bytes,
                writable: false,
                enumerable: true,
                configurable: false
            }
        );
    }

    toPubKeyBytes(): Uint8Array & { length: 32 }
    {
        return this.bytes.slice( 0, 32 ) as any;
    }

    chainCode(): Uint8Array & { length: 32 }
    {
        return this.bytes.slice( 32, 64 ) as any;
    }

    verify( message: Uint8Array, signature: Uint8Array ): boolean
    {
        return verifyEd25519Signature( signature, message, this.toPubKeyBytes() );
    }

    derive( index: number ): XPub
    {
        index = Math.round( Math.abs( index ) );
        
        // NO HARD DERIVATION FOR PUB KEY
        if( index >= 0x80000000 ) index = index - 0x80000000;

        const pk = this.toPubKeyBytes();
        const chainCode = this.chainCode();

        const z = new Uint8Array( 1 + 32 + 4 );
        const i = new Uint8Array( 1 + 32 + 4 );

        z.set([ 0x02 ], 0);
        z.set( pk, 1 );
        writeUint32LE( z, index, 33 );
        i.set([ 0x03 ], 0);
        i.set( pk, 1 );
        writeUint32LE( i, index, 33 );


        const zmac = hmacSHA512( chainCode, z );
        const leftZ = zmac.slice( 0, 32 );
        // const rightZ = zmac.slice( 32, 64 );
        
        const left = pointPlus( pk, point_of_trunc28_mul8( leftZ ) );
        // const right = add256Bits( rightKey, rightZ );

        const imac = hmacSHA512( chainCode, i );
        const nextChainCode = imac.slice( 32, 64 );
        
        const raw = new Uint8Array( 64 ) as XPubBytes;
        raw.set( left, 0 );
        raw.set( nextChainCode, 32 );
        return new XPub( raw );
    }
}

function point_of_trunc28_mul8( sk: Uint8Array ): Uint8Array
{
    const copy = add28mul8( new Uint8Array( 32 ), sk );
    const scalar = ed25519bigint( bytesToNumberLE( copy ) );
    const a = scalarMultBase( scalar );
    return bigpointToUint8Array( a );
}

function pointPlus( p1: Uint8Array, p2: Uint8Array ): Uint8Array
{
    return bigpointToUint8Array(
        addPointsEdwards(
            pointFromBytes( p1 ),
            pointFromBytes( p2 )
        )
    );
}

function bytesToNumberLE(bytes: Uint8Array): bigint
{
    return BigInt( "0x" + toHex(Uint8Array.from(bytes).reverse()) );
}