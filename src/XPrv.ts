import { fromHex, writeUint32LE } from "@harmoniclabs/uint8array-utils";
import { pbkdf2 } from "./pbkdf2";
import { XPub } from "./XPub";
import { add28mul8 } from "./add28mul8";
import { extendedToPublic, signExtendedEd25519, hmacSHA512, sha2_512, decodeBech32, encodeBech32 } from "@harmoniclabs/crypto";

/// Extended Private key size in bytes
const XPRV_SIZE = 96 as const;
const EXTENDED_SECRET_KEY_SIZE = 64;

export type XPrvBytes = Uint8Array & { length: 96 };
// export type Uint8Arr32 = Uint8Array & { length: 32 };

export function isXPrvBytes( stuff: any ): stuff is XPrvBytes
{
    return stuff instanceof Uint8Array && stuff.length === 96;
}

/// Extended Public key size in bytes
const XPUB_SIZE = 64;
const PUBLIC_KEY_SIZE = 32;
const CHAIN_CODE_SIZE = 32;

const hmacSoftInputLen = 1 + 32 + 4;
const hmacHardInputLen = 1 + 64 + 4;

export class XPrv
{
    readonly bytes: XPrvBytes
    constructor( xprv: Uint8Array )
    {
        if(!isXPrvBytes( xprv )) throw new TypeError("invalid argument for 'XPrv'");

        Object.defineProperty(
            this, "bytes", {
                value: xprv,
                writable: false,
                enumerable: true,
                configurable: false
            }
        );
    }

    /**
     * @returns reference to self
     */
    clear3rdHighestBit(): XPrv
    {
        this.bytes[31] &= 0b1101_1111;;
        return this;
    }

    toBech32( prefix: string = "root_xsk" ): string
    {
        return encodeBech32( prefix, this.bytes);
    }

    toString(): string
    {
        return this.toBech32();
    }

    toBytes(): XPrvBytes
    {
        return Uint8Array.prototype.slice.call( this.bytes ) as XPrvBytes;
    }

    chainCode(): Uint8Array & { length: 32 }
    {
        return Uint8Array.prototype.slice.call( this.bytes, 64, 96 ) as any;
    }

    toPrivateKeyBytes(): Uint8Array & { length: 64 }
    {
        return this.bytes.slice( 0, 64 ) as (Uint8Array & { length: 64 });
    }

    sign( message: Uint8Array ): { pubKey: Uint8Array, signature: Uint8Array }
    {
        return signExtendedEd25519( message, this.toPrivateKeyBytes() );
    }

    /**
     * derive extended public key
     */
    public(): XPub
    {
        const pk = extendedToPublic( this.toPrivateKeyBytes() );
        const out = new Uint8Array( XPUB_SIZE ); // 64
        out.set( pk, 0 );
        out.set( this.chainCode(), 32 );
        return new XPub( out );
    }

    static fromBech32( xprv: string ): XPrv
    {
        return new XPrv(
            Uint8Array.from(
                decodeBech32( xprv )[1]
            )
        );
    }
    
    static fromString( xprv: string ): XPrv
    {
        return XPrv.fromBech32( xprv );
    }

    /**
     *  Takes a non-extended Ed25519 secret key and hash through SHA512 it in the same way the standard
     *  Ed25519 signature system make extended key, but *also* force clear the 3rd highest bit of the key
     *  instead of returning an error
     */
    static fromNonExended( bytes: Uint8Array, chainCode: Uint8Array ): XPrv
    {
        const raw = new Uint8Array( XPRV_SIZE ) as XPrvBytes;
        raw.set( sha2_512( bytes ), 0 );
        raw.set( chainCode, 64 );
        normalizeBytesForce3rd( raw );
        return new XPrv( raw );
    }

    static fromExtended( extended: Uint8Array, chainCode: Uint8Array ): XPrv
    {
        const raw = new Uint8Array( XPRV_SIZE );
        raw.set( extended, 0 );
        raw.set( chainCode, 64 );
        return new XPrv( raw );
    }

    /**
     * construtcts an `XPrv` given bip39 entropy bytes
     * 
     * @param password is optional, and in Cardano is more ofthen than not the empty string (`""`)
     * note that this is a totally different password used in cardano wallets (aka. THIS IS **NOT** THE SPENDING PASSWORD)
     * @returns {XPrv} the extended private key
     */
    static fromEntropy( entropy: Uint8Array | string, password: string = "" ): XPrv
    {
        entropy = typeof entropy === "string" && /[0-9a-fA-F]*/.test( entropy ) ? fromHex( entropy ) : entropy; 
        const bytes = pbkdf2( password, entropy, 4096, 96 );
        normalizeBytesForce3rd( bytes );
        return new XPrv( bytes );
    }

    static fromBytes( bytes: Uint8Array ): XPrv
    {
        if(!(
            bytes instanceof Uint8Array &&
            (
                bytes.length === 96 ||
                bytes.length === 64
            )
        )) throw new TypeError("invalid argument for 'XPrv'");

        if( bytes.length === 64 )
        {
            // fromNonExended
            const tmp = new Uint8Array( 96 ) as XPrvBytes;
            tmp.set( sha2_512( bytes.slice( 0,32 ) ) );
            tmp.set( bytes.slice( 32, 64 ), 64 );
            normalizeBytesForce3rd( tmp );
            bytes = tmp;
        }

        const scalar = bytes.slice(0,32);
        const last = scalar[31];
        const first = scalar[0];

        if ((last & 0b1100_0000) !== 0b0100_0000) {
            throw new Error("invalid bytes for XPrv; highest bit invalid");
        }
        if ((first & 0b0000_0111) != 0b0000_0000) {
            throw new Error("invalid bytes for XPrv; lowest bit invalid");
        }

        return new XPrv( bytes );
    }

    derive( index: number ): XPrv
    {
        index = Math.round( Math.abs( index ) );
        
        const extendedKey = this.bytes.slice( 0, 64 );
        const leftKey = this.bytes.slice( 0, 32 );
        const rightKey = this.bytes.slice( 32, 64 );
        const chainCode = this.bytes.slice( 64, 96 );

        const hard = index >= 0x80000000;

        const z = new Uint8Array( hard ? hmacHardInputLen : hmacSoftInputLen );
        const i = new Uint8Array( hard ? hmacHardInputLen : hmacSoftInputLen );

        if( hard )
        {
            z.set([ 0x00 ], 0);
            z.set( extendedKey, 1 );
            writeUint32LE( z, index, 65 );

            i.set([ 0x01 ], 0);
            i.set( extendedKey, 1 );
            writeUint32LE( i, index, 65 );
        }
        else
        {
            const pk = extendedToPublic( extendedKey );
            
            z.set([ 0x02 ], 0);
            z.set( pk, 1 );
            writeUint32LE( z, index, 33 );

            i.set([ 0x03 ], 0);
            i.set( pk, 1 );
            writeUint32LE( i, index, 33 );
        }

        const zmac = hmacSHA512( chainCode, z );
        const leftZ = zmac.slice( 0, 32 );
        const rightZ = zmac.slice( 32, 64 );
        
        const left = add28mul8( leftKey, leftZ );
        const right = add256Bits( rightKey, rightZ );

        // note: we don't perform the check for curve order divisibility because it will not happen:
        // 1. all keys are in the range K=2^254 .. 2^255 (actually the even smaller range 2^254+2^253)
        // 2. all keys are also multiple of 8
        // 3. all existing multiple of the curve order n in the range of K are not multiple of 8

        const imac = hmacSHA512( chainCode, i );
        const nextChainCode = imac.slice( 32, 64 );
        
        const raw = new Uint8Array( XPRV_SIZE ) as XPrvBytes;
        raw.set( left, 0 );
        raw.set( right, 32 );
        raw.set( nextChainCode, 64 );
        return new XPrv( raw );
    }

    static fromParts( left: Uint8Array, right: Uint8Array, chainCode: Uint8Array )
    {
        if(!(
            left instanceof Uint8Array &&
            right instanceof Uint8Array &&
            chainCode instanceof Uint8Array &&

            left.length === 32 &&
            right.length === 32 &&
            chainCode.length === 32
        )) throw new TypeError("invalid XPrv parts");

        const raw = new Uint8Array( XPRV_SIZE ) as XPrvBytes;
        raw.set( left, 0 );
        raw.set( right, 32 );
        raw.set( chainCode, 64 );
        return new XPrv( raw );
    }
}

export function harden(num: number): number {
    return 0x80000000 + num;
}

/** @returns reference to the same input */
function normalizeBytesForce3rd( bytes: XPrvBytes ): XPrvBytes
{
    bytes[0] &= 0b1111_1000;
    bytes[31] &= 0b0001_1111;
    bytes[31] |= 0b0100_0000;
    return bytes;
}

function add256Bits( x: Uint8Array, y: Uint8Array ): Uint8Array
{
    let carry = 0;
    const out = new Uint8Array( 32 );
    for(let i = 0; i < 32; i++)
    {
        let r = x[i] + y[i] + carry;
        out[i] = r & 0xff;
        carry = r >> 8;
    }
    return out;
}