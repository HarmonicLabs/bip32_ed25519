import { fromUtf8, writeUInt32BE } from "@harmoniclabs/uint8array-utils";
import { hmacSHA512 } from "@harmoniclabs/crypto";

type TypedArray = Int8Array | Uint8ClampedArray | Uint8Array |
    Uint16Array | Int16Array | Uint32Array | Int32Array;

/*
const sizes = {
    md5: 16,
    sha1: 20,
    sha224: 28,
    sha256: 32,
    sha384: 48,
    sha512: 64,
    rmd160: 20,
    ripemd160: 20
}
*/

type BytesLike = string | Uint8Array | TypedArray | DataView;

export function pbkdf2<KeyLen extends number>(
    password: BytesLike,
    salt: BytesLike,
    iterations: number,
    keylen: KeyLen
): Uint8Array & { length: KeyLen }
{
    checkParameters( iterations, keylen )
    password = toBuffer( password );
    salt = toBuffer( salt );

    const DK = new Uint8Array(keylen)
    const block1 = new Uint8Array(salt.length + 4)
    // salt.copy(block1, 0, 0, salt.length)
    block1.set( salt, 0 );

    let destPos = 0
    const hLen = 64; // sha512
    const l = Math.ceil(keylen / hLen)

    for (let i = 1; i <= l; i++) {
        writeUInt32BE(block1, i, salt.length)

        const T = hmacSHA512( password, block1 );
        let U = T

        for (let j = 1; j < iterations; j++) {
            U = hmacSHA512( password, U );
            for (let k = 0; k < hLen; k++) T[k] ^= U[k]
        }

        // T.copy(DK, destPos)
        DK.set(
            // only in the DK bound
            T.slice(0,DK.length - destPos), 
            destPos
        );
        destPos += hLen
    }

    return DK as any;
}

const MAX_ALLOC = Math.pow(2, 30) - 1 // default in iojs

function checkParameters( iterations: number, keylen: number ) {
    if (typeof iterations !== 'number') {
      throw new TypeError('Iterations not a number')
    }
  
    if (iterations < 0) {
      throw new TypeError('Bad iterations')
    }
  
    if (typeof keylen !== 'number') {
      throw new TypeError('Key length not a number')
    }
  
    if (keylen < 0 || keylen > MAX_ALLOC || keylen !== keylen) {
      throw new TypeError('Bad key length')
    }
}

function toBuffer(thing: BytesLike): Uint8Array
{
    if (thing instanceof Uint8Array) {
        return thing
    } else if (typeof thing === 'string') {
        return fromUtf8( thing );
    } else if (ArrayBuffer.isView(thing)) {
        return new Uint8Array( thing.buffer )
    } else {
        throw new TypeError("cannot convert to buffer")
    }
}