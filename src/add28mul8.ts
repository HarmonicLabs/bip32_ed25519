
export function add28mul8( x: Uint8Array, y: Uint8Array ): Uint8Array
{
    let carry = 0;
    const out = new Uint8Array( 32 );
    for(let i = 0; i < 28; i++)
    {
        let r = x[i] + (y[i] << 3) + carry;
        out[i] = r & 0xff;
        carry = r >> 8;
    }
    for(let i = 28; i < 32; i++)
    {
        let r = x[i] + carry;
        out[i] = r & 0xff;
        carry = r >> 8;
    }
    return out;
}