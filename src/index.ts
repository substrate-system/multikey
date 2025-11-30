import { base58btc } from 'multiformats/bases/base58'

// multicodec code for ed25519-pub is 0xED (237).
// varint encoding for 237 is two bytes: 0xED 0x01
const ED25519_MULTICODEC_VARINT = Uint8Array.from([0xed, 0x01])

// multicodec code for rsa-pub is 0x1205 (4613).
// varint encoding for 4613 is two bytes: 0x85 0x24
const RSA_MULTICODEC_VARINT = Uint8Array.from([0x85, 0x24])

export type KeyType = 'ed25519'|'rsa'

export function encode (
    rawKeyBytes:Uint8Array,
    keyType:KeyType
):string {
    const multicodecVarint = keyType === 'rsa' ?
        RSA_MULTICODEC_VARINT :
        ED25519_MULTICODEC_VARINT

    const size = multicodecVarint.length + rawKeyBytes.length
    const out = new Uint8Array(size)
    out.set(multicodecVarint, 0)
    out.set(rawKeyBytes, multicodecVarint.length)

    // multiformats' base58btc.encode typically returns a string that already
    // uses the 'z' prefix
    let encoded = base58btc.encode(out)
    encoded = encoded.startsWith('z') ? encoded : 'z' + encoded

    return encoded
}

/**
 * Decode a Multikey multibase string (ed25519-pub) back to raw key bytes.
 * Returns an object { algCode, rawKey } where algCode is the multicodec
 * numeric code.
 */
export function decode (multibaseStr:string):{
    multicodec:number,
    key:Uint8Array<ArrayBufferLike>,
    type:KeyType|'unknown'
} {
    // Accept with/without leading 'z'
    // multiformats will accept without the 'z' only if decoder used directly.
    const cleaned = (multibaseStr.startsWith('z') ?
        multibaseStr :
        'z' + multibaseStr)
    const decoded = base58btc.decode(cleaned)  // returns Uint8Array

    // read varint (we know ed25519 varint is two bytes: 0xed 0x01)
    // handle single or two-byte varints for small values
    let i = 0
    let code = 0
    let shift = 0
    while (i < decoded.length) {
        const b = decoded[i++]
        code |= (b & 0x7f) << shift
        if ((b & 0x80) === 0) break
        shift += 7
    }
    const rawKey = decoded.slice(i)  // remainder is the raw key bytes

    let type = 'unknown'
    if (code === 237) type = 'ed25519' as const
    if (code === 4613) type = 'rsa' as const

    return {
        multicodec: code,
        key: rawKey,
        type: type as (KeyType|'unknown')
    }
}
