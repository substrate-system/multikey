import { base58btc } from 'multiformats/bases/base58'
import { webcrypto } from '@substrate-system/one-webcrypto'

const { subtle } = webcrypto

// multicodec code for ed25519-pub is 0xED (237).
// varint encoding for 237 is two bytes: 0xED 0x01
const ED25519_MULTICODEC_VARINT = Uint8Array.from([0xed, 0x01])

// multicodec code for rsa-pub is 0x1205 (4613).
// varint encoding for 4613 is two bytes: 0x85 0x24
const RSA_MULTICODEC_VARINT = Uint8Array.from([0x85, 0x24])

export type KeyType = 'ed25519'|'rsa'

/**
 * Encode the given Uint8Array to a Multikey string.
 * @param {Uint8Array} rawKeyBytes The key material
 * @param {'ed25519'|'rsa'} keyType key algorithm -- RSA or Ed25519
 * @returns {string} Multikey encoded key string
 */
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
 * Take a CryptoKey instance and convert it to MultiKey format.
 */
encode.cryptoKey = async function (key:CryptoKey, alg:KeyType) {
    const rawKey = await subtle.exportKey('raw', key)
    return encode(new Uint8Array(rawKey), alg)
}

/**
 * Decode a Multikey multibase string (ed25519-pub) back to raw key bytes.
 * Returns an object where `multicodec` is the multicodec
 * numeric code -- 237 for Ed255519, 4613 for RSA.
 */
export function decode (multibaseStr:string):{
    multicodec:number,
    key:Uint8Array<ArrayBuffer>,
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
        type: type as KeyType|'unknown'
    }
}

/**
 * Decode a given string to a CryptoKey instance.
 *
 * @param {string} multibaseStr A multikey encoded public key
 * @returns {CryptoKey} Public key as a `CryptoKey`
 */
decode.toCryptoKey = async function (multibaseStr:string):Promise<CryptoKey> {
    const keyData = decode(multibaseStr)
    const key = await subtle.importKey(
        'raw',
        keyData.key,
        'ed25519',
        true,
        ['verify']
    )

    return key
}
