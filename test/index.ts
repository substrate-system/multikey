import { test } from '@substrate-system/tapzero'
import { webcrypto } from '@substrate-system/one-webcrypto'
import { encode, decode } from '../src/index.js'
import { base58btc } from 'multiformats/bases/base58'

test('encode ed25519 public key to multikey format', async t => {
    // Test with a 32-byte ed25519 public key
    const publicKey = new Uint8Array(32).fill(1)
    const encoded = encode(publicKey)

    t.ok(encoded.startsWith('z'), 'should start with z prefix')
    t.ok(encoded.length > 32, 'should be longer than raw key')
})

test('decode multikey format back to raw key', async t => {
    const publicKey = new Uint8Array(32).fill(1)
    const encoded = encode(publicKey)
    const decoded = decode(encoded)

    t.equal(decoded.multicodec, 237, 'should have ed25519-pub multicodec (237)')
    t.equal(decoded.key.length, 32, 'should have 32-byte raw key')
    t.deepEqual(decoded.key, publicKey, 'should decode to original key')
})

test('encode/decode round trip preserves data', async t => {
    const testKeys = [
        new Uint8Array(32).fill(0),
        new Uint8Array(32).fill(255),
        new Uint8Array(32).map((_, i) => i),
        new Uint8Array(32).map((_, i) => i * 7 % 256),
        crypto.getRandomValues(new Uint8Array(32))
    ]

    for (const key of testKeys) {
        const encoded = encode(key)
        const decoded = decode(encoded)
        t.deepEqual(decoded.key, key, 'round trip should preserve key bytes')
        t.equal(decoded.multicodec, 237, 'should preserve multicodec')
    }
})

test('decode accepts multikey with or without z prefix', async t => {
    const publicKey = new Uint8Array(32).fill(42)
    const encoded = encode(publicKey)

    // With 'z' prefix
    const decoded1 = decode(encoded)
    t.equal(decoded1.multicodec, 237, 'should decode with z prefix')
    t.deepEqual(decoded1.key, publicKey,
        'should decode correct key with z prefix')

    // Without 'z' prefix
    const withoutZ = encoded.substring(1)
    const decoded2 = decode(withoutZ)
    t.equal(decoded2.multicodec, 237, 'should decode without z prefix')
    t.deepEqual(decoded2.key, publicKey,
        'should decode correct key without z prefix')
})

test('different keys produce different encodings', async t => {
    const key1 = new Uint8Array(32).fill(1)
    const key2 = new Uint8Array(32).fill(2)

    const encoded1 = encode(key1)
    const encoded2 = encode(key2)

    t.notEqual(encoded1, encoded2,
        'different keys should produce different encodings')
})

test('encoded format is consistent', async t => {
    const publicKey = new Uint8Array(32).fill(123)
    const encoded1 = encode(publicKey)
    const encoded2 = encode(publicKey)

    t.equal(encoded1, encoded2, 'encoding same key should be deterministic')
})

test('handles all zero key', async t => {
    const zeroKey = new Uint8Array(32).fill(0)
    const encoded = encode(zeroKey)
    const decoded = decode(encoded)

    t.deepEqual(decoded.key, zeroKey, 'should handle all-zero key')
    t.equal(decoded.multicodec, 237, 'should have correct multicodec')
})

test('handles all 0xFF key', async t => {
    const maxKey = new Uint8Array(32).fill(255)
    const encoded = encode(maxKey)
    const decoded = decode(encoded)

    t.deepEqual(decoded.key, maxKey, 'should handle all-0xFF key')
    t.equal(decoded.multicodec, 237, 'should have correct multicodec')
})

test('encoded multikey has expected structure', async t => {
    const publicKey = new Uint8Array(32).fill(100)
    const encoded = encode(publicKey)
    const decoded = decode(encoded)

    // Verify the multicodec prefix is present
    t.equal(decoded.multicodec, 237, 'should contain ed25519-pub multicodec')

    // Verify the total decoded length (2 bytes varint + 32 bytes key = 34)
    const fullDecoded = await import('multiformats/bases/base58').then(m =>
        m.base58btc.decode(encoded)
    )
    t.equal(fullDecoded.length, 34, 'should have 2-byte varint + 32-byte key')
    t.equal(fullDecoded[0], 0xed, 'first byte should be 0xed')
    t.equal(fullDecoded[1], 0x01, 'second byte should be 0x01')
})

test('decode extracts correct raw key from varint-prefixed data', async t => {
    const publicKey = crypto.getRandomValues(new Uint8Array(32))
    const encoded = encode(publicKey)
    const decoded = decode(encoded)

    // The raw key should not include the varint prefix
    t.equal(decoded.key.length, 32, 'raw key should be exactly 32 bytes')
    t.notEqual(decoded.key[0], 0xed,
        'raw key should not start with varint prefix')
    t.deepEqual(decoded.key, publicKey, 'raw key should match original')
})

test('encode real ed25519 public key generated with webcrypto', async t => {
    const { subtle } = webcrypto
    // Generate a real ed25519 keypair using webcrypto
    const keypair = await webcrypto.subtle.generateKey(
        { name: 'Ed25519' },
        true,
        ['sign', 'verify']
    )

    // Export the public key as raw bytes
    const publicKeyBytes = await subtle.exportKey('raw', keypair.publicKey)
    const publicKey = new Uint8Array(publicKeyBytes)

    // Verify it's 32 bytes as expected for ed25519
    t.equal(publicKey.length, 32, 'ed25519 public key should be 32 bytes')

    // Encode to multikey format
    const encoded = encode(publicKey)

    // Verify structure
    t.ok(encoded.startsWith('z'), 'should start with z prefix')
    t.equal(encoded.length, 48,
        'should have expected length for ed25519 multikey')

    // Decode and verify round-trip
    const decoded = decode(encoded)
    t.equal(decoded.multicodec, 237, 'should have ed25519-pub multicodec')
    t.deepEqual(decoded.key, publicKey, 'should decode to original key')

    // Verify the encoded string matches the expected multikey format
    const reencoded = encode(publicKey)
    t.equal(encoded, reencoded, 'encoding should be deterministic')
})

test('encode real RSA public key generated with webcrypto', async t => {
    const { subtle } = webcrypto
    // Generate a real RSA keypair using webcrypto
    const keypair = await subtle.generateKey(
        {
            name: 'RSASSA-PKCS1-v1_5',
            modulusLength: 2048,
            publicExponent: new Uint8Array([1, 0, 1]),
            hash: 'SHA-256'
        },
        true,
        ['sign', 'verify']
    )

    // Export the public key in SPKI format
    const publicKeyBytes = await subtle.exportKey('spki', keypair.publicKey)
    const publicKey = new Uint8Array(publicKeyBytes)

    // RSA SPKI keys are larger than ed25519 keys
    t.ok(publicKey.length > 32, 'RSA public key should be larger than 32 bytes')

    // Encode to multikey format with RSA type
    const encoded = encode(publicKey, 'rsa')

    // Verify structure
    t.ok(encoded.startsWith('z'), 'should start with z prefix')
    t.ok(encoded.length > 48, 'RSA multikey should be longer than ed25519')

    // Decode and verify round-trip
    const decoded = decode(encoded)
    t.equal(decoded.multicodec, 4613, 'should have rsa-pub multicodec (4613)')
    t.equal(decoded.type, 'rsa', 'should have type rsa')
    t.deepEqual(decoded.key, publicKey, 'should decode to original key')

    // Verify the encoded string matches the expected multikey format
    const reencoded = encode(publicKey, 'rsa')
    t.equal(encoded, reencoded, 'encoding should be deterministic')
})

test('decode returns correct type field for ed25519', async t => {
    const publicKey = new Uint8Array(32).fill(42)
    const encoded = encode(publicKey, 'ed25519')
    const decoded = decode(encoded)

    t.equal(decoded.type, 'ed25519', 'should have type ed25519')
    t.equal(decoded.multicodec, 237, 'should have ed25519-pub multicodec')
})

test('decode returns correct type field for rsa', async t => {
    const { subtle } = webcrypto
    const keypair = await subtle.generateKey(
        {
            name: 'RSASSA-PKCS1-v1_5',
            modulusLength: 2048,
            publicExponent: new Uint8Array([1, 0, 1]),
            hash: 'SHA-256'
        },
        true,
        ['sign', 'verify']
    )

    const publicKeyBytes = await subtle.exportKey('spki', keypair.publicKey)
    const publicKey = new Uint8Array(publicKeyBytes)
    const encoded = encode(publicKey, 'rsa')
    const decoded = decode(encoded)

    t.equal(decoded.type, 'rsa', 'should have type rsa')
    t.equal(decoded.multicodec, 4613, 'should have rsa-pub multicodec')
})

test('decode returns unknown type for unrecognized multicodec', async t => {
    // Manually create a multikey with an unknown multicodec (e.g., 999)
    // varint encoding of 999 is [0xE7, 0x07]
    const unknownMulticodecVarint = new Uint8Array([0xE7, 0x07])
    const keyBytes = new Uint8Array(32).fill(123)
    const combined = new Uint8Array(unknownMulticodecVarint.length + keyBytes.length)
    combined.set(unknownMulticodecVarint, 0)
    combined.set(keyBytes, unknownMulticodecVarint.length)

    const encoded = base58btc.encode(combined)
    const decoded = decode(encoded)

    t.equal(decoded.type, 'unknown', 'should have type unknown for unrecognized multicodec')
    t.equal(decoded.multicodec, 999, 'should have multicodec 999')
    t.deepEqual(decoded.key, keyBytes, 'should decode key bytes correctly')
})

test('all done', () => {
    // @ts-expect-error tests
    if (!isNode()) window.testsFinished = true
})

function isNode ():boolean {
    return (typeof process !== 'undefined' && !!process.versions?.node)
}
