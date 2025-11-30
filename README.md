# multikey

[![tests](https://img.shields.io/github/actions/workflow/status/substrate-system/multikey/nodejs.yml?style=flat-square)](https://github.com/substrate-system/multikey/actions/workflows/nodejs.yml)
[![types](https://img.shields.io/npm/types/@substrate-system/multikey?style=flat-square)](README.md)
[![module](https://img.shields.io/badge/module-ESM%2FCJS-blue?style=flat-square)](README.md)
[![semantic versioning](https://img.shields.io/badge/semver-2.0.0-blue?logo=semver&style=flat-square)](https://semver.org/)
[![Common Changelog](https://nichoth.github.io/badge/common-changelog.svg)](./CHANGELOG.md)
[![install size](https://flat.badgen.net/packagephobia/install/@substrate-system/multikey)](https://packagephobia.com/result?p=@substrate-system/multikey)
[![gzip size](https://flat.badgen.net/bundlephobia/minzip/@substrate-system/multikey?style=flat-square)](https://bundlephobia.com/package/@substrate-system/multikey)
[![license](https://img.shields.io/badge/license-Big_Time-blue?style=flat-square)](LICENSE)


Encode and decode in [multikey format](https://www.w3.org/TR/cid-1.0/#Multikey).
Multikey format is a generic, self-describing 
[multicodec-based](https://www.w3.org/TR/cid-1.0/#multibase-0)
public key encoding.

<details><summary><h2>Contents</h2></summary>

<!-- toc -->

- [Install](#install)
- [Example](#example)
- [API](#api)
  * [`encode (rawKeyBytes, keyType?)`](#encode-rawkeybytes-keytype)
  * [`decode (multibaseStr)`](#decode-multibasestr)
  * [Module formats](#module-formats)
  * [pre-built JS](#pre-built-js)

<!-- tocstop -->

</details>

## Install

```sh
npm i -S @substrate-system/multikey
```

## Example

```js
import { encode, decode } from '@substrate-system/multikey'
const subtle = window.crypto.subtle

// Generate an ed25519 keypair
const keypair = await subtle.generateKey(
    { name: 'Ed25519' },
    true,
    ['sign', 'verify']
)

// Export the public key as raw bytes
const publicKeyBytes = await subtle.exportKey('raw', keypair.publicKey)
const publicKey = new Uint8Array(publicKeyBytes)

// Encode to multikey format (base58btc with 'z' prefix)
// keyType defaults to 'ed25519'
const encoded = encode(publicKey)
console.log(encoded)
// => z6Mk... (a string starting with 'z')

// Decode back to raw key bytes
const decoded = decode(encoded)
console.log(decoded.multicodec)  // => 237 (ed25519-pub)
console.log(decoded.type)        // => 'ed25519'
console.log(decoded.key)         // => Uint8Array(32) [...]

// Round-trip encoding preserves the original key
console.log(decoded.key.toString() === publicKey.toString())  // => true
```


## API

### `encode (rawKeyBytes, keyType?)`

```ts
function encode (
    rawKeyBytes:Uint8Array,
    keyType:'ed25519'|'rsa' = 'ed25519'
)
```

Encode a public key to multikey format.

**Parameters:**
- `rawKeyBytes` (`Uint8Array`) - The raw public key bytes
- `keyType` (`'ed25519' | 'rsa'`, optional) Default is `'ed25519'`

**Returns:** `string` - A base58btc-encoded multikey string starting with 'z'


#### Encode Example

```js
const encoded = encode(publicKey)  // Ed25519 by default
const encodedRsa = encode(rsaPublicKey, 'rsa')  // RSA key
```

### `decode (multibaseStr)`

```ts
function decode (multibaseStr:string):{
    multicodec:number,
    key:Uint8Array<ArrayBufferLike>,
    type:KeyType|'unknown'
}
```

Decode a multikey format string back to raw key bytes.

**Parameters:**

* `multibaseStr` (`string`) - A multikey string (with or without 'z' prefix)

**Returns:** `{ multicodec: number, key: Uint8Array, type: KeyType|'unknown' }`

* `multicodec` - The multicodec identifier (237 for ed25519-pub, 4613 for rsa-pub)
* `key` - The raw public key bytes
* `type` - The key type: `'ed25519'`, `'rsa'`, or `'unknown'`

#### Decode Example

```js
const decoded = decode('z6Mk...')
console.log(decoded.multicodec)  // 237 or 4613 for ed25519 or rsa
console.log(decoded.type)        // 'ed25519', 'rsa', or 'unknown'
console.log(decoded.key)         // Uint8Array
```

### Module formats

This exposes ESM and common JS via
[package.json `exports` field](https://nodejs.org/api/packages.html#exports).
Works in browsers and Node.

#### ESM
```js
import { encode, decode } from '@substrate-system/multikey'
```

#### Common JS
```js
const multi = require('@substrate-system/multikey')
```

### pre-built JS
This package exposes minified JS files too. Copy them to a location that is
accessible to your web server, then link to them in HTML.

#### copy
```sh
cp ./node_modules/@substrate-system/multikey/dist/index.min.js ./public/multikey.min.js
```

#### HTML
```html
<script type="module" src="./multikey.min.js"></script>
```
