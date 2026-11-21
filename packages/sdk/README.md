# @blockcred/sdk

An isomorphic SDK (Node ≥ 20 and modern browsers) for BlockCred credentials:

- **`jws`**: strict ES256 JWS on WebCrypto, pluggable signers (HSM/KMS-ready)
- **`sdjwt`**: SD-JWT issue / present / verify with key binding and decoy digests
- **`did`**: did:web resolution (TTL cache, timeouts) and DID document builder
- **`chain`**: read access to `IssuerRegistry`, `RevocationRegistry`, `MerkleAnchor` (ethers v6)
- **`merkle`**: OpenZeppelin `StandardMerkleTree`-compatible proofs
- **`verify`**: the full verification pipeline, returning a verdict

`jws`, `sdjwt`, `did`, `credential` and `util` have **no dependencies** and are safe to bundle in browsers.

## Verify a presentation

```js
import { BlockCredChain, BlockCredVerifier, DidWebResolver, Verdict } from '@blockcred/sdk';

const chain = BlockCredChain.fromConfig({
  rpcUrl: 'https://rpc-amoy.polygon.technology',   // comma-separate several URLs for failover
  chainId: 80002,
  contracts: { IssuerRegistry: '0x…', RevocationRegistry: '0x…', MerkleAnchor: '0x…' },
});

const verifier = new BlockCredVerifier({
  chain,
  didResolver: new DidWebResolver({ cacheTtlMs: 300_000 }),
  audience: 'https://hr.example.com',                 // must equal the KB-JWT aud
  policy: { requireKeyBinding: true, requireAnchor: false, allowedVcts: ['urn:blockcred:vct:degree:v1'] },
});

const result = await verifier.verify(presentation, { nonce: theNonceYouIssued, anchorProof });
if (result.verdict === Verdict.VALID) console.log(result.disclosed);
else console.log(result.verdict, result.error);
```

`verify()` never throws for verification failures. It returns:

```ts
{
  valid: boolean,
  verdict: 'VALID' | 'REVOKED' | 'UNTRUSTED_ISSUER' | 'INVALID_SIGNATURE' | 'EXPIRED' |
           'HOLDER_BINDING_FAILED' | 'REPLAY_DETECTED' | 'UNKNOWN_SCHEMA' |
           'WRONG_STATUS_REGISTRY' | 'NOT_ANCHORED' | 'ISSUER_UNREACHABLE' | 'INVALID_FORMAT' | 'ERROR',
  issuer?, credential?, disclosed?, holder?, checks, errorCode?, error?
}
```

## Issue and present (low level)

```js
import { generateKeyPair, signerFromCryptoKey, exportPublicJwk } from '@blockcred/sdk/jws';
import { issueSdJwt, presentSdJwt, verifySdJwt } from '@blockcred/sdk/sdjwt';

const { sdJwt } = await issueSdJwt({ claims, disclosable: ['name', 'cgpa'], signer: issuerSigner, decoys: 3 });
const presentation = await presentSdJwt({ sdJwt, disclose: ['name'], holderSigner, aud, nonce });
const { disclosed } = await verifySdJwt(presentation, { issuerKey, expectedAud: aud, expectedNonce: nonce, requireKeyBinding: true });
```

## Custom signer (HSM / KMS)

```js
const kmsSigner = {
  alg: 'ES256',
  kid: 'did:web:university.edu#key-2',
  async sign(bytes) {
    const der = await kms.sign({ KeyId, Message: bytes, SigningAlgorithm: 'ECDSA_SHA_256' });
    return derToRaw(der.Signature); // JWS needs 64-byte r||s
  },
};
```

## Tests

```bash
npm test -w packages/sdk
```
