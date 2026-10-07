# google-cloud-kms-signer

Import Ethereum private keys into HSM-backed Google Cloud KMS and sign messages, transactions, and EIP-712 typed data with `CloudWallet`.

Signing verifies CRC32C integrity, normalizes ECDSA signatures to low-s, and recovers the Ethereum recovery ID.

## Setup

Requires Node.js >= 26, pnpm, and a Google Cloud project with the KMS API enabled.

```sh
pnpm install
gcloud auth application-default login
```

The authenticated account needs permissions to list KMS locations, create key rings and keys, create and read import jobs, import key versions, and retrieve public keys.
Signing also requires permission to use key versions to sign.
See [Cloud KMS permissions and roles](https://docs.cloud.google.com/kms/docs/reference/permissions-and-roles) for the corresponding IAM permissions.

## Import a Key

```sh
pnpm exec tsx scripts/import.ts
```

The script detects the project from Application Default Credentials, prompts for the location, key ring, key name, and private key, then verifies that the imported key's Ethereum address matches the local address.
It prints the full key version resource name for use with `CloudWallet`.

## API

Run `pnpm build` to generate `dist/index.js`.

```js
import { CloudWallet } from "./dist/index.js";

const versionName =
  "projects/<project>/locations/<location>/keyRings/<keyRing>/cryptoKeys/<key>/cryptoKeyVersions/<version>";
const wallet = new CloudWallet(versionName);

const address = await wallet.getAddress();
const signature = await wallet.signMessage("message");
```

`CloudWallet` extends ethers.js `BaseWallet` and accepts an optional provider for address and ENS resolution.

| Method                                | Description                                     |
| ------------------------------------- | ----------------------------------------------- |
| `constructor(versionName, provider?)` | Create a wallet backed by a KMS key version     |
| `getAddress()`                        | Derive the Ethereum address from the public key |
| `signMessage(message)`                | Sign an EIP-191 personal message                |
| `signTransaction(tx)`                 | Sign a transaction                              |
| `signTypedData(domain, types, value)` | Sign EIP-712 typed data                         |

The module also exports `importKey`, `ImportKeyOptions`, `privateKeyToDer`, `cloudPublicKey`, and `cloudSign` for direct use.

## Development

```sh
pnpm check
pnpm build
pnpm exec vitest run tests/wallet.test.ts
```

`pnpm check` runs TypeScript 6, ESLint, and Prettier.
The wallet tests run locally without Google Cloud credentials.

For the KMS comparison tests, copy `.env.example` to `.env`, fill in `VERSION_NAME` and its matching `PRIVATE_KEY`, then run:

```sh
pnpm exec vitest run tests/cloud.test.ts
```

`pnpm test` runs both suites; the KMS suite is skipped when either environment variable is missing.

## References

- [Importing a key into Cloud KMS](https://docs.cloud.google.com/kms/docs/importing-a-key#kms-create-key-for-import-nodejs)

## License

MIT
