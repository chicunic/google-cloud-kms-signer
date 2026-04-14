# google-cloud-kms-signer

Import Ethereum private keys into Google Cloud KMS and sign transactions with them.

## Features

- Import existing Ethereum private keys (secp256k1) into Google Cloud KMS (HSM-backed)
- `CloudWallet` — an ethers.js `BaseWallet` implementation backed by KMS
- Sign messages, typed data (EIP-712), and transactions via KMS
- CRC32C integrity verification on all KMS sign requests
- Low-s normalization and v recovery for Ethereum-compatible ECDSA signatures
- Interactive import script with colored output and progress indicators

## Prerequisites

- Node.js >= 24
- pnpm
- Google Cloud project with KMS API enabled
- Authenticated via `gcloud auth application-default login`

## Install

```bash
pnpm install
```

## Import a Key

The interactive import script will auto-detect the GCP project and verify the imported key address:

```bash
pnpm tsx scripts/import.ts
```

Required IAM permissions:

| Permission                          | Purpose             |
| ----------------------------------- | ------------------- |
| `cloudkms.keyRings.create`          | Create key ring     |
| `cloudkms.cryptoKeys.create`        | Create crypto key   |
| `cloudkms.importJobs.create`        | Create import job   |
| `cloudkms.cryptoKeyVersions.create` | Import key version  |
| `cloudkms.cryptoKeys.getPublicKey`  | Verify imported key |

## API

### `CloudWallet`

| Method                                | Description                                         |
| ------------------------------------- | --------------------------------------------------- |
| `constructor(versionName, provider?)` | Create a wallet backed by a KMS key version         |
| `getAddress()`                        | Derive the Ethereum address from the KMS public key |
| `signMessage(message)`                | Sign an EIP-191 personal message                    |
| `signTransaction(tx)`                 | Sign a transaction                                  |
| `signTypedData(domain, types, value)` | Sign EIP-712 typed data                             |

### `importKey(options)`

Import a private key into KMS (HSM protection level). Creates the key ring, crypto key, and import job automatically. Key material is wrapped using CKM_RSA_AES_KEY_WRAP (AES-256-KWP + RSA-OAEP SHA-256).

### `cloudSign(versionName, digest, ethereumAddress)`

Sign a 32-byte digest using KMS with CRC32C integrity verification.

### `cloudPublicKey(versionName)`

Retrieve the uncompressed public key from KMS.

### `privateKeyToDer(privateKeyHex)`

Convert an Ethereum private key (hex) to PKCS#8 DER format for KMS import.

## Test

```bash
pnpm test
```

Integration tests require a `.env` file with `VERSION_NAME` and `PRIVATE_KEY` (see `.env.example`). If not set, integration tests are automatically skipped.

## References

- [Importing a key into Cloud KMS](https://docs.cloud.google.com/kms/docs/importing-a-key#kms-create-key-for-import-nodejs)

## License

MIT
