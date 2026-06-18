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

- Node.js >= 26
- pnpm
- Google Cloud project with KMS API enabled
- Authenticated via Application Default Credentials

## Import a Key

Run the interactive import script. It auto-detects the GCP project, validates the location and private key, and verifies the imported key address matches the local one.

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

## References

- [Importing a key into Cloud KMS](https://docs.cloud.google.com/kms/docs/importing-a-key#kms-create-key-for-import-nodejs)

## License

MIT
