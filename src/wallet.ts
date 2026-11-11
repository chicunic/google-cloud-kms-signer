import {
  AbstractSigner,
  type Authorization,
  type AuthorizationRequest,
  type BytesLike,
  type Provider,
  type Signature,
  Transaction,
  type TransactionLike,
  type TransactionRequest,
  type TypedDataDomain,
  TypedDataEncoder,
  type TypedDataField,
  assert,
  assertArgument,
  computeAddress,
  copyRequest,
  dataLength,
  getAddress,
  getBigInt,
  getBytesCopy,
  hashAuthorization,
  hashMessage,
  resolveAddress,
  resolveProperties,
} from "ethers";
import { cloudPublicKey, cloudSign } from "./sign.js";

export class CloudWallet extends AbstractSigner {
  readonly versionName: string;
  #address = "";

  constructor(versionName: string, provider?: null | Provider) {
    super(provider);
    this.versionName = versionName;
  }

  get address(): string {
    return this.#address;
  }

  connect(provider: null | Provider): CloudWallet {
    const wallet = new CloudWallet(this.versionName, provider);
    wallet.#address = this.#address;
    return wallet;
  }

  async getAddress(): Promise<string> {
    if (!this.#address) {
      const publicKey = await cloudPublicKey(this.versionName);
      this.#address = computeAddress(publicKey);
    }
    return this.#address;
  }

  private async sign(digest: BytesLike): Promise<Signature> {
    assertArgument(dataLength(digest) === 32, "invalid digest length", "digest", digest);

    const ethereumAddress = await this.getAddress();
    return cloudSign(this.versionName, getBytesCopy(digest), ethereumAddress);
  }

  async signTransaction(request: TransactionRequest): Promise<string> {
    const tx = copyRequest(request);
    const { to, from } = await resolveProperties({
      to: tx.to ? resolveAddress(tx.to, this.provider) : undefined,
      from: tx.from ? resolveAddress(tx.from, this.provider) : undefined,
    });

    if (to != null) tx.to = to;
    if (from != null) {
      const address = await this.getAddress();
      assertArgument(getAddress(from) === address, "transaction from address mismatch", "tx.from", from);
      delete tx.from;
    }

    const transaction = Transaction.from(tx as TransactionLike);
    transaction.signature = await this.sign(transaction.unsignedHash);

    return transaction.serialized;
  }

  async signMessage(message: string | Uint8Array): Promise<string> {
    const signature = await this.sign(hashMessage(message));
    return signature.serialized;
  }

  async authorize(request: AuthorizationRequest): Promise<Authorization> {
    const address = getAddress(await resolveAddress(request.address, this.provider));
    const populated = await this.populateAuthorization({ ...request, address });
    const authorization = {
      address,
      chainId: getBigInt(populated.chainId ?? 0),
      nonce: getBigInt(populated.nonce ?? 0),
    };
    const signature = await this.sign(hashAuthorization(authorization));
    return { ...authorization, signature };
  }

  async signTypedData(
    domain: TypedDataDomain,
    types: Record<string, TypedDataField[]>,
    value: Record<string, unknown>,
  ): Promise<string> {
    const populated: { domain: TypedDataDomain; value: Record<string, unknown> } = await TypedDataEncoder.resolveNames(
      domain,
      types,
      value,
      async (name: string) => {
        assert(this.provider != null, "cannot resolve ENS names without a provider", "UNSUPPORTED_OPERATION", {
          operation: "resolveName",
          info: { name },
        });

        const address = await this.provider.resolveName(name);
        assert(address != null, "unconfigured ENS name", "UNCONFIGURED_NAME", { value: name });

        return address;
      },
    );

    const signature = await this.sign(TypedDataEncoder.hash(populated.domain, types, populated.value));
    return signature.serialized;
  }
}
