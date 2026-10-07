import {
  BaseWallet,
  type BytesLike,
  type Provider,
  type Signature,
  SigningKey,
  Transaction,
  type TransactionLike,
  type TransactionRequest,
  type TypedDataDomain,
  TypedDataEncoder,
  type TypedDataField,
  assert,
  assertArgument,
  computeAddress,
  dataLength,
  getAddress,
  getBytesCopy,
  hashMessage,
  resolveAddress,
  resolveProperties,
} from "ethers";
import { cloudPublicKey, cloudSign } from "./sign.js";

// Placeholder key satisfying BaseWallet's constructor; CloudWallet never signs with it locally.
const PLACEHOLDER_SIGNING_KEY = "0x0000000000000000000000000000000000000000000000000000000000000001";

export class CloudWallet extends BaseWallet {
  readonly versionName: string;
  readonly provider: null | Provider;
  public address: string;

  constructor(versionName: string, provider?: null | Provider) {
    super(new SigningKey(PLACEHOLDER_SIGNING_KEY), provider);
    this.versionName = versionName;
    this.provider = provider ?? null;
    this.address = "";
  }

  async getAddress(): Promise<string> {
    if (!this.address) {
      const publicKey = await cloudPublicKey(this.versionName);
      this.address = computeAddress(publicKey);
    }
    return this.address;
  }

  private async sign(digest: BytesLike): Promise<Signature> {
    assertArgument(dataLength(digest) === 32, "invalid digest length", "digest", digest);

    const ethereumAddress = await this.getAddress();
    return cloudSign(this.versionName, getBytesCopy(digest), ethereumAddress);
  }

  async signTransaction(tx: TransactionRequest): Promise<string> {
    const { to, from } = await resolveProperties({
      to: tx.to ? resolveAddress(tx.to, this.provider) : undefined,
      from: tx.from ? resolveAddress(tx.from, this.provider) : undefined,
    });

    if (to != null) tx.to = to;
    if (from != null) {
      assertArgument(getAddress(from) === this.address, "transaction from address mismatch", "tx.from", from);
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
