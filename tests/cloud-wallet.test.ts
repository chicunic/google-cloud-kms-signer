import { beforeEach, describe, expect, it, vi } from "vitest";
import { JsonRpcProvider, Transaction, Wallet, ZeroAddress, verifyAuthorization, verifyMessage } from "ethers";
import { CloudWallet } from "@/wallet.js";
import { cloudPublicKey, cloudSign } from "@/sign.js";

vi.mock("@/sign.js", () => ({ cloudPublicKey: vi.fn(), cloudSign: vi.fn() }));

describe("CloudWallet with a mocked KMS", () => {
  const versionName = "projects/test/locations/global/keyRings/test/cryptoKeys/test/cryptoKeyVersions/1";
  const key = Wallet.createRandom();
  const transaction = { to: ZeroAddress, chainId: 1, nonce: 0, gasLimit: 21000n, gasPrice: 1n, type: 0 };

  beforeEach(() => {
    vi.clearAllMocks();
    vi.mocked(cloudPublicKey).mockResolvedValue(key.signingKey.publicKey);
    vi.mocked(cloudSign).mockImplementation((_name, digest) => Promise.resolve(key.signingKey.sign(digest)));
  });

  it("connects to a provider and keeps signing with the same KMS version", async () => {
    const provider = new JsonRpcProvider();
    const wallet = new CloudWallet(versionName).connect(provider);

    expect(wallet).toBeInstanceOf(CloudWallet);
    expect(wallet.provider).toBe(provider);
    expect(wallet).not.toHaveProperty("signMessageSync");
    expect(verifyMessage("test", await wallet.signMessage("test"))).toBe(key.address);
    expect(cloudSign).toHaveBeenCalledWith(versionName, expect.any(Uint8Array), key.address);
  });

  it("signs EIP-7702 authorizations with KMS", async () => {
    const wallet = new CloudWallet(versionName);
    const authorization = await wallet.authorize({ address: ZeroAddress, chainId: 1, nonce: 0 });

    expect(verifyAuthorization(authorization, authorization.signature)).toBe(key.address);
  });

  it("validates from on the first transaction without changing the request", async () => {
    const wallet = new CloudWallet(versionName);
    const request = Object.freeze({ ...transaction, from: key.address });

    const signed = await wallet.signTransaction(request);

    expect(Transaction.from(signed).from).toBe(key.address);
    expect(request.from).toBe(key.address);
  });

  it("rejects a different sender before signing", async () => {
    const wallet = new CloudWallet(versionName);

    await expect(wallet.signTransaction({ ...transaction, from: ZeroAddress })).rejects.toThrow(
      "transaction from address mismatch",
    );
    expect(cloudSign).not.toHaveBeenCalled();
  });
});
