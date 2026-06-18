import { Crc32c } from "@aws-crypto/crc32c";
import { KeyManagementServiceClient } from "@google-cloud/kms";
import { ECDSASigValue } from "@peculiar/asn1-ecc";
import { AsnParser } from "@peculiar/asn1-schema";
import { createPublicKey } from "crypto";
import { Signature, recoverAddress, toBeHex } from "ethers";

// secp256k1 curve order; signatures with s > N/2 are normalized to the lower half (EIP-2).
const SECP256K1_N = BigInt("0xfffffffffffffffffffffffffffffffebaaedce6af48a03bbfd25e8cd0364141");

function uint8ArrayToBigInt(buf: Uint8Array): bigint {
  return BigInt("0x" + Buffer.from(buf).toString("hex"));
}

const client = new KeyManagementServiceClient();

export async function cloudSign(versionName: string, digest: Uint8Array, ethereumAddress: string): Promise<Signature> {
  const digestBuffer = Buffer.from(digest);
  const digestCrc32c = new Crc32c().update(digestBuffer).digest();
  const [signResponse] = await client.asymmetricSign({
    name: versionName,
    digest: { sha256: digestBuffer },
    digestCrc32c: { value: digestCrc32c },
  });

  if (signResponse.name !== versionName) {
    throw new Error(`KMS sign returned unexpected version name: ${signResponse.name ?? "null"}`);
  }
  if (!signResponse.verifiedDigestCrc32c) {
    throw new Error("KMS could not verify the request digest CRC32C");
  }
  const signature = signResponse.signature;
  if (!(signature instanceof Uint8Array)) {
    throw new Error("KMS sign response is missing the signature");
  }
  if (new Crc32c().update(signature).digest() !== Number(signResponse.signatureCrc32c?.value)) {
    throw new Error("KMS signature CRC32C mismatch (possible data corruption in transit)");
  }

  // Parse DER-encoded ECDSA signature
  const parsedSignature = AsnParser.parse(Buffer.from(signature), ECDSASigValue);
  const rBigInt = uint8ArrayToBigInt(new Uint8Array(parsedSignature.r));
  let sBigInt = uint8ArrayToBigInt(new Uint8Array(parsedSignature.s));
  if (sBigInt > SECP256K1_N / 2n) sBigInt = SECP256K1_N - sBigInt;

  // Recover the signature's recovery id (v) by trying both candidates against the known address.
  const r = toBeHex(rBigInt, 32);
  const s = toBeHex(sBigInt, 32);
  const target = ethereumAddress.toLowerCase();
  for (const v of [27, 28]) {
    if (recoverAddress(digestBuffer, { r, s, v }).toLowerCase() === target) {
      return Signature.from({ r, s, v });
    }
  }
  throw new Error(`KMS signature does not recover to the expected address ${ethereumAddress}`);
}

export async function cloudPublicKey(versionName: string): Promise<string> {
  const [publicKey] = await client.getPublicKey({ name: versionName });
  if (!publicKey.pem) throw new Error(`KMS key version not found or has no public key: ${versionName}`);
  const publicKeyBuffer = createPublicKey({ key: publicKey.pem, format: "pem" })
    .export({ type: "spki", format: "der" })
    .subarray(-64);
  return `0x${Buffer.from(publicKeyBuffer).toString("hex")}`;
}
