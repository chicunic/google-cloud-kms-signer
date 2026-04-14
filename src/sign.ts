import { Crc32c } from '@aws-crypto/crc32c';
import { KeyManagementServiceClient } from '@google-cloud/kms';
import { ECDSASigValue } from '@peculiar/asn1-ecc';
import { AsnParser } from '@peculiar/asn1-schema';
import { createPublicKey } from 'crypto';
import { Signature, recoverAddress, toBeHex } from 'ethers';

const uint8ArrayToBigInt = (buf: Uint8Array): bigint => BigInt('0x' + Buffer.from(buf).toString('hex'));

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
    throw new Error('sign failed');
  }
  if (!signResponse.verifiedDigestCrc32c) {
    throw new Error('sign failed');
  }
  if (
    new Crc32c().update(signResponse.signature as Uint8Array).digest() !== Number(signResponse.signatureCrc32c?.value)
  ) {
    throw new Error('sign failed');
  }

  // Parse DER-encoded ECDSA signature
  const parsedSignature = AsnParser.parse(signResponse.signature as Buffer, ECDSASigValue);
  const rBigInt = uint8ArrayToBigInt(new Uint8Array(parsedSignature.r));
  let sBigInt = uint8ArrayToBigInt(new Uint8Array(parsedSignature.s));
  const secp256k1N = BigInt('0xfffffffffffffffffffffffffffffffebaaedce6af48a03bbfd25e8cd0364141');
  if (sBigInt > secp256k1N / 2n) sBigInt = secp256k1N - sBigInt;

  // Recover v
  const r: string = toBeHex(rBigInt, 32);
  const s: string = toBeHex(sBigInt, 32);
  let v = 27;
  let recovered = recoverAddress(digestBuffer, { r, s, v });
  if (recovered.toLowerCase() !== ethereumAddress.toLowerCase()) {
    v = 28;
    recovered = recoverAddress(digestBuffer, { r, s, v });
  }
  if (recovered.toLowerCase() !== ethereumAddress.toLowerCase()) {
    throw new Error('sign failed');
  }
  return Signature.from({ r, s, v });
}

export async function cloudPublicKey(versionName: string): Promise<string> {
  const [publicKey] = await client.getPublicKey({ name: versionName });
  if (!publicKey || !publicKey.pem) throw new Error('can not find version name');
  const publicKeyBuffer = createPublicKey({ key: publicKey.pem, format: 'pem' })
    .export({ type: 'spki', format: 'der' })
    .subarray(-64);
  return `0x${Buffer.from(publicKeyBuffer).toString('hex')}`;
}
