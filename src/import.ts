import { KeyManagementServiceClient } from "@google-cloud/kms";
import { constants, createCipheriv, createECDH, createPublicKey, publicEncrypt, randomBytes } from "crypto";

/**
 * Convert an Ethereum private key (hex) to PKCS#8 DER format for KMS import.
 */
export function privateKeyToDer(privateKeyHex: string): Buffer {
  const hex = privateKeyHex.startsWith("0x") ? privateKeyHex.slice(2) : privateKeyHex;
  const ecdh = createECDH("secp256k1");
  ecdh.setPrivateKey(Buffer.from(hex, "hex"));
  const publicKey = ecdh.getPublicKey();

  // ASN.1 ECPrivateKey (SEC 1) — curve OID omitted since it's in PKCS#8 AlgorithmIdentifier
  const privateKeyBuf = Buffer.from(hex, "hex");
  const ecPrivateKeyBody = Buffer.concat([
    Buffer.from([0x02, 0x01, 0x01]), // version 1
    Buffer.from([0x04, 0x20, ...privateKeyBuf]), // private key octet string
    Buffer.from([0xa1, 0x44, 0x03, 0x42, 0x00, ...publicKey]), // [1] public key bit string
  ]);
  const ecPrivateKeySeq = Buffer.concat([Buffer.from([0x30, ecPrivateKeyBody.length]), ecPrivateKeyBody]);

  // Wrap in PKCS#8 PrivateKeyInfo
  const algorithmIdentifier = Buffer.from([
    0x30,
    0x10,
    0x06,
    0x07,
    0x2a,
    0x86,
    0x48,
    0xce,
    0x3d,
    0x02,
    0x01, // OID 1.2.840.10045.2.1 (EC)
    0x06,
    0x05,
    0x2b,
    0x81,
    0x04,
    0x00,
    0x0a, // OID 1.3.132.0.10 (secp256k1)
  ]);
  const privateKeyOctetString = Buffer.concat([
    Buffer.from([0x04, ...derLength(ecPrivateKeySeq.length)]),
    ecPrivateKeySeq,
  ]);
  const pkcs8Version = Buffer.from([0x02, 0x01, 0x00]);
  const pkcs8Body = Buffer.concat([pkcs8Version, algorithmIdentifier, privateKeyOctetString]);
  const pkcs8 = Buffer.concat([Buffer.from([0x30, ...derLength(pkcs8Body.length)]), pkcs8Body]);

  return pkcs8;
}

function derLength(length: number): number[] {
  if (length < 0x80) return [length];
  if (length < 0x100) return [0x81, length];
  return [0x82, (length >> 8) & 0xff, length & 0xff];
}

/**
 * Wrap PKCS#8 DER key material with CKM_RSA_AES_KEY_WRAP (HSM import).
 * Uses AES-256-KWP (RFC 5649) for the target key, then RSA-OAEP for the AES key.
 */
function wrapKeyRsaAes(keyDer: Buffer, wrappingKeyPem: string): Buffer {
  const aesKey = randomBytes(32);
  const iv = Buffer.from("A65959A6", "hex");
  const cipher = createCipheriv("aes256-wrap-pad", aesKey, iv);
  const wrappedTargetKey = Buffer.concat([cipher.update(keyDer), cipher.final()]);

  const wrappingKey = createPublicKey({ key: wrappingKeyPem, format: "pem" });
  const wrappedAesKey = publicEncrypt(
    {
      key: wrappingKey,
      padding: constants.RSA_PKCS1_OAEP_PADDING,
      oaepHash: "sha256",
    },
    aesKey,
  );

  return Buffer.concat([wrappedAesKey, wrappedTargetKey]);
}

export interface ImportKeyOptions {
  projectId: string;
  locationId: string;
  keyRingId: string;
  cryptoKeyId: string;
  privateKeyHex: string;
}

/**
 * Import an Ethereum private key into Google Cloud KMS.
 * Returns the full versionName of the imported key.
 */
export async function importKey(options: ImportKeyOptions): Promise<string> {
  const { projectId, locationId, keyRingId, cryptoKeyId, privateKeyHex } = options;
  const client = new KeyManagementServiceClient();

  const locationPath = client.locationPath(projectId, locationId);
  const keyRingPath = client.keyRingPath(projectId, locationId, keyRingId);
  const cryptoKeyPath = client.cryptoKeyPath(projectId, locationId, keyRingId, cryptoKeyId);

  // 1. Create key ring (ignore if already exists)
  try {
    await client.createKeyRing({ parent: locationPath, keyRingId, keyRing: {} });
  } catch (e: unknown) {
    if (!(e instanceof Error && "code" in e && e.code === 6)) throw e; // 6 = ALREADY_EXISTS
  }

  // 2. Create crypto key
  try {
    await client.createCryptoKey({
      parent: keyRingPath,
      cryptoKeyId,
      cryptoKey: {
        purpose: "ASYMMETRIC_SIGN",
        versionTemplate: {
          algorithm: "EC_SIGN_SECP256K1_SHA256",
          protectionLevel: "HSM",
        },
        importOnly: true,
      },
      skipInitialVersionCreation: true,
    });
  } catch (e: unknown) {
    if (!(e instanceof Error && "code" in e && e.code === 6)) throw e;
  }

  // 3. Create import job
  const importJobId = `import-${Date.now()}`;
  const [importJob] = await client.createImportJob({
    parent: keyRingPath,
    importJobId,
    importJob: {
      importMethod: "RSA_OAEP_4096_SHA256_AES_256",
      protectionLevel: "HSM",
    },
  });

  // 4. Wait for import job to be active
  const importJobName = importJob.name;
  if (!importJobName) throw new Error("Import job was created without a name");
  let job = importJob;
  while (job.state !== "ACTIVE") {
    await new Promise((resolve) => setTimeout(resolve, 1000));
    const [refreshed] = await client.getImportJob({ name: importJobName });
    job = refreshed;
  }

  // 5. Wrap key material
  const wrappingKeyPem = job.publicKey?.pem;
  if (!wrappingKeyPem) throw new Error("Import job is active but exposes no wrapping public key");
  const keyDer = privateKeyToDer(privateKeyHex);
  const wrappedKey = wrapKeyRsaAes(keyDer, wrappingKeyPem);

  // 6. Import crypto key version
  const [version] = await client.importCryptoKeyVersion({
    parent: cryptoKeyPath,
    algorithm: "EC_SIGN_SECP256K1_SHA256",
    importJob: importJobName,
    wrappedKey,
  });

  if (!version.name) throw new Error("Imported key version was created without a name");
  return version.name;
}
