import { KeyManagementServiceClient, protos } from "@google-cloud/kms";
import { constants, createCipheriv, createECDH, createPublicKey, publicEncrypt, randomBytes } from "node:crypto";

const { ImportJobState } = protos.google.cloud.kms.v1.ImportJob;
const { CryptoKeyVersionState } = protos.google.cloud.kms.v1.CryptoKeyVersion;
const POLL_INTERVAL_MS = 1000;
const POLL_TIMEOUT_MS = 5 * 60 * 1000;

async function waitForPoll(deadline: number, name: string): Promise<number> {
  const delay = Math.max(0, Math.min(POLL_INTERVAL_MS, deadline - performance.now()));
  await new Promise<void>((resolve) => setTimeout(resolve, delay));
  const timeout = Math.floor(deadline - performance.now());
  if (timeout <= 0) throw new Error(`Timed out waiting for KMS resource ${name}`);
  return timeout;
}

/** Convert a hex Ethereum private key to PKCS#8 DER for KMS import. */
export function privateKeyToDer(privateKeyHex: string): Buffer {
  const hex = privateKeyHex.startsWith("0x") ? privateKeyHex.slice(2) : privateKeyHex;
  const privateKey = Buffer.from(hex, "hex");
  const ecdh = createECDH("secp256k1");
  ecdh.setPrivateKey(privateKey);
  const publicKey = ecdh.getPublicKey();

  // SEC 1 ECPrivateKey; the curve OID is supplied by the PKCS#8 wrapper.
  const ecPrivateKeyBody = Buffer.concat([
    Buffer.from([0x02, 0x01, 0x01]), // version 1
    Buffer.from([0x04, 0x20, ...privateKey]), // private key octet string
    Buffer.from([0xa1, 0x44, 0x03, 0x42, 0x00, ...publicKey]), // [1] public key bit string
  ]);
  const ecPrivateKeySeq = Buffer.concat([Buffer.from([0x30, ecPrivateKeyBody.length]), ecPrivateKeyBody]);

  // PKCS#8 AlgorithmIdentifier: id-ecPublicKey (1.2.840.10045.2.1) and secp256k1 (1.3.132.0.10).
  const algorithmIdentifier = Buffer.from("301006072a8648ce3d020106052b8104000a", "hex");
  const privateKeyOctetString = Buffer.concat([
    Buffer.from([0x04, ...derLength(ecPrivateKeySeq.length)]),
    ecPrivateKeySeq,
  ]);
  const pkcs8Version = Buffer.from([0x02, 0x01, 0x00]);
  const pkcs8Body = Buffer.concat([pkcs8Version, algorithmIdentifier, privateKeyOctetString]);
  return Buffer.concat([Buffer.from([0x30, ...derLength(pkcs8Body.length)]), pkcs8Body]);
}

function derLength(length: number): number[] {
  if (length < 0x80) return [length];
  if (length < 0x100) return [0x81, length];
  return [0x82, (length >> 8) & 0xff, length & 0xff];
}

/** Wrap PKCS#8 DER with AES-256-KWP (RFC 5649) and RSA-OAEP-SHA256 for HSM import. */
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

function ignoreAlreadyExists(error: unknown): void {
  if (error instanceof Error && "code" in error && error.code === 6) return; // gRPC ALREADY_EXISTS
  throw error;
}

/** Import an Ethereum private key into Cloud KMS and return its full version resource name once enabled. */
export async function importKey(options: ImportKeyOptions): Promise<string> {
  const { projectId, locationId, keyRingId, cryptoKeyId, privateKeyHex } = options;
  const client = new KeyManagementServiceClient();

  const locationPath = client.locationPath(projectId, locationId);
  const keyRingPath = client.keyRingPath(projectId, locationId, keyRingId);
  const cryptoKeyPath = client.cryptoKeyPath(projectId, locationId, keyRingId, cryptoKeyId);

  try {
    await client.createKeyRing({ parent: locationPath, keyRingId, keyRing: {} });
  } catch (error: unknown) {
    ignoreAlreadyExists(error);
  }

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
  } catch (error: unknown) {
    ignoreAlreadyExists(error);
  }

  const importJobId = `import-${Date.now()}`;
  const [importJob] = await client.createImportJob({
    parent: keyRingPath,
    importJobId,
    importJob: {
      importMethod: "RSA_OAEP_4096_SHA256_AES_256",
      protectionLevel: "HSM",
    },
  });

  // KMS generates the wrapping key asynchronously; wait before wrapping the private key.
  const importJobName = importJob.name;
  if (!importJobName) throw new Error("Import job was created without a name");
  const jobDeadline = performance.now() + POLL_TIMEOUT_MS;
  let job = importJob;
  while (job.state === "PENDING_GENERATION" || job.state === ImportJobState.PENDING_GENERATION) {
    const timeout = await waitForPoll(jobDeadline, importJobName);
    [job] = await client.getImportJob({ name: importJobName }, { timeout });
  }
  if (job.state !== "ACTIVE" && job.state !== ImportJobState.ACTIVE) {
    const state = typeof job.state === "number" ? ImportJobState[job.state] : job.state;
    throw new Error(`KMS import job ${importJobName} ended in state ${state ?? "unknown"}`);
  }

  const wrappingKeyPem = job.publicKey?.pem;
  if (!wrappingKeyPem) throw new Error("Import job is active but exposes no wrapping public key");
  const keyDer = privateKeyToDer(privateKeyHex);
  const wrappedKey = wrapKeyRsaAes(keyDer, wrappingKeyPem);

  let [version] = await client.importCryptoKeyVersion({
    parent: cryptoKeyPath,
    algorithm: "EC_SIGN_SECP256K1_SHA256",
    importJob: importJobName,
    wrappedKey,
  });

  const versionName = version.name;
  if (!versionName) throw new Error("Imported key version was created without a name");
  const versionDeadline = performance.now() + POLL_TIMEOUT_MS;
  while (version.state === "PENDING_IMPORT" || version.state === CryptoKeyVersionState.PENDING_IMPORT) {
    const timeout = await waitForPoll(versionDeadline, versionName);
    [version] = await client.getCryptoKeyVersion({ name: versionName }, { timeout });
  }
  if (version.state !== "ENABLED" && version.state !== CryptoKeyVersionState.ENABLED) {
    const state = typeof version.state === "number" ? CryptoKeyVersionState[version.state] : version.state;
    const reason = version.importFailureReason ? `: ${version.importFailureReason}` : "";
    throw new Error(`KMS key version ${versionName} ended in state ${state ?? "unknown"}${reason}`);
  }
  return versionName;
}
