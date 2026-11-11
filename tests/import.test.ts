import { generateKeyPairSync } from "node:crypto";
import { protos } from "@google-cloud/kms";
import { afterEach, beforeEach, describe, expect, it, vi } from "vitest";
import { importKey } from "@/import.js";

const kms = vi.hoisted(() => ({
  createImportJob: vi.fn(),
  getImportJob: vi.fn(),
  importCryptoKeyVersion: vi.fn(),
  getCryptoKeyVersion: vi.fn(),
}));

vi.mock("@google-cloud/kms", async (importOriginal) => ({
  ...(await importOriginal<typeof import("@google-cloud/kms")>()),
  KeyManagementServiceClient: class {
    locationPath = () => "projects/test/locations/global";
    keyRingPath = () => "projects/test/locations/global/keyRings/test";
    cryptoKeyPath = () => "projects/test/locations/global/keyRings/test/cryptoKeys/test";
    createKeyRing = vi.fn().mockResolvedValue([{}]);
    createCryptoKey = vi.fn().mockResolvedValue([{}]);
    createImportJob = kms.createImportJob;
    getImportJob = kms.getImportJob;
    importCryptoKeyVersion = kms.importCryptoKeyVersion;
    getCryptoKeyVersion = kms.getCryptoKeyVersion;
  },
}));

describe("importKey with a mocked KMS", () => {
  const { CryptoKeyVersionState } = protos.google.cloud.kms.v1.CryptoKeyVersion;
  const jobName = "projects/test/locations/global/keyRings/test/importJobs/test";
  const versionName = "projects/test/locations/global/keyRings/test/cryptoKeys/test/cryptoKeyVersions/1";
  const options = {
    projectId: "test",
    locationId: "global",
    keyRingId: "test",
    cryptoKeyId: "test",
    privateKeyHex: "0xac0974bec39a17e36ba4a6b4d238ff944bacb478cbed5efcae784d7bf4f2ff80",
  };
  const { publicKey } = generateKeyPairSync("rsa", { modulusLength: 2048 });
  const activeJob = {
    name: jobName,
    state: "ACTIVE",
    publicKey: { pem: publicKey.export({ type: "spki", format: "pem" }) },
  };

  beforeEach(() => {
    vi.resetAllMocks();
    vi.useFakeTimers();
    kms.createImportJob.mockResolvedValue([activeJob]);
    kms.importCryptoKeyVersion.mockResolvedValue([{ name: versionName, state: "PENDING_IMPORT" }]);
  });

  afterEach(() => {
    vi.useRealTimers();
  });

  it("waits for the wrapping key and the enabled version", async () => {
    kms.createImportJob.mockResolvedValue([{ name: jobName, state: "PENDING_GENERATION" }]);
    kms.getImportJob.mockResolvedValue([activeJob]);
    kms.getCryptoKeyVersion
      .mockResolvedValueOnce([{ name: versionName, state: CryptoKeyVersionState.PENDING_IMPORT }])
      .mockResolvedValueOnce([{ name: versionName, state: CryptoKeyVersionState.ENABLED }]);

    await Promise.all([expect(importKey(options)).resolves.toBe(versionName), vi.advanceTimersByTimeAsync(3000)]);
    expect(kms.getImportJob).toHaveBeenCalledOnce();
    expect(kms.getCryptoKeyVersion).toHaveBeenCalledTimes(2);
  });

  it("reports the import failure reason and the version name", async () => {
    kms.getCryptoKeyVersion.mockResolvedValue([
      { name: versionName, state: "IMPORT_FAILED", importFailureReason: "Invalid key material" },
    ]);

    await Promise.all([
      expect(importKey(options)).rejects.toThrow(`${versionName} ended in state IMPORT_FAILED: Invalid key material`),
      vi.advanceTimersByTimeAsync(1000),
    ]);
  });

  it("stops polling when the version stays pending", async () => {
    kms.getCryptoKeyVersion.mockResolvedValue([{ name: versionName, state: "PENDING_IMPORT" }]);

    await Promise.all([
      expect(importKey(options)).rejects.toThrow(`Timed out waiting for KMS resource ${versionName}`),
      vi.advanceTimersByTimeAsync(5 * 60 * 1000),
    ]);
  });

  it("stops when the import job expires", async () => {
    kms.createImportJob.mockResolvedValue([{ name: jobName, state: "EXPIRED" }]);

    await expect(importKey(options)).rejects.toThrow(`${jobName} ended in state EXPIRED`);
    expect(kms.importCryptoKeyVersion).not.toHaveBeenCalled();
  });
});
