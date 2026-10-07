import { createInterface } from "node:readline/promises";
import { KeyManagementServiceClient } from "@google-cloud/kms";
import chalk from "chalk";
import { Wallet, computeAddress } from "ethers";
import ora from "ora";
import { importKey } from "../src/import.js";
import { cloudPublicKey } from "../src/sign.js";

const rl = createInterface({ input: process.stdin, output: process.stdout });

async function prompt(question: string, defaultValue?: string): Promise<string> {
  const suffix = defaultValue ? chalk.dim(` [${defaultValue}]`) : "";
  const answer = (await rl.question(`${question}${suffix}: `)).trim();
  return answer || (defaultValue ?? "");
}

function step(n: number, total: number, message: string): void {
  console.log(chalk.cyan(`\n[${n}/${total}]`) + ` ${message}`);
}

async function main(): Promise<void> {
  console.log(chalk.bold("\n🔑 Google Cloud KMS Key Import\n"));

  const TOTAL_STEPS = 4;

  step(1, TOTAL_STEPS, "Select project and location");

  const client = new KeyManagementServiceClient();
  const projectId = await client.getProjectId();
  const confirm = await prompt(`GCP project: ${chalk.green(projectId)}. Continue? (Y/n)`);
  if (confirm && confirm.toLowerCase() !== "y") {
    console.log(chalk.yellow("Aborted. Run: gcloud config set project <PROJECT_ID>"));
    process.exit(0);
  }

  const spinner = ora("Fetching available locations...").start();
  const locations = new Set<string>();
  for await (const loc of client.listLocationsAsync({ name: `projects/${projectId}` })) {
    if (loc.locationId) locations.add(loc.locationId);
  }
  spinner.succeed(`Found ${locations.size} available locations.`);

  let locationId: string;
  for (;;) {
    locationId = await prompt("Location ID (e.g. us-central1, global, asia-east1)", "us-central1");
    if (locations.has(locationId)) break;
    console.error(
      chalk.red(`✗ Invalid location: ${locationId}.`) + " See: https://cloud.google.com/kms/docs/locations",
    );
  }

  step(2, TOTAL_STEPS, "Configure key");

  let keyRingId: string;
  while (!(keyRingId = await prompt("Key ring ID (e.g. eth-keyring)"))) {
    console.error(chalk.red("✗ Key ring ID is required."));
  }
  let cryptoKeyId: string;
  while (!(cryptoKeyId = await prompt("Crypto key ID (e.g. eth-key)"))) {
    console.error(chalk.red("✗ Crypto key ID is required."));
  }

  const cryptoKeyPath = `projects/${projectId}/locations/${locationId}/keyRings/${keyRingId}/cryptoKeys/${cryptoKeyId}`;
  console.log(`  Protection level: ${chalk.green("HSM")}`);
  console.log(`  Import target:    ${chalk.green(cryptoKeyPath)}`);

  step(3, TOTAL_STEPS, "Enter private key");

  let privateKeyHex: string;
  let localWallet: Wallet;
  for (;;) {
    privateKeyHex = await prompt("Private key (hex, e.g. 0xac09...ff80)");
    if (!privateKeyHex) {
      console.error(chalk.red("✗ Private key is required."));
      continue;
    }
    const hex = privateKeyHex.startsWith("0x") ? privateKeyHex.slice(2) : privateKeyHex;
    if (!/^[0-9a-fA-F]{64}$/.test(hex)) {
      console.error(chalk.red("✗ Invalid private key. Must be 32 bytes (64 hex characters)."));
      continue;
    }
    localWallet = new Wallet(privateKeyHex);
    break;
  }
  console.log(`  Local address: ${chalk.green(localWallet.address)}`);

  const confirmImport = await prompt("\nContinue? (Y/n)");
  if (confirmImport && confirmImport.toLowerCase() !== "y") {
    console.log(chalk.yellow("Aborted."));
    process.exit(0);
  }

  rl.close();

  step(4, TOTAL_STEPS, "Importing key to KMS");

  const importSpinner = ora("Creating key ring...").start();
  const versionName = await importKey({
    projectId,
    locationId,
    keyRingId,
    cryptoKeyId,
    privateKeyHex,
  });
  importSpinner.succeed(`Imported: ${chalk.green(versionName)}`);

  const verifySpinner = ora("Verifying KMS address...").start();
  const kmsPublicKey = await cloudPublicKey(versionName);
  const kmsAddress = computeAddress(kmsPublicKey);

  if (localWallet.address !== kmsAddress) {
    verifySpinner.fail(`KMS address: ${chalk.red(kmsAddress)} — address mismatch!`);
    process.exit(1);
  }
  verifySpinner.succeed(`KMS address: ${chalk.green(kmsAddress)} — addresses match!`);

  console.log(chalk.bold.green("\n✅ Import complete.\n"));
}

main().catch((err: unknown) => {
  console.error(chalk.red(err instanceof Error ? err.message : String(err)));
  process.exit(1);
});
