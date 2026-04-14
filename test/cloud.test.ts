import { config } from 'dotenv';
import { describe, it, expect, beforeAll } from 'vitest';
import { Transaction, Wallet, ZeroAddress, parseEther, parseUnits, verifyMessage, verifyTypedData } from 'ethers';
import { CloudWallet } from '@/wallet.js';

config();

const hasEnv = process.env.VERSION_NAME && process.env.PRIVATE_KEY;

describe.skipIf(!hasEnv)('Cloud KMS signing vs local signing', () => {
  let cloudWallet: CloudWallet;
  let localWallet: Wallet;
  let address: string;

  beforeAll(async () => {
    cloudWallet = new CloudWallet(process.env.VERSION_NAME as string);
    localWallet = new Wallet(process.env.PRIVATE_KEY as string);
    address = await cloudWallet.getAddress();
  });

  it('derives the same address', () => {
    expect(address).toBe(localWallet.address);
  });

  it('signMessage verifies', async () => {
    const message = 'message';
    const cloudSigned = await cloudWallet.signMessage(message);
    expect(verifyMessage(message, cloudSigned)).toBe(address);
  });

  it('signTransaction verifies', async () => {
    const transaction = {
      to: address,
      nonce: 0,
      gasLimit: 21000,
      value: parseEther('0.1'),
      chainId: 1,
      type: 2,
      maxPriorityFeePerGas: parseUnits('1.5', 'gwei'),
      maxFeePerGas: parseUnits('51.5', 'gwei'),
    };
    const cloudSigned = await cloudWallet.signTransaction(transaction);
    expect(Transaction.from(cloudSigned).from).toBe(address);
  });

  it('signTypedData verifies', async () => {
    const domain = {
      name: 'name',
      version: '1.0.0',
      chainId: 1,
      verifyingContract: ZeroAddress,
    };
    const types = {
      Collection: [{ name: 'tokenId', type: 'uint256' }],
    };
    const value = { tokenId: 1 };
    const cloudSigned = await cloudWallet.signTypedData(domain, types, value);
    expect(verifyTypedData(domain, types, value, cloudSigned)).toBe(address);
  });
});
