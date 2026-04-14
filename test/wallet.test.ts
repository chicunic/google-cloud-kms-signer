import { describe, it, expect, beforeAll } from 'vitest';
import { Transaction, Wallet, ZeroAddress, parseEther, parseUnits, verifyMessage, verifyTypedData } from 'ethers';

describe('Ethers wallet signing (baseline)', () => {
  const privateKey = '0xac0974bec39a17e36ba4a6b4d238ff944bacb478cbed5efcae784d7bf4f2ff80';
  const address = '0xf39Fd6e51aad88F6F4ce6aB8827279cffFb92266';
  let wallet: Wallet;

  beforeAll(() => {
    wallet = new Wallet(privateKey);
  });

  it('creates wallet with correct address', () => {
    expect(wallet.address).toBe(address);
  });

  it('signs message and verifies', async () => {
    const message = 'message';
    const signed = await wallet.signMessage(message);
    const verified = verifyMessage(message, signed);
    expect(verified).toBe(address);
  });

  it('signs transaction deterministically', async () => {
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
    const signed = await wallet.signTransaction(transaction);
    const { hash: txid } = Transaction.from(signed);
    expect(txid).toBe('0xb11a068e2c6583c3392974e1230d5935c5e8bfb55b1d16984a3ae13aae1d1202');
  });

  it('signs typed data and verifies', async () => {
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
    const signed = await wallet.signTypedData(domain, types, value);
    const verified = verifyTypedData(domain, types, value, signed);
    expect(verified).toBe(address);
  });
});
