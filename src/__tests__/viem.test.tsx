import { beforeEach, describe, expect, it, jest } from '@jest/globals';
import { privateKeyToAccount } from 'viem/accounts';
import { recoverAddress, type Hex } from 'viem';

import vectors from '../__fixtures__/secp256k1-vectors.json';

const mockGetPublicKey = jest.fn<(k: string) => Promise<string>>();
const mockSignDigest =
  jest.fn<(k: string, d: string, r: string) => Promise<string>>();

jest.mock('../NativeWalletKeystore', () => ({
  __esModule: true,
  default: {
    getPublicKey: (k: string) => mockGetPublicKey(k),
    signDigest: (k: string, d: string, r: string) => mockSignDigest(k, d, r),
  },
}));

import { toKeystoreAccount } from '../viem';

/**
 * Stands in for the native module by signing with viem itself.
 *
 * The point is not to test viem — it is to pin the exact bytes the native
 * layers must produce. These same vectors get asserted against real iOS and
 * Android output, which is what catches low-s errors, recovery-id errors, and
 * divergence between libsecp256k1 and BouncyCastle.
 */
const reference = privateKeyToAccount(vectors.privateKey as Hex);

beforeEach(() => {
  jest.clearAllMocks();
  mockGetPublicKey.mockResolvedValue(vectors.publicKey);
  mockSignDigest.mockImplementation(async (_k, digestHex) =>
    reference.sign({ hash: `0x${digestHex}` as Hex })
  );
});

describe('known-answer vectors', () => {
  it('has vectors that are all low-s', () => {
    // EIP-2 rejects s > n/2. If a vector itself were high-s the whole suite
    // would be asserting the wrong thing.
    const halfN = BigInt(vectors.halfCurveOrder);
    for (const vector of vectors.vectors) {
      expect(BigInt(vector.s) <= halfN).toBe(true);
    }
  });

  it('covers both recovery ids', () => {
    // A vector set that only exercises v=27 would miss a broken recid branch.
    const recoveryIds = new Set(vectors.vectors.map((v) => v.v));
    expect(recoveryIds.has(27)).toBe(true);
    expect(recoveryIds.has(28)).toBe(true);
  });

  it.each(vectors.vectors)(
    'signature for $digest recovers to the expected address',
    async (vector) => {
      const recovered = await recoverAddress({
        hash: vector.digest as Hex,
        signature: vector.signature as Hex,
      });
      expect(recovered).toBe(vectors.address);
    }
  );
});

describe('toKeystoreAccount', () => {
  it('derives the address from the public key without authenticating', async () => {
    const account = await toKeystoreAccount('wallet');

    expect(account.address).toBe(vectors.address);
    // Deriving an address must never cost the user a biometric prompt.
    expect(mockSignDigest).not.toHaveBeenCalled();
  });

  it('skips the native round-trip when the public key is supplied', async () => {
    const account = await toKeystoreAccount('wallet', {
      publicKey: vectors.publicKey as Hex,
    });

    expect(account.address).toBe(vectors.address);
    expect(mockGetPublicKey).not.toHaveBeenCalled();
  });

  it('signs a raw digest byte-for-byte identically to viem', async () => {
    const account = await toKeystoreAccount('wallet');
    const vector = vectors.vectors[0]!;

    const signature = await account.sign!({ hash: vector.digest as Hex });

    expect(signature).toBe(vector.signature);
  });

  it('hashes messages in JS and sends only a digest to native', async () => {
    const account = await toKeystoreAccount('wallet');

    const signature = await account.signMessage({ message: 'hello wallet' });

    expect(signature).toBe(vectors.messageVector.signature);
    // The native layer must never see the message — only its EIP-191 digest.
    const [, digestSent] = mockSignDigest.mock.calls[0]!;
    expect(`0x${digestSent}`).toBe(vectors.messageVector.hash);
  });

  it('produces a message signature that recovers to the account', async () => {
    const account = await toKeystoreAccount('wallet');

    const signature = await account.signMessage({ message: 'hello wallet' });
    const recovered = await recoverAddress({
      hash: vectors.messageVector.hash as Hex,
      signature,
    });

    expect(recovered).toBe(account.address);
  });

  it('passes the configured reason to every signature', async () => {
    const account = await toKeystoreAccount('wallet', {
      reason: 'Approve swap',
    });

    await account.signMessage({ message: 'x' });

    expect(mockSignDigest).toHaveBeenCalledWith(
      'wallet',
      expect.any(String),
      'Approve swap'
    );
  });

  it('signs typed data via its EIP-712 hash', async () => {
    const account = await toKeystoreAccount('wallet');

    const signature = await account.signTypedData({
      domain: { name: 'Test', version: '1', chainId: 1 },
      types: { Mail: [{ name: 'contents', type: 'string' }] },
      primaryType: 'Mail',
      message: { contents: 'hello' },
    });

    expect(signature).toMatch(/^0x[0-9a-f]{130}$/);
    expect(mockSignDigest).toHaveBeenCalledTimes(1);
  });
});
