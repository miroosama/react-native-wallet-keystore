import { privateKeyToAccount, privateKeyToAddress } from 'viem/accounts';
import { keccak256, toHex, recoverAddress, hashMessage } from 'viem';
import { secp256k1 } from '@noble/curves/secp256k1';

const KEY = '0x4c0883a69102937d6231471b5dbb6204fe512961708279e2d0f3d5f0f0f0a1b2';
const account = privateKeyToAccount(KEY);

// Fixed digests, not random — the whole point is reproducibility.
const digests = [
  keccak256(toHex('wallet-keystore-vector-1')),
  keccak256(toHex('wallet-keystore-vector-2')),
  '0x' + '00'.repeat(31) + '01',
  '0x' + 'ff'.repeat(32),
];

const N = secp256k1.CURVE.n;
const out = { privateKey: KEY, address: account.address, publicKey: account.publicKey, vectors: [] };

for (const digest of digests) {
  const sig = await account.sign({ hash: digest });
  const r = sig.slice(2, 66);
  const s = sig.slice(66, 130);
  const v = sig.slice(130, 132);
  const sBig = BigInt('0x' + s);
  out.vectors.push({
    digest,
    signature: sig,
    r: '0x' + r, s: '0x' + s, v: parseInt(v, 16),
    lowS: sBig <= N / 2n,
    recovered: await recoverAddress({ hash: digest, signature: sig }),
  });
}

out.curveOrder = '0x' + N.toString(16);
out.halfCurveOrder = '0x' + (N / 2n).toString(16);
out.messageVector = {
  message: 'hello wallet',
  hash: hashMessage('hello wallet'),
  signature: await account.signMessage({ message: 'hello wallet' }),
};
console.log(JSON.stringify(out, null, 2));
