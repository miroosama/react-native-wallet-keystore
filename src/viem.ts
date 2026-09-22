import {
  hashMessage,
  hashTypedData,
  keccak256,
  serializeTransaction,
  type Hex,
  type LocalAccount,
  type SerializeTransactionFn,
  type SignableMessage,
  type TransactionSerializable,
  type TypedData,
  type TypedDataDefinition,
} from 'viem';
import { publicKeyToAddress, toAccount } from 'viem/accounts';

import { getPublicKey, signDigest } from './keystore';

export type KeystoreAccountOptions = {
  /** Shown in the authentication prompt. One prompt per signature. */
  reason?: string;
  /**
   * Supply the public key if it is already known, to skip a native round-trip.
   * The address is derived from it, so it must belong to `keyId`.
   */
  publicKey?: Hex;
};

const DEFAULT_REASON = 'Sign with your wallet key';

/**
 * Adapts a hardware-wrapped key into a viem {@link LocalAccount}.
 *
 * Every signing path hashes in JS and sends only a 32-byte digest to native,
 * so EIP-191, EIP-712 and transaction serialization all stay in viem where
 * they are already correct and audited.
 *
 * ```ts
 * const account = await toKeystoreAccount('wallet-1');
 * const client = createWalletClient({ account, chain: mainnet, transport: http() });
 * await client.sendTransaction({ to: '0x…', value: 1n });
 * ```
 *
 * Note that each signature raises its own authentication prompt. That is the
 * point — the key is unusable without it — but it means batching several
 * signatures will prompt several times.
 */
export async function toKeystoreAccount(
  keyId: string,
  options: KeystoreAccountOptions = {}
): Promise<LocalAccount> {
  const reason = options.reason ?? DEFAULT_REASON;
  const publicKey = options.publicKey ?? (await getPublicKey(keyId));

  // Derived locally rather than returned by native: the address is a pure
  // function of the public key, and keccak has no business in the native layer.
  const address = publicKeyToAddress(publicKey);

  const sign = (digest: Hex) =>
    signDigest(keyId, digest, reason) as Promise<Hex>;

  return toAccount({
    address,
    // `toAccount` narrows on the shape it is given; the cast pins the result to
    // LocalAccount rather than the JsonRpcAccount branch of the union.

    async sign({ hash }: { hash: Hex }) {
      return sign(hash);
    },

    async signMessage({ message }: { message: SignableMessage }) {
      // EIP-191 prefixing happens here, not natively.
      return sign(hashMessage(message));
    },

    async signTypedData<
      const typedData extends TypedData | Record<string, unknown>,
      primaryType extends keyof typedData | 'EIP712Domain' = keyof typedData,
    >(typedData: TypedDataDefinition<typedData, primaryType>) {
      return sign(hashTypedData(typedData as TypedDataDefinition));
    },

    async signTransaction(
      transaction: TransactionSerializable,
      args?: {
        serializer?:
          SerializeTransactionFn<TransactionSerializable> | undefined;
      }
    ) {
      const serializer = args?.serializer ?? serializeTransaction;

      // Sign the hash of the *unsigned* serialization, then re-serialize with
      // the signature attached — the EIP-155 / typed-transaction rules live in
      // viem's serializer, which already handles every tx type.
      const unsigned = (await serializer(transaction)) as Hex;
      const signature = await sign(keccak256(unsigned));

      return (await serializer(transaction, {
        r: `0x${signature.slice(2, 66)}` as Hex,
        s: `0x${signature.slice(66, 130)}` as Hex,
        v: BigInt(parseInt(signature.slice(130, 132), 16)),
      })) as Hex;
    },
  }) as LocalAccount;
}
