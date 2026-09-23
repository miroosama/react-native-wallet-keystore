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
  /** Shown in the authentication prompt. */
  reason?: string;
  /** Skips a native round-trip. Must belong to `keyId`. */
  publicKey?: Hex;
};

const DEFAULT_REASON = 'Sign with your wallet key';

/**
 * Adapts a hardware-wrapped key into a viem {@link LocalAccount}.
 *
 * Every path hashes in JS and sends only a 32-byte digest to native, leaving
 * EIP-191, EIP-712 and transaction serialization to viem.
 *
 * ```ts
 * const account = await toKeystoreAccount('wallet-1');
 * const client = createWalletClient({ account, chain: mainnet, transport: http() });
 * await client.sendTransaction({ to: '0x…', value: 1n });
 * ```
 *
 * Each signature raises its own authentication prompt, so batching several will
 * prompt several times.
 */
export async function toKeystoreAccount(
  keyId: string,
  options: KeystoreAccountOptions = {}
): Promise<LocalAccount> {
  const reason = options.reason ?? DEFAULT_REASON;
  const publicKey = options.publicKey ?? (await getPublicKey(keyId));

  // Derived here rather than natively: the address is a pure function of the
  // public key, and keccak has no business in the native layer.
  const address = publicKeyToAddress(publicKey);

  const sign = (digest: Hex) =>
    signDigest(keyId, digest, reason) as Promise<Hex>;

  const account = toAccount({
    address,

    async sign({ hash }: { hash: Hex }) {
      return sign(hash);
    },

    async signMessage({ message }: { message: SignableMessage }) {
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

      // Sign the hash of the unsigned serialization, then re-serialize with the
      // signature attached; viem's serializer owns the EIP-155 and typed-tx
      // rules for every transaction type.
      const unsigned = (await serializer(transaction)) as Hex;
      const signature = await sign(keccak256(unsigned));

      return (await serializer(transaction, {
        r: `0x${signature.slice(2, 66)}` as Hex,
        s: `0x${signature.slice(66, 130)}` as Hex,
        v: BigInt(parseInt(signature.slice(130, 132), 16)),
      })) as Hex;
    },
  });

  // toAccount's return type is a union; this pins it to the local branch.
  return account as LocalAccount;
}
