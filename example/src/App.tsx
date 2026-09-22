import { useCallback, useEffect, useState } from 'react';
import {
  Pressable,
  ScrollView,
  StyleSheet,
  Text,
  View,
  type ColorValue,
} from 'react-native';
import {
  authenticate,
  deleteSecret,
  exportPrivateKey,
  generateKey,
  getBiometryType,
  getPublicKey,
  hasSecret,
  getSecret,
  importPrivateKey,
  signDigest,
  storeSecret,
  type AuthPolicy,
  type BiometryType,
  type InvalidationPolicy,
  type KeystoreError,
} from 'react-native-wallet-keystore';
import { toKeystoreAccount } from 'react-native-wallet-keystore/viem';
import { hashMessage, keccak256, recoverAddress, toHex } from 'viem';
import { privateKeyToAccount } from 'viem/accounts';

const KEY_ID = 'demo-wallet';

/** The same vector the Jest known-answer tests assert against. */
const KNOWN_KEY =
  '0x4c0883a69102937d6231471b5dbb6204fe512961708279e2d0f3d5f0f0f0a1b2';
const KNOWN_DIGEST = keccak256(toHex('wallet-keystore-vector-1'));

/** An arbitrary non-key secret, to show storage is not wallet-specific. */
const SECRET_ID = 'demo-secret';
const SECRET_HEX = '00112233445566778899aabbccddeeff';

type Outcome = {
  label: string;
  status: 'success' | 'error';
  code?: string;
  message: string;
  at: string;
};

const REMEDY: Record<string, string> = {
  NOT_ENROLLED: 'Send the user to Settings — retrying will not help.',
  USER_CANCELED: 'User declined. Safe to re-prompt.',
  LOCKOUT: 'Too many attempts. Retry after a cooldown.',
  LOCKOUT_PERMANENT: 'Locked until the device credential is used (Android).',
  KEY_NOT_FOUND: 'Nothing stored under this id. Generate or import first.',
  KEY_ALREADY_EXISTS: 'Delete before storing again — overwrites are explicit.',
  KEY_INVALIDATED: 'The key is gone. Unrecoverable; start recovery.',
  INVALID_KEY: 'Not a valid secp256k1 key or 32-byte digest.',
  STORAGE_ERROR: 'The keystore or keychain itself failed.',
};

export default function App() {
  const [biometry, setBiometry] = useState<BiometryType | null>(null);
  const [policy, setPolicy] = useState<AuthPolicy>('biometricOrPasscode');
  const [invalidation, setInvalidation] = useState<InvalidationPolicy>('never');
  const [busy, setBusy] = useState(false);
  const [outcomes, setOutcomes] = useState<Outcome[]>([]);

  useEffect(() => {
    getBiometryType()
      .then(setBiometry)
      .catch(() => setBiometry('none'));
  }, []);

  const run = useCallback(async (label: string, op: () => Promise<unknown>) => {
    setBusy(true);
    const at = new Date().toLocaleTimeString();
    try {
      const result = await op();
      setOutcomes((prev) => [
        {
          label,
          status: 'success',
          message: result === undefined ? 'OK' : String(result),
          at,
        },
        ...prev,
      ]);
    } catch (error) {
      const e = error as KeystoreError;
      setOutcomes((prev) => [
        { label, status: 'error', code: e.code, message: e.message, at },
        ...prev,
      ]);
    } finally {
      setBusy(false);
    }
  }, []);

  const groups: {
    title: string;
    note: string;
    actions: [string, () => Promise<unknown>][];
  }[] = [
    {
      title: '1 · Authentication',
      note: 'UX gate only. The boolean can be faked by a compromised bundle.',
      actions: [
        ['authenticate', () => authenticate('Unlock your wallet', policy)],
      ],
    },
    {
      title: '2 · Create a key',
      note: 'Pick ONE. Import uses a fixed key so signatures are checkable.',
      actions: [
        [
          'generateKey (random)',
          async () => {
            const publicKey = await generateKey(KEY_ID, {
              policy,
              invalidation,
            });
            return `${publicKey.slice(0, 16)}… (${(publicKey.length - 2) / 2}B)`;
          },
        ],
        [
          'importPrivateKey (known)',
          async () => {
            const publicKey = await importPrivateKey(KEY_ID, KNOWN_KEY, {
              policy,
              invalidation,
            });
            const expected =
              privateKeyToAccount(KNOWN_KEY).publicKey.toLowerCase();
            return publicKey.toLowerCase() === expected
              ? 'public key matches viem'
              : 'MISMATCH vs viem';
          },
        ],
      ],
    },
    {
      title: '3 · Read public data (never prompts)',
      note: 'A public key is not secret, so these must not authenticate.',
      actions: [
        [
          'getPublicKey',
          async () => (await getPublicKey(KEY_ID)).slice(0, 22) + '…',
        ],
        [
          'address (via viem)',
          async () => (await toKeystoreAccount(KEY_ID)).address,
        ],
        ['hasSecret', () => hasSecret(KEY_ID)],
      ],
    },
    {
      title: '4 · Sign (prompts every time)',
      note: 'Needs the known key from step 2 for the KAT to be meaningful.',
      actions: [
        [
          'signDigest (known-answer)',
          async () => {
            const signature = await signDigest(
              KEY_ID,
              KNOWN_DIGEST,
              'Sign digest'
            );
            const expected = await privateKeyToAccount(KNOWN_KEY).sign({
              hash: KNOWN_DIGEST,
            });
            return signature.toLowerCase() === expected.toLowerCase()
              ? 'KAT PASS — matches viem exactly'
              : `KAT FAIL\nnative:   ${signature}\nexpected: ${expected}`;
          },
        ],
        [
          'signMessage (viem account)',
          async () => {
            const account = await toKeystoreAccount(KEY_ID);
            const signature = await account.signMessage({
              message: 'hello wallet',
            });
            const recovered = await recoverAddress({
              hash: hashMessage('hello wallet'),
              signature,
            });
            return recovered === account.address
              ? `recovers to ${recovered.slice(0, 12)}…`
              : 'RECOVERY MISMATCH';
          },
        ],
      ],
    },
    {
      title: '5 · Arbitrary secrets (not wallet-specific)',
      note: 'Same wrapping path, any bytes. Separate id from the wallet key.',
      actions: [
        [
          'storeSecret',
          () => storeSecret(SECRET_ID, SECRET_HEX, { policy, invalidation }),
        ],
        [
          'getSecret',
          async () => {
            const hex = await getSecret(SECRET_ID, 'Read your secret');
            return hex === SECRET_HEX ? 'round-trip OK' : `MISMATCH: ${hex}`;
          },
        ],
      ],
    },
    {
      title: '6 · Backup and teardown',
      note: 'Export surfaces the key to JS — user-initiated backup only.',
      actions: [
        [
          'exportPrivateKey',
          async () => {
            const hex = await exportPrivateKey(KEY_ID, 'Export for backup');
            return hex.toLowerCase() === KNOWN_KEY.toLowerCase()
              ? 'matches the imported key'
              : `${hex.slice(0, 14)}… (generated key)`;
          },
        ],
        ['deleteSecret (wallet key)', () => deleteSecret(KEY_ID)],
        ['deleteSecret (demo secret)', () => deleteSecret(SECRET_ID)],
      ],
    },
  ];

  return (
    <View style={styles.container}>
      <View style={styles.header}>
        <Text style={styles.title}>Wallet Keystore</Text>
        <Text style={styles.subtitle}>
          Biometry: <Text style={styles.mono}>{biometry ?? 'checking…'}</Text>
        </Text>
      </View>

      <View style={styles.segments}>
        <Segment
          options={['biometricOrPasscode', 'biometricOnly', 'none']}
          value={policy}
          onChange={(v) => setPolicy(v as AuthPolicy)}
        />
        <Segment
          options={['never', 'onEnrollmentChange']}
          value={invalidation}
          onChange={(v) => setInvalidation(v as InvalidationPolicy)}
        />
      </View>

      <ScrollView
        style={styles.body}
        contentContainerStyle={styles.bodyContent}
      >
        {groups.map((group) => (
          <View key={group.title} style={styles.group}>
            <Text style={styles.groupTitle}>{group.title}</Text>
            <Text style={styles.groupNote}>{group.note}</Text>
            {group.actions.map(([label, op]) => (
              <Pressable
                key={label}
                style={({ pressed }) => [
                  styles.button,
                  pressed && styles.buttonPressed,
                  busy && styles.buttonDisabled,
                ]}
                disabled={busy}
                onPress={() => run(label, op)}
              >
                <Text style={styles.buttonText}>{label}</Text>
              </Pressable>
            ))}
          </View>
        ))}

        {outcomes.length === 0 ? (
          <Text style={styles.empty}>
            Import the known key, then run the known-answer signature. It must
            match viem byte-for-byte on both platforms.
          </Text>
        ) : (
          outcomes.map((outcome, index) => (
            <Row key={`${outcome.at}-${index}`} outcome={outcome} />
          ))
        )}
      </ScrollView>
    </View>
  );
}

function Segment({
  options,
  value,
  onChange,
}: {
  options: string[];
  value: string;
  onChange: (v: string) => void;
}) {
  return (
    <View style={styles.segment}>
      {options.map((option) => (
        <Pressable
          key={option}
          onPress={() => onChange(option)}
          style={[
            styles.segmentItem,
            value === option && styles.segmentItemActive,
          ]}
        >
          <Text
            style={[
              styles.segmentText,
              value === option && styles.segmentTextActive,
            ]}
            numberOfLines={1}
          >
            {option}
          </Text>
        </Pressable>
      ))}
    </View>
  );
}

function Row({ outcome }: { outcome: Outcome }) {
  const accent: ColorValue =
    outcome.status === 'success' ? '#1a7f37' : '#b3261e';

  return (
    <View style={[styles.row, { borderLeftColor: accent }]}>
      <View style={styles.rowHead}>
        <Text style={[styles.code, { color: accent }]}>
          {outcome.code ?? 'SUCCESS'}
        </Text>
        <Text style={styles.time}>{outcome.at}</Text>
      </View>
      <Text style={styles.policy}>{outcome.label}</Text>
      <Text style={styles.message}>{outcome.message}</Text>
      {outcome.code != null && REMEDY[outcome.code] != null ? (
        <Text style={styles.remedy}>{REMEDY[outcome.code]}</Text>
      ) : null}
    </View>
  );
}

const styles = StyleSheet.create({
  container: { flex: 1, backgroundColor: '#fbfbfa', paddingTop: 60 },
  header: { paddingHorizontal: 20, paddingBottom: 10 },
  title: { fontSize: 23, fontWeight: '700', color: '#141413' },
  subtitle: { fontSize: 13, color: '#5e5d59', marginTop: 3 },
  mono: { fontFamily: 'Menlo', color: '#141413' },
  segments: { paddingHorizontal: 20, gap: 7, paddingBottom: 10 },
  segment: {
    flexDirection: 'row',
    backgroundColor: '#eeece6',
    borderRadius: 8,
    padding: 3,
    gap: 3,
  },
  segmentItem: {
    flex: 1,
    paddingVertical: 6,
    borderRadius: 6,
    alignItems: 'center',
  },
  segmentItemActive: { backgroundColor: '#fff' },
  segmentText: { fontSize: 10, color: '#5e5d59' },
  segmentTextActive: { color: '#141413', fontWeight: '600' },
  body: { flex: 1 },
  bodyContent: { paddingHorizontal: 20, paddingBottom: 40, gap: 9 },
  group: { gap: 6, paddingTop: 10 },
  groupTitle: { fontSize: 12, fontWeight: '700', color: '#141413' },
  groupNote: {
    fontSize: 11,
    color: '#8a8984',
    lineHeight: 15,
    marginBottom: 2,
  },
  button: {
    backgroundColor: '#141413',
    paddingVertical: 10,
    borderRadius: 8,
    alignItems: 'center',
  },
  buttonPressed: { opacity: 0.7 },
  buttonDisabled: { opacity: 0.4 },
  buttonText: { color: '#fff', fontSize: 13, fontWeight: '600' },
  empty: { color: '#8a8984', fontSize: 13, lineHeight: 19 },
  row: {
    backgroundColor: '#fff',
    borderRadius: 8,
    borderLeftWidth: 3,
    padding: 11,
    borderWidth: StyleSheet.hairlineWidth,
    borderColor: '#e6e4df',
  },
  rowHead: { flexDirection: 'row', justifyContent: 'space-between' },
  code: { fontSize: 12, fontWeight: '700', fontFamily: 'Menlo' },
  time: { fontSize: 11, color: '#8a8984' },
  policy: { fontSize: 11, color: '#5e5d59', marginTop: 3 },
  message: {
    fontSize: 12,
    color: '#141413',
    marginTop: 5,
    fontFamily: 'Menlo',
  },
  remedy: { fontSize: 11, color: '#5e5d59', marginTop: 5, lineHeight: 16 },
});
