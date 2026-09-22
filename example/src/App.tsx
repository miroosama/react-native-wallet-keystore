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
  getBiometryType,
  getSecret,
  hasSecret,
  storeSecret,
  KeystoreError,
  type AuthPolicy,
  type BiometryType,
  type InvalidationPolicy,
} from 'react-native-wallet-keystore';

const KEY_ID = 'demo-wallet';

/** Stand-in for a private key: 32 bytes, the size of a secp256k1 scalar. */
const SECRET_HEX =
  '4c0883a69102937d6231471b5dbb6204fe512961708279e2d0f3d5f0f0f0a1b2';

type Outcome = {
  label: string;
  status: 'success' | 'error';
  code?: string;
  message: string;
  at: string;
};

const REMEDY: Record<string, string> = {
  NOT_AVAILABLE: 'No biometric hardware, or it is currently unavailable.',
  NOT_ENROLLED: 'Send the user to Settings to enroll — retrying will not help.',
  USER_CANCELED: 'User declined. Safe to offer the prompt again.',
  USER_FALLBACK: 'User chose the fallback. Offer a passcode path.',
  LOCKOUT: 'Too many attempts. Temporary — retry after a cooldown.',
  LOCKOUT_PERMANENT: 'Locked until the device credential is used (Android).',
  SYSTEM_CANCEL: 'The OS dismissed the prompt. Not user intent.',
  KEY_NOT_FOUND: 'Nothing stored under this id. Store one first.',
  KEY_ALREADY_EXISTS: 'Delete before storing again — overwrites are explicit.',
  KEY_INVALIDATED:
    'The wrapping key is gone. The secret is unrecoverable; start recovery.',
  STORAGE_ERROR: 'The keystore or keychain itself failed.',
  UNKNOWN: 'Unrecognized failure. Check `nativeCode` for the raw value.',
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

  const run = useCallback(
    async (label: string, op: () => Promise<string | void | boolean>) => {
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
    },
    []
  );

  const actions: [string, () => Promise<string | void | boolean>][] = [
    ['authenticate', () => authenticate('Unlock your wallet', policy)],
    [
      'storeSecret',
      () => storeSecret(KEY_ID, SECRET_HEX, { policy, invalidation }),
    ],
    [
      'getSecret',
      async () => {
        const hex = await getSecret(KEY_ID, 'Unlock your wallet key');
        // Confirms the round-trip rather than just that something came back.
        return hex === SECRET_HEX
          ? `round-trip OK (${hex.length / 2}B)`
          : 'MISMATCH';
      },
    ],
    ['hasSecret', () => hasSecret(KEY_ID)],
    ['deleteSecret', () => deleteSecret(KEY_ID)],
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

      <View style={styles.buttons}>
        {actions.map(([label, op]) => (
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

      <ScrollView
        style={styles.log}
        contentContainerStyle={styles.logContent}
        testID="outcome-log"
      >
        {outcomes.length === 0 ? (
          <Text style={styles.empty}>
            storeSecret → getSecret round-trips a 32-byte secret through the
            hardware wrapping key.
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
  container: { flex: 1, backgroundColor: '#fbfbfa', paddingTop: 64 },
  header: { paddingHorizontal: 20, paddingBottom: 12 },
  title: { fontSize: 24, fontWeight: '700', color: '#141413' },
  subtitle: { fontSize: 14, color: '#5e5d59', marginTop: 4 },
  mono: { fontFamily: 'Menlo', color: '#141413' },
  segments: { paddingHorizontal: 20, gap: 8, paddingBottom: 12 },
  segment: {
    flexDirection: 'row',
    backgroundColor: '#eeece6',
    borderRadius: 8,
    padding: 3,
    gap: 3,
  },
  segmentItem: {
    flex: 1,
    paddingVertical: 7,
    borderRadius: 6,
    alignItems: 'center',
  },
  segmentItemActive: { backgroundColor: '#fff' },
  segmentText: { fontSize: 11, color: '#5e5d59' },
  segmentTextActive: { color: '#141413', fontWeight: '600' },
  buttons: { paddingHorizontal: 20, gap: 7 },
  button: {
    backgroundColor: '#141413',
    paddingVertical: 11,
    borderRadius: 9,
    alignItems: 'center',
  },
  buttonPressed: { opacity: 0.7 },
  buttonDisabled: { opacity: 0.4 },
  buttonText: { color: '#fff', fontSize: 14, fontWeight: '600' },
  log: { flex: 1, marginTop: 14 },
  logContent: { paddingHorizontal: 20, paddingBottom: 40, gap: 9 },
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
  message: { fontSize: 12, color: '#141413', marginTop: 5 },
  remedy: { fontSize: 11, color: '#5e5d59', marginTop: 5, lineHeight: 16 },
});
