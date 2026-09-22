import { beforeEach, describe, expect, it, jest } from '@jest/globals';

const mockGetBiometryType = jest.fn<() => Promise<string>>();
const mockAuthenticate = jest.fn<(r: string, p: string) => Promise<boolean>>();
const mockStoreSecret =
  jest.fn<(k: string, s: string, p: string, i: string) => Promise<void>>();
const mockGetSecret = jest.fn<(k: string, r: string) => Promise<string>>();
const mockHasSecret = jest.fn<(k: string) => Promise<boolean>>();
const mockDeleteSecret = jest.fn<(k: string) => Promise<void>>();
const mockGenerateKey =
  jest.fn<(k: string, p: string, i: string) => Promise<string>>();
const mockImportPrivateKey =
  jest.fn<(k: string, pk: string, p: string, i: string) => Promise<string>>();
const mockGetPublicKey = jest.fn<(k: string) => Promise<string>>();
const mockSignDigest =
  jest.fn<(k: string, d: string, r: string) => Promise<string>>();
const mockExportPrivateKey =
  jest.fn<(k: string, r: string) => Promise<string>>();

jest.mock('../NativeWalletKeystore', () => ({
  __esModule: true,
  default: {
    getBiometryType: () => mockGetBiometryType(),
    authenticate: (reason: string, policy: string) =>
      mockAuthenticate(reason, policy),
    storeSecret: (k: string, sec: string, p: string, i: string) =>
      mockStoreSecret(k, sec, p, i),
    getSecret: (k: string, r: string) => mockGetSecret(k, r),
    hasSecret: (k: string) => mockHasSecret(k),
    deleteSecret: (k: string) => mockDeleteSecret(k),
    generateKey: (k: string, p: string, i: string) => mockGenerateKey(k, p, i),
    importPrivateKey: (k: string, pk: string, p: string, i: string) =>
      mockImportPrivateKey(k, pk, p, i),
    getPublicKey: (k: string) => mockGetPublicKey(k),
    signDigest: (k: string, d: string, r: string) => mockSignDigest(k, d, r),
    exportPrivateKey: (k: string, r: string) => mockExportPrivateKey(k, r),
  },
}));

import {
  authenticate,
  deleteSecret,
  exportPrivateKey,
  generateKey,
  getBiometryType,
  getPublicKey,
  getSecret,
  hasSecret,
  importPrivateKey,
  KeystoreError,
  signDigest,
  storeSecret,
  type KeystoreErrorCode,
} from '../index';

/** Shaped like a React Native promise rejection: an Error carrying `code`. */
function nativeRejection(code: string, message = 'native failure') {
  return Object.assign(new Error(message), { code });
}

beforeEach(() => {
  jest.clearAllMocks();
  mockAuthenticate.mockResolvedValue(true);
  mockGetBiometryType.mockResolvedValue('faceId');
  mockStoreSecret.mockResolvedValue(undefined);
  mockGetSecret.mockResolvedValue('deadbeef');
  mockHasSecret.mockResolvedValue(true);
  mockDeleteSecret.mockResolvedValue(undefined);
  mockGenerateKey.mockResolvedValue(PUBLIC_KEY);
  mockImportPrivateKey.mockResolvedValue(PUBLIC_KEY);
  mockGetPublicKey.mockResolvedValue(PUBLIC_KEY);
  mockSignDigest.mockResolvedValue('ab'.repeat(65));
  mockExportPrivateKey.mockResolvedValue(PRIVATE_KEY);
});

const PUBLIC_KEY = '04' + 'aa'.repeat(64);
const PRIVATE_KEY = '4c'.repeat(32);
const DIGEST = '0x' + 'cd'.repeat(32);

describe('authenticate', () => {
  it('applies the default policy when omitted', async () => {
    await authenticate('Unlock your wallet');

    expect(mockAuthenticate).toHaveBeenCalledWith(
      'Unlock your wallet',
      'biometricOrPasscode'
    );
  });

  it('passes an explicit policy through unchanged', async () => {
    await authenticate('Unlock', 'biometricOnly');

    expect(mockAuthenticate).toHaveBeenCalledWith('Unlock', 'biometricOnly');
  });

  it('resolves true on success', async () => {
    await expect(authenticate('Unlock')).resolves.toBe(true);
  });

  it('rejects an empty reason without reaching the native module', async () => {
    // iOS raises NSInvalidArgumentException on an empty localizedReason, so
    // the guard has to sit in front of the bridge, not behind it.
    await expect(authenticate('   ')).rejects.toBeInstanceOf(KeystoreError);
    expect(mockAuthenticate).not.toHaveBeenCalled();
  });
});

describe('error mapping', () => {
  const cases: KeystoreErrorCode[] = [
    'NOT_AVAILABLE',
    'NOT_ENROLLED',
    'USER_CANCELED',
    'USER_FALLBACK',
    'LOCKOUT',
    'LOCKOUT_PERMANENT',
    'SYSTEM_CANCEL',
    'KEY_NOT_FOUND',
    'KEY_ALREADY_EXISTS',
    'KEY_INVALIDATED',
    'STORAGE_ERROR',
    'INVALID_KEY',
    'UNKNOWN',
  ];

  it.each(cases)('maps native %s to the same typed code', async (code) => {
    mockAuthenticate.mockRejectedValue(nativeRejection(code));

    await expect(authenticate('Unlock')).rejects.toMatchObject({ code });
  });

  it('falls back to UNKNOWN for an unrecognized native code', async () => {
    mockAuthenticate.mockRejectedValue(nativeRejection('E_SOMETHING_NEW'));

    const error = await authenticate('Unlock').catch((e) => e);

    expect(error.code).toBe('UNKNOWN');
    // The original code survives, so an unexpected platform error is still
    // diagnosable after the fallback.
    expect(error.nativeCode).toBe('E_SOMETHING_NEW');
  });

  it('falls back to UNKNOWN when the rejection has no code at all', async () => {
    mockAuthenticate.mockRejectedValue(new Error('bare failure'));

    await expect(authenticate('Unlock')).rejects.toMatchObject({
      code: 'UNKNOWN',
      message: 'bare failure',
    });
  });

  it('keeps NOT_ENROLLED distinct from USER_CANCELED', async () => {
    // These drive different UI: one sends the user to Settings, the other
    // re-prompts. Collapsing them is the bug this test exists to prevent.
    mockAuthenticate.mockRejectedValue(nativeRejection('NOT_ENROLLED'));
    const enrollment = await authenticate('Unlock').catch((e) => e);

    mockAuthenticate.mockRejectedValue(nativeRejection('USER_CANCELED'));
    const cancel = await authenticate('Unlock').catch((e) => e);

    expect(enrollment.code).not.toBe(cancel.code);
  });
});

describe('KeystoreError', () => {
  it('is a real Error subclass with a usable stack', async () => {
    mockAuthenticate.mockRejectedValue(nativeRejection('LOCKOUT'));

    const error = await authenticate('Unlock').catch((e) => e);

    expect(error).toBeInstanceOf(KeystoreError);
    expect(error).toBeInstanceOf(Error);
    expect(error.name).toBe('KeystoreError');
    expect(typeof error.stack).toBe('string');
    expect(error.stack.length).toBeGreaterThan(0);
  });

  it('retains the underlying rejection as `cause`', async () => {
    const underlying = nativeRejection('LOCKOUT');
    mockAuthenticate.mockRejectedValue(underlying);

    const error = await authenticate('Unlock').catch((e) => e);

    expect(error.cause).toBe(underlying);
  });

  it('does not re-wrap an error it already produced', async () => {
    const original = new KeystoreError('LOCKOUT', 'already typed');
    mockAuthenticate.mockRejectedValue(original);

    await expect(authenticate('Unlock')).rejects.toBe(original);
  });
});

describe('getBiometryType', () => {
  it('passes through a known modality', async () => {
    mockGetBiometryType.mockResolvedValue('touchId');

    await expect(getBiometryType()).resolves.toBe('touchId');
  });

  it('reports none when there is no biometric hardware', async () => {
    mockGetBiometryType.mockResolvedValue('none');

    await expect(getBiometryType()).resolves.toBe('none');
  });

  it('degrades an unrecognized modality to the generic type', async () => {
    // Guards the case where native is newer than the JS layer.
    mockGetBiometryType.mockResolvedValue('palmPrint');

    await expect(getBiometryType()).resolves.toBe('biometric');
  });
});

describe('storeSecret', () => {
  it('applies both defaults when options are omitted', async () => {
    await storeSecret('wallet', 'deadbeef');

    // 'never' is the default invalidation on purpose: the alternative destroys
    // the key on enrollment change, which for a wallet means lost funds.
    expect(mockStoreSecret).toHaveBeenCalledWith(
      'wallet',
      'deadbeef',
      'biometricOrPasscode',
      'never'
    );
  });

  it('keeps the invalidation axis independent of the auth policy', async () => {
    await storeSecret('wallet', 'deadbeef', { policy: 'biometricOnly' });

    // biometricOnly must NOT imply onEnrollmentChange.
    expect(mockStoreSecret).toHaveBeenCalledWith(
      'wallet',
      'deadbeef',
      'biometricOnly',
      'never'
    );
  });

  it('passes an explicit invalidation through', async () => {
    await storeSecret('wallet', 'deadbeef', {
      invalidation: 'onEnrollmentChange',
    });

    expect(mockStoreSecret).toHaveBeenCalledWith(
      'wallet',
      'deadbeef',
      'biometricOrPasscode',
      'onEnrollmentChange'
    );
  });

  it.each([
    ['odd length', 'abc'],
    ['non-hex characters', 'zzzz'],
    ['empty', ''],
    ['0x prefix', '0xdeadbeef'],
  ])('rejects %s before reaching native', async (_label, value) => {
    await expect(storeSecret('wallet', value)).rejects.toBeInstanceOf(
      KeystoreError
    );
    expect(mockStoreSecret).not.toHaveBeenCalled();
  });

  it('accepts mixed-case hex', async () => {
    await expect(storeSecret('wallet', 'DeAdBeEf')).resolves.toBeUndefined();
  });

  it('rejects a blank keyId', async () => {
    await expect(storeSecret('  ', 'deadbeef')).rejects.toBeInstanceOf(
      KeystoreError
    );
    expect(mockStoreSecret).not.toHaveBeenCalled();
  });

  it('surfaces KEY_ALREADY_EXISTS rather than overwriting', async () => {
    mockStoreSecret.mockRejectedValue(nativeRejection('KEY_ALREADY_EXISTS'));

    await expect(storeSecret('wallet', 'deadbeef')).rejects.toMatchObject({
      code: 'KEY_ALREADY_EXISTS',
    });
  });
});

describe('getSecret', () => {
  it('returns the secret hex', async () => {
    await expect(getSecret('wallet', 'Unlock')).resolves.toBe('deadbeef');
    expect(mockGetSecret).toHaveBeenCalledWith('wallet', 'Unlock');
  });

  it('rejects an empty reason before reaching native', async () => {
    await expect(getSecret('wallet', '  ')).rejects.toBeInstanceOf(
      KeystoreError
    );
    expect(mockGetSecret).not.toHaveBeenCalled();
  });

  it('maps KEY_INVALIDATED distinctly from a retryable failure', async () => {
    // This one means the secret is gone for good and the app must start
    // recovery — collapsing it into UNKNOWN would tell the user to retry
    // forever.
    mockGetSecret.mockRejectedValue(nativeRejection('KEY_INVALIDATED'));
    const invalidated = await getSecret('wallet', 'Unlock').catch((e) => e);

    mockGetSecret.mockRejectedValue(nativeRejection('USER_CANCELED'));
    const canceled = await getSecret('wallet', 'Unlock').catch((e) => e);

    expect(invalidated.code).toBe('KEY_INVALIDATED');
    expect(canceled.code).toBe('USER_CANCELED');
  });

  it('maps KEY_NOT_FOUND', async () => {
    mockGetSecret.mockRejectedValue(nativeRejection('KEY_NOT_FOUND'));

    await expect(getSecret('missing', 'Unlock')).rejects.toMatchObject({
      code: 'KEY_NOT_FOUND',
    });
  });
});

describe('hasSecret / deleteSecret', () => {
  it('reports presence without authenticating', async () => {
    await expect(hasSecret('wallet')).resolves.toBe(true);
    expect(mockGetSecret).not.toHaveBeenCalled();
    expect(mockAuthenticate).not.toHaveBeenCalled();
  });

  it('deletes idempotently', async () => {
    await expect(deleteSecret('wallet')).resolves.toBeUndefined();
    expect(mockDeleteSecret).toHaveBeenCalledWith('wallet');
  });
});

describe('generateKey', () => {
  it('returns a 0x-prefixed public key and never a private one', async () => {
    const publicKey = await generateKey('wallet');

    expect(publicKey).toBe(`0x${PUBLIC_KEY}`);
    // The private key must not transit the bridge during generation; only a
    // keyId, the policies, and the public key ever appear in this exchange.
    expect(mockGenerateKey).toHaveBeenCalledWith(
      'wallet',
      'biometricOrPasscode',
      'never'
    );
  });

  it('keeps invalidation independent of the auth policy', async () => {
    await generateKey('wallet', { policy: 'biometricOnly' });

    expect(mockGenerateKey).toHaveBeenCalledWith(
      'wallet',
      'biometricOnly',
      'never'
    );
  });
});

describe('importPrivateKey', () => {
  it('strips 0x before crossing the bridge', async () => {
    await importPrivateKey('wallet', `0x${PRIVATE_KEY}`);

    expect(mockImportPrivateKey).toHaveBeenCalledWith(
      'wallet',
      PRIVATE_KEY,
      'biometricOrPasscode',
      'never'
    );
  });

  it.each([
    ['too short', '00'.repeat(31)],
    ['too long', '00'.repeat(33)],
    ['non-hex', 'zz'.repeat(32)],
    ['empty', ''],
  ])('rejects a %s key as INVALID_KEY before native', async (_l, value) => {
    await expect(importPrivateKey('wallet', value)).rejects.toMatchObject({
      code: 'INVALID_KEY',
    });
    expect(mockImportPrivateKey).not.toHaveBeenCalled();
  });

  it('defers the range check to native', async () => {
    // Zero is correctly shaped but out of range. Whether it is in [1, n-1] is
    // a curve question, so native owns it rather than duplicating the order.
    mockImportPrivateKey.mockRejectedValue(nativeRejection('INVALID_KEY'));

    await expect(
      importPrivateKey('wallet', '00'.repeat(32))
    ).rejects.toMatchObject({ code: 'INVALID_KEY' });
    expect(mockImportPrivateKey).toHaveBeenCalled();
  });
});

describe('signDigest', () => {
  it('sends a bare 32-byte digest and returns a 0x signature', async () => {
    const signature = await signDigest('wallet', DIGEST, 'Sign');

    expect(mockSignDigest).toHaveBeenCalledWith(
      'wallet',
      'cd'.repeat(32),
      'Sign'
    );
    expect(signature).toBe(`0x${'ab'.repeat(65)}`);
  });

  it.each([
    ['31 bytes', '0x' + 'cd'.repeat(31)],
    ['33 bytes', '0x' + 'cd'.repeat(33)],
    ['not hex', '0x' + 'zz'.repeat(32)],
  ])('rejects a digest that is %s', async (_l, value) => {
    // A short digest would be silently zero-padded by some native paths and
    // sign the wrong thing, so the length is enforced before the bridge.
    await expect(signDigest('wallet', value, 'Sign')).rejects.toMatchObject({
      code: 'INVALID_KEY',
    });
    expect(mockSignDigest).not.toHaveBeenCalled();
  });

  it('requires a non-empty reason', async () => {
    await expect(signDigest('wallet', DIGEST, '  ')).rejects.toBeInstanceOf(
      KeystoreError
    );
    expect(mockSignDigest).not.toHaveBeenCalled();
  });
});

describe('getPublicKey / exportPrivateKey', () => {
  it('reads the public key without authenticating', async () => {
    await expect(getPublicKey('wallet')).resolves.toBe(`0x${PUBLIC_KEY}`);
    expect(mockSignDigest).not.toHaveBeenCalled();
    expect(mockAuthenticate).not.toHaveBeenCalled();
  });

  it('requires a reason to export', async () => {
    await expect(exportPrivateKey('wallet', '')).rejects.toBeInstanceOf(
      KeystoreError
    );
    expect(mockExportPrivateKey).not.toHaveBeenCalled();
  });

  it('surfaces KEY_NOT_FOUND from getPublicKey', async () => {
    mockGetPublicKey.mockRejectedValue(nativeRejection('KEY_NOT_FOUND'));

    await expect(getPublicKey('missing')).rejects.toMatchObject({
      code: 'KEY_NOT_FOUND',
    });
  });
});
