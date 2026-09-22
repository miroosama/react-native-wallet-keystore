/**
 * Public entry point.
 *
 * Kept as a pure re-export barrel so that `viem.ts` can depend on the core API
 * without a cycle back through this module.
 */
export * from './keystore';
export { KeystoreError, type KeystoreErrorCode } from './errors';

// The viem adapter is deliberately NOT re-exported here. Doing so makes every
// consumer resolve `viem` at import time, including those who never use the
// adapter and have not installed it. It ships instead as the
// `react-native-wallet-keystore/viem` subpath, with viem as an optional peer.
