export * from './keystore';
export { KeystoreError, type KeystoreErrorCode } from './errors';

// The viem adapter is intentionally not re-exported. It ships as the
// `react-native-wallet-keystore/viem` subpath with viem as an optional peer, so
// importing the core API never requires viem to be installed.
