package com.walletkeystore

import com.facebook.react.bridge.ReactApplicationContext

class WalletKeystoreModule(reactContext: ReactApplicationContext) :
  NativeWalletKeystoreSpec(reactContext) {

  override fun multiply(a: Double, b: Double): Double {
    return a * b
  }

  companion object {
    const val NAME = NativeWalletKeystoreSpec.NAME
  }
}
