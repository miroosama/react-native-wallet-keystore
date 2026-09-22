require "json"

package = JSON.parse(File.read(File.join(__dir__, "package.json")))

Pod::Spec.new do |s|
  s.name         = "WalletKeystore"
  s.version      = package["version"]
  s.summary      = package["description"]
  s.homepage     = package["homepage"]
  s.license      = package["license"]
  s.authors      = package["author"]

  s.platforms    = { :ios => min_ios_version_supported }
  s.source       = { :git => "https://github.com/miroosama/react-native-wallet-keystore.git", :tag => "#{s.version}" }

  s.source_files = "ios/**/*.{h,m,mm,swift,cpp}"
  s.private_header_files = "ios/**/*.h"

  # Not linked by install_modules_dependencies, which only wires up the React
  # Native dependencies.
  s.frameworks = "LocalAuthentication", "Security"

  # bitcoin-core/libsecp256k1 with the recovery module compiled in. The
  # recovery module is what yields Ethereum's `v` directly, rather than
  # recovering the public key four times and comparing.
  s.dependency "secp256k1.swift", "~> 0.1"

  install_modules_dependencies(s)
end
