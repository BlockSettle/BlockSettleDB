# BlockSettle - ArmoryDB fork

A fork of [Armory](https://github.com/goatpig/BitcoinArmory) that only produces
ArmoryDB, the headless binary.

## Build instructions

### Prerequisites

The following should be the only `apt` prerequisite you need that isn't common for devs. If anything's missing, it'll be added here later.

```
sudo apt install libprotobuf-dev protobuf-compiler
```

on mac make sure Homebrew, XCode and XCode command line tools are installed,
and get protobuf from Homebrew:

```
brew install protobuf
```

On Windows dependencies are handled automatically with vcpkg.

### ArmoryDB

The following steps will build ArmoryDB:

```
mkdir build
cd build
cmake ..
make -j`nproc`
```

On Windows the procedure is similar:

```
mkdir build
cd build
cmake .. -DVCPKG_TARGET_TRIPLET=x64-windows
msbuild /m
```

Overall, Armory tries to use static linking. There will still be a few dependencies, as
seen by `ldd` (Ubuntu) or `otool -L` (macOS). This should be fine. If there are
any issues, they can be addressed as they're encountered.

On Windows on the other hand, there will be `.dll` files built along with the
binary, and they must be in the same directory as the `ArmoryDB` binary if it
is to be distributed or moved. Or somewhere in the `PATH` environment variable.

TODO: use static vcpkg triplet for windows

### CMake options

| **Option**                  | **Description**                                                                          | **Default**                    |
|-----------------------------|------------------------------------------------------------------------------------------|--------------------------------|
| WITH_HOST_CPU_FEATURES      | use -march=native and supported cpu feature flags, gcc only                              | ON                             |
| WITH_CRYPTOPP               | use Crypto++ library for cryptography functions                                          | OFF                            |
| WITH_CLIENT                 | build Python client                                                                      | AUTO                           |
| WITH_GUI                    | build GUI support using Qt4 for the Python client                                        | AUTO                           |
| ENABLE_TESTS                | build the test binaries                                                                  | OFF                            |
| LIBBTC_WITH_WALLET          | enable libbtc wallet                                                                     | OFF                            |
| LIBBTC_WITH_TESTS           | enable libbtc tests                                                                      | OFF                            |
| LIBBTC_WITH_TOOLS           | build libbtc tools binaries                                                              | OFF                            |
| LIBBTC_RANDOM_DEVICE        | device to use for random numbers                                                         | /dev/urandom                   |
| SECP256K1_ENABLE_ASM        | enable asm routines in the secp256k1 library                                             | ON                             |
| SECP256K1_USE_LIBGMP        | use libgmp for numeric routines in the secp256k1 library                                 | AUTO                           |
| SECP256K1_MODULE_ECDH       | enable the ecdh module in the secp256k1 library                                          | OFF                            |
| SECP256K1_MODULE_SCHNORR    | enable the schnorr module in the secp256k1 library                                       | OFF                            |
| SECP256K1_ECMULT_STATIC_PRECOMPUTATION | use a statically generated ecmult table for the secp256k1 library             | OFF                            |
| SECP256K1_ENDOMORPHISM      | use endomorphism optiomization for the secp256k1 library                                 | OFF                            |
| SECP256K1_WITH_FIELD        | field for the secp256k1 library, can be '32bit', '64bit' or 'AUTO'                       | AUTO                           |
| SECP256K1_WITH_SCALAR       | scalar for the secp256k1 library, can be '32bit', '64bit' or 'AUTO'                      | AUTO                           |
| VCPKG_TARGET_TRIPLET        | see below                                                                                | not set                        |

### CMake Windows/vcpkg Build Type

When building on windows, set the cmake variable `VCPKG_TARGET_TRIPLET` to
`x64-windows` or `x86-windows` depending on whether the build is for 64 bit or
32 bit.

All vcpkg supported triplets should work in theory, assuming the protobuf port
will build on that platform.

When building with the Visual Studio IDE, the build products will be located
under `C:\Users\<your-user>\CMakeBuilds`.

## Changes

The following changes have been made compared to the upstream version of Armory:

- The build system is now cmake (needs to be upstreamed.)
- The Armory-specific "public mode" of BIP 150 is the default (i.e., verify the
  server but not the client). Users who wish to do two-way verification will
  need to invoke `ArmoryDB` with the `--fullbip150` flag, which restores
  ArmoryDB to the default BIP 150 behavior for the upstream ArmoryDB.
