# BlockSettle - ArmoryDB fork
A fork of [Armory](https://github.com/goatpig/BitcoinArmory) that only produces ArmoryDB, the headless binary. For now, this repo is meant primarily to support Linux builds. macOS builds should be possible but aren't confirmed. Windows builds will require CMake files or modified versions of Visual Studio files in the upstream Armory repo.

## Build instructions
### Prerequisites
The following should be the only `apt` prerequisite you need that isn't common for devs. If anything's missing, it'll be added here later.

```
sudo apt install protobuf
```

### libwebsockets
Note that ArmoryDB requires libwebsockets. The default version of libwebsockets included by Ubuntu (as of 18.10) will not work properly with ArmoryDB. To keep things simple, this repo includes a clean copy of [v3.1.0 of libwebsockets](https://github.com/warmcat/libwebsockets/tree/v3.1.0). This must be compiled before compiling Armory. For now, the ArmoryDB build process does *not* automatically compile libwebsockets. This step must be done manually.

Go into the libwebsockets subdirectory and issue the following commands.

```
mkdir build
cd build
cmake .. -DLWS_SSL_CLIENT_USE_OS_CA_CERTS=0 -DLWS_WITH_SHARED=0 -DLWS_WITH_SSL=0
make
```

### ArmoryDB
Once libwebsockets has been compiled, you may compile Armory. The following steps will work.

```
./autogen.sh
./configure
make
```

Note that this fork makes an important change. Upstream, the code requires the explicit statement of a root directory containing [libwebsockets](https://github.com/warmcat/libwebsockets/) materials. If /usr/local/lib contains libwebsockets.a, /usr/local needs to be specified. This was changed here in order to simplify the compilation process. Unless otherwise specified, Autotools will simply assume that `libwebsockets/build` is the root directory. If you wish to override with a different/newer version, `--with-own-lws=/the/preferred/directory` must be specified when configuring Armory.

Overall, Armory uses static linking. There will still be a few dependencies, as seen by `ldd` (Ubuntu) or `otool -L` (macOS). This should be fine. If there are any issues, they can be addressed as they're encountered.

## Changes
The following changes have been made compared to the upstream version of Armory:

- Everything other than the C++ files required to build ArmoryDB, along with support files (e.g., Autotools), have been removed completely.
- The Autotools files have been modified slightly to enforce the production of only ArmoryDB.
- Crypto++ has been removed completely. ArmoryDB *must* compile with support for [libbtc](https://github.com/libbtc/libbtc).
- README.md has been moved to README\_upstream.md.
- The Armory-specific "public mode" of BIP 150 is the default (i.e., verify the server but not the client). Users who wish to do two-way verification will need to invoke `ArmoryDB` with the `--fullbip150` flag, which restores ArmoryDB to the default BIP 150 behavior for the upstream ArmoryDB.

## Possible future changes
In the future, it may be worthwhile to do the following:

- Add the C++ test suite. It would be a simple drop-in.
- libwebsockets is just a simple dump of a download of the given libwebsockets version. It may be desirable to switch it to a subtree model, similar to what's used for libbtc. This way, users can be assured that the committed code is exactly the same as what's in the original repo.
- Switch to CMake. Some of the CMake functionality has been written in other BlockSettle repos. However, the files expect the ArmoryDB code to be part of a larger binary. The files would need to be rewritten to output everything to a standalone binary, and would need to be updated to cover any changes made to the Autotools files. Switching to CMake would arguably be more trouble than it's worth unless the idea is to try to upstream the CMake changes.

## CMake options

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

## CMake Windows/vcpkg Build Type

When building on windows, set the cmake variable `VCPKG_TARGET_TRIPLET` to
`x64-windows` or `x86-windows` depending on whether the build is for 64 bit or
32 bit. You must be in the appropriate Visual Studio environment as well.

All vcpkg supported triplets should work, and this variable can be used to
activate vcpkg support on other platforms.

When building with the Visual Studio IDE, the build products will be located
under `C:\Users\<your-user>\CMakeBuilds`.
