# BlockSettle - `ArmoryDB` Headless Runtime

This is a fork of [ArmoryDB](https://github.com/goatpig/BitcoinArmory) that produces
a headless runtime of `ArmoryDB`. The wallet and trading platfrom from [blocksettle.com](http://blocksettle.com/) fully supports this version of ArmoryDB, and provides all the required UI tools to interact with the backend.

## Install ArmoryDB.
BlockSettle provides binary distribution of the runtime for few platforms, including Ubuntu, Windows, and MacOS.

### Ubuntu 
To install the binary release on Ubuntu, 
```bash
sudo add-apt-repository ppa:blocksettle/armorydb
sudo apt-get update

sudo apt-get install armorydb
```
For more information and other available packages please visit our Launchpad page [launchpad.net/BlockSettle] (https://launchpad.net/~blocksettle/+archive/ubuntu/armorydb )

## Running `ArmoryDB`
Before you can run Armorydb you have to make sure you have successfully setup bitcoin core on your system and it is fully synced. You can download the bitcoin core for your distribution from [bitcoin.org](https://bitcoin.org/en/download). You can select between "testnet" and "mainnet" depending on what you want to do. Optionally if you whish to save your bitcoin core settings you can use [Bitcoin Core Config Generator](https://jlopp.github.io/bitcoin-core-config-generator/) to easily create a fully functional bitcon.conf file online. Please note that the following parameters are important. 

* enable server=1 or --server
* disablewallert=0 
* --rest.
* --testnet or --mainnet.

and example command would look like this.
```bash
./bitcoind --server --testnet --rest
#if you saved all your settings to bitcoin.conf
./bitcoind --conf=/home/<your_path>/.bitcon/bitcon.conf 
```
### ArmoryDB connection design

ArmoryDB *must* run alongside the Bitcoin Core node. This is because ArmoryDB
does a memory map on the blockchain files. This can only be done if ArmoryDB
and the node are running on the same OS and, ideally, on the same storage
device. The IP address of the Core node is hardcoded (localhost) and can't be
changed without recompiling Armory (and changing the design at your own risk!).
Only the node's port can be changed via the `satoshirpc-port` parameter. This
design may change in the future.

It is possible for Armory and other clients to talk to ArmoryDB remotely.
Possibilities for reaching ArmoryDB include placing ArmoryDB behind an HTTP
daemon or logging into the ArmoryDB machine remotely via VPN. Talking to
ArmoryDB is done via JSON-encoded packets, as seen in the `armoryd` project.

`ArmoryDB` works by reading the blockchain downloaded by Bitcoin Core and
finding any transactions relevant to the wallets loaded into Armory. This means
that the entire blockchain must be rescanned whenever a new wallet or lockbox
is loaded. Once a wallet/lockbox has been loaded and the blockchain fully
scanned for that wallet, ArmoryDB will keep an eye on the blockchain. Any
transactions relevant to the addresses controlled by wallets/lockboxes will be
resolved. In addition, as Armory builds its own mempool by talking to the Core
node, any relevant zero-confirmation transactions will be resolved by ArmoryDB.

### Start ArmoryDB headless Server.
By default it will try to connect to your running bitcoin core RPC API, and also read data from your bitcoin core block files on your disk. If your bitcoin core configuration differs from the default and you have setup data directories on non standard locations, then you will also have to tell armorydb using command-line parameters or using a config file where it can locate the block files downloaded by bitcoin core. The supported parameters are listed at [Armorydb FAQ](https://btcarmory.com/docs/faq)


The database types are as follows:

* DB\_BARE: Tracks wallet history only. Smallest DB, as the DB doesn't resolve
  a wallet's relevant transaction hashes until requested. (In other words,
  database accesses will be relatively slow.) This was the default database
  type in Armory v0.94.
* DB\_FULL: Tracks wallet history and resolves all relevant transaction hashes.
  (In other words, the database can instantly pull up relevant transaction
  data). ~1GB minimum size for the database. This was the default database type
  in Armory v0.96.5.
* DB\_SUPER: Tracks the entire blockchain history. Any transaction hash can be
  instantly resolved into its relevant data. The database will be at least
  ~100GB large. Default database type.

Note that the flags may be added to the Armory root data directory in an
ArmoryDB config file (`armorydb.conf`). The file will set the parameters every
time ArmoryDB is started. Command line flags, including flags used by Armory,
will override config values. (Changing Armory's default values will require
recompilation.) An example file that mirrors the default parameters used by
Armory can be seen below.

```
db-type="DB_SUPER"
cookie=1
satoshi-datadir="/home/snakamoto/.bitcoin/blocks""
datadir="/home/snakamoto/Armory/"
dbdir="/home/snakamoto/Armory/databases"
```

## Build instructions

### Prerequisites

The following should be the only `apt` prerequisite you need that isn't common
for devs. If anything's missing, it'll be added here later.

```
sudo apt install libprotobuf-dev protobuf-compiler
```

on mac make sure Homebrew, XCode and XCode command line tools are installed,
and get protobuf from Homebrew:

```
brew install protobuf
```

On Windows dependencies are handled automatically with vcpkg.Addtinally a proper development setup would include the following.
* Install Visual Studio 2019 Community Edition
* This build was done using windows10 1809 build - activated licence.
* Only Desktop Development with C++ needs to be installed.
* Git has to be setup or you can install it with visual studio additional components. 
* Windows 10 SDK at least one version (in our case 10.0.18363.xx)( these numbers can disappear so just for reference if it's a recent enough installation.)
* Also double check MSVC build tools are installed. 

### ArmoryDB build instructions for Ubuntu/MacOS

The following steps will build ArmoryDB:

```
cd /path/to/ArmoryDB
mkdir build
cd build
cmake ..
make -j`nproc`
```
### ArmoryDB build instructions for Windows 10.

- Clone and Setup ArmodyDB and Build Environment.

```bash
%comspec% /k "C:\Program Files (x86)\Microsoft Visual Studio\2019\Community\VC\Auxiliary\Build\vcvars64.bat"
cd c:\projects\

git clone https://github.com/BlockSettle/ArmoryDB.git
cd c:\projects\ArmoryDB
mkdir build
```
- Build VCPKG inside the build root.

```bash
git clone https://github.com/Microsoft/vcpkg.git
cd vcpkg
bootstrap-vcpkg.bat
vcpkg integrate install
vcpkg install libwebsockets --head
```
- Build ArmodyDB on Windows 10
```bash
cmake .. -DVCPKG_TARGET_TRIPLET=x64-windows -DCMAKE_CXX_FLAGS="/MP" -DCMAKE_C_FLAGS="/MP" -verbosity:quiet
msbuild -m -p:BuildInParallel=true ALL_BUILD.vcxproj
```

`vcpkg` will be installed automatically.

Overall, Armory tries to use static linking. There will still be a few dependencies, as
seen by `ldd` (Ubuntu) or `otool -L` (macOS). This should be fine. If there are
any issues, they can be addressed as they are encountered.

On Windows on the other hand, there will be `.dll` files built along with the
binary, and they must be in the same directory as the `ArmoryDB` binary if it
is to be distributed or moved. Or somewhere in the `PATH` environment variable.

TODO: use static vcpkg triplet for windows

### CMake Options

| **Option**                  | **Description**                                                                          | **Default**                    |
|-----------------------------|------------------------------------------------------------------------------------------|--------------------------------|
| WITH_HOST_CPU_FEATURES      | use -march=native and supported cpu feature flags, gcc only                              | ON                             |
| ENABLE_LTO                  | enable link-time-optimizations                                                           | OFF for Debug, ON otherwise    |
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

## Changes From Upstream

The following changes have been made compared to the upstream version of Armory:

- The build system is now cmake (needs to be upstreamed.)

- The Armory-specific "public mode" of BIP 150 is the default (i.e., verify the
  server but not the client). Users who wish to do two-way verification will
  need to invoke `ArmoryDB` with the `--fullbip150` flag, which restores
  ArmoryDB to the default BIP 150 behavior for the upstream ArmoryDB.

- The default config type is changed from `FULL` node to `SUPERNODE`.

- `FULL` node support currently does **NOT** work.

- The python and GUI support is not built by default unless all the
  dependencies are available. This fork is concerned only with `ArmoryDB`.

- The datadir is `$HOME/.armorydb` by default.

## Merging Upstream

Make sure you have the `upstream` remote in git, this will list your configured remotes:

```bash
git remote -v
```

to add it do:

```bash
git remote add upstream git@github.com:goatpig/BitcoinArmory
```

to fetch upstream changes and merge them, do:


```bash
git fetch --all --prune
git merge upstream/dev --signoff -S
```

if you get conflicts you will need to resolve them.

## License

Distributed under the MIT License. See the [LICENSE file](LICENSE-MIT) for more
information.

