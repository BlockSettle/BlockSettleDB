@ECHO OFF
if "%~1"=="" (
   echo "Run with 'Release' or 'Debug' as an argument"
   GOTO completed
)
mkdir build
cd build
rem Add -DENABLE_TESTS=OFF to the command line below to disable build of tests
cmake .. -DVCPKG_TARGET_TRIPLET=x64-windows -DCMAKE_CXX_FLAGS="/MP /EHa" -DCMAKE_C_FLAGS="/MP" -DWITH_LIBBTC="../libbtc"
msbuild -m -p:BuildInParallel=true -p:Configuration=%1 ALL_BUILD.vcxproj
cd ..
:completed
