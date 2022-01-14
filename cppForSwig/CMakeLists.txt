set(CMAKE_CXX_STANDARD 14)
set(CMAKE_CXX_STANDARD_REQUIRED ON)
set(CMAKE_POSITION_INDEPENDENT_CODE ON)
set(CMAKE_CXX_EXTENSIONS OFF)

add_subdirectory(chacha20poly1305)

set(LIBARMORYCOMMON_INCLUDE_DIRECTORIES
    PUBLIC .
    PUBLIC hkdf
    PUBLIC lmdbpp
    PRIVATE bech32/ref/c++
    PRIVATE chacha20poly1305
    PUBLIC libbtc/src/secp256k1/include
    PUBLIC ${LIBBTC_INCLUDE_DIR}
    PUBLIC ${SECP256k1_INCLUDE_DIR}
    PUBLIC Signer
    PUBLIC Wallets
    PRIVATE Wallets/Accounts
    PRIVATE ${PROJECT_BINARY_DIR} # for protobuf protoc genned .h files
)

IF (MSVC)
    LIST(APPEND LIBARMORYCOMMON_INCLUDE_DIRECTORIES
        PUBLIC leveldb_windows_port/win32_posix
    )
ENDIF (MSVC)

set(LIBARMORYCOMMON_LINK_LIBRARIES
    chacha20poly1305
    ${LIBBTC_LIB}
    ${LMDB_LIB}
    ${LIBWEBSOCKETS_LIB}
)

IF (NOT MSVC)
    list(APPEND LIBARMORYCOMMON_LINK_LIBRARIES
        pthread
    )
ENDIF (NOT MSVC)


FILE(GLOB LIBARMORYCOMMON_SOURCES *.cpp)
FILE(GLOB WALLETS_SOURCES Wallets/*.cpp)
FILE(GLOB ACCOUNTS_SOURCES Wallets/Accounts/*.cpp)
FILE(GLOB SIGNER_SOURCES Signer/*.cpp)

list(APPEND LIBARMORYCOMMON_SOURCES
    hkdf/hkdf.c
    gtest/NodeUnitTest.cpp
    lmdbpp/lmdbpp.cpp
    ${WALLETS_SOURCES}
    ${ACCOUNTS_SOURCES}
    ${SIGNER_SOURCES}
)

IF (MSVC)
    list(APPEND LIBARMORYCOMMON_SOURCES
        leveldb_windows_port/win32_posix/dirent_win32.cpp
        leveldb_windows_port/win32_posix/mman.cpp
        leveldb_windows_port/win32_posix/win32_posix.cc
    )
    list(REMOVE_ITEM LIBARMORYCOMMON_SOURCES
        ${CMAKE_CURRENT_SOURCE_DIR}/SocketService_unix.cpp
    )

    set(OS_SPECIFIC_LIBS )

ELSE (MSVC)
    list(REMOVE_ITEM LIBARMORYCOMMON_SOURCES
        ${CMAKE_CURRENT_SOURCE_DIR}/SocketService_win32.cpp
        ${CMAKE_CURRENT_SOURCE_DIR}/Win_TranslatePath.cpp
    )

    set(OS_SPECIFIC_LIBS gmp)

ENDIF (MSVC)

list(REMOVE_ITEM LIBARMORYCOMMON_SOURCES
    ${CMAKE_CURRENT_SOURCE_DIR}/main.cpp
    ${CMAKE_CURRENT_SOURCE_DIR}/old_not_very_good_tests.cpp
    ${CMAKE_CURRENT_SOURCE_DIR}/playground.cpp
)


set(LIBARMORYCOMMON_COMPILE_DEFINITIONS
    PRIVATE
)

if(ENABLE_TESTS)
    add_definitions(-DUNIT_TESTS)
endif()

if(NOT CMAKE_TOOLCHAIN_FILE MATCHES vcpkg)
    find_package(PkgConfig REQUIRED)
endif()

if(TARGET websockets) # we are bundling it
    set(LIBWEBSOCKETS_LIBRARIES websockets)
elseif(CMAKE_TOOLCHAIN_FILE MATCHES vcpkg)
    find_package(libwebsockets CONFIG REQUIRED)
    set(LIBWEBSOCKETS_LIBRARIES websockets_shared)
else()
    pkg_check_modules(LIBWEBSOCKETS REQUIRED libwebsockets>=3.0.1)
endif()

list(APPEND LIBARMORYCOMMON_INCLUDE_DIRECTORIES
    PUBLIC ${LIBWEBSOCKETS_INCLUDE_DIRS}
)

list(APPEND LIBARMORYCOMMON_LINK_LIBRARIES
    ${LIBWEBSOCKETS_LIBRARIES}
)

include(CheckCXXSymbolExists)

check_cxx_symbol_exists(LWS_WITH_TLS lws_config.h LIBWEBSOCKETS_WITH_TLS)

if(LIBWEBSOCKETS_WITH_TLS)
    if(APPLE)
        set(OPENSSL_ROOT_DIR /usr/local/opt/openssl)
    endif()

    find_package(OpenSSL REQUIRED)

    list(APPEND LIBARMORYCOMMON_INCLUDE_DIRECTORIES
        PUBLIC ${OPENSSL_INCLUDE_DIR}
    )

    list(APPEND LIBARMORYCOMMON_LINK_LIBRARIES
        ${OPENSSL_LIBRARIES}
    )
endif()

check_cxx_symbol_exists(LWS_WITH_LIBUV lws_config.h LIBWEBSOCKETS_WITH_LIBUV)

if(LIBWEBSOCKETS_WITH_LIBUV)
    pkg_check_modules(LIBUV REQUIRED libuv)

    list(APPEND LIBARMORYCOMMON_LINK_LIBRARIES
        ${LIBUV_LIBRARIES}
    )
endif()

check_cxx_symbol_exists(LWS_WITH_LIBEVENT lws_config.h LIBWEBSOCKETS_WITH_LIBEVENT)

if(LIBWEBSOCKETS_WITH_LIBEVENT)
    pkg_check_modules(LIBEVENT REQUIRED libevent)

    list(APPEND LIBARMORYCOMMON_LINK_LIBRARIES
        ${LIBEVENT_LIBRARIES}
    )
endif()

check_cxx_symbol_exists(LWS_WITH_LIBCAP lws_config.h LIBWEBSOCKETS_WITH_LIBCAP)

if(LIBWEBSOCKETS_WITH_LIBCAP)
    pkg_check_modules(LIBCAP REQUIRED libcap)

    list(APPEND LIBARMORYCOMMON_LINK_LIBRARIES
        ${LIBCAP_LIBRARIES}
    )
endif()

if(CMAKE_TOOLCHAIN_FILE MATCHES vcpkg)
    find_package(protobuf CONFIG REQUIRED)
    set(PROTOBUF_LIBRARIES protobuf::libprotoc protobuf::libprotobuf)
else()
    pkg_check_modules(PROTOBUF REQUIRED protobuf>=2.0.0)
endif()

list(APPEND LIBARMORYCOMMON_INCLUDE_DIRECTORIES
    PRIVATE ${PROTOBUF_INCLUDE_DIRS}
)

list(APPEND LIBARMORYCOMMON_LINK_LIBRARIES
    ${PROTOBUF_LIBRARIES}
)

set(PROTOBUF_FILES
    AddressBook.proto
    AddressData.proto
    BDVCommand.proto
    CommonTypes.proto
    FeeEstimate.proto
    LedgerEntry.proto
    NodeStatus.proto
    Utxo.proto
    Signer.proto
)

find_program(PROTOC_EXECUTABLE protoc)

if(NOT PROTOC_EXECUTABLE)
    message(FATAL_ERROR "protocol buffers compiler 'protoc' not found")
endif()

file(MAKE_DIRECTORY ${PROJECT_BINARY_DIR}/protobuf)

foreach(proto ${PROTOBUF_FILES})
    string(REGEX REPLACE "\\.proto$" ".pb.cc" proto_cc ${proto})

    add_custom_command(
        OUTPUT ${PROJECT_BINARY_DIR}/protobuf/${proto_cc}
        COMMAND ${PROTOC_EXECUTABLE} --cpp_out=${PROJECT_BINARY_DIR}/protobuf --proto_path=${CMAKE_CURRENT_SOURCE_DIR}/protobuf ${CMAKE_CURRENT_SOURCE_DIR}/protobuf/${proto}
        DEPENDS protobuf/${proto}
    )

    list(APPEND LIBARMORYCOMMON_SOURCES ${PROJECT_BINARY_DIR}/protobuf/${proto_cc})
endforeach()

add_library(ArmoryCommon
    STATIC
    ${LIBARMORYCOMMON_SOURCES}
)

target_compile_definitions(ArmoryCommon
    PUBLIC __STDC_LIMIT_MACROS
    ${LIBARMORYCOMMON_COMPILE_DEFINITIONS}
)

target_include_directories(ArmoryCommon
    ${LIBARMORYCOMMON_INCLUDE_DIRECTORIES}
)

target_link_libraries(ArmoryCommon
    ${LIBARMORYCOMMON_LINK_LIBRARIES}
)

set(LIBARMORYCLI_SOURCES
    BDM_mainthread.cpp
    BDM_Server.cpp
    BIP150_151.cpp
    BIP15x_Handshake.cpp
    BitcoinP2P.cpp
    Blockchain.cpp
    BlockchainScanner.cpp
    BlockchainScanner_Super.cpp
    BlockDataMap.cpp
    BlockDataViewer.cpp
    BlockObj.cpp
    BlockUtils.cpp
    BtcWallet.cpp
    DatabaseBuilder.cpp
    HistoryPager.cpp
    HttpMessage.cpp
    JSON_codec.cpp
    LedgerEntry.cpp
    lmdb_wrapper.cpp
    nodeRPC.cpp
    Progress.cpp
    ScrAddrFilter.cpp
    ScrAddrObj.cpp
    Server.cpp
    SshParser.cpp
    StringSockets.cpp
    txio.cpp
    ZeroConf.cpp
)

if(MSVC)
    list(APPEND LIBARMORYCLI_SOURCES
        SocketService_win32.cpp
    )
else()
    list(APPEND LIBARMORYCLI_SOURCES
        SocketService_unix.cpp
    )
endif()

add_library(ArmoryCLI
    STATIC
    ${LIBARMORYCLI_SOURCES}
)

set_target_properties(ArmoryCLI PROPERTIES CXX_STANDARD 14)
target_compile_features(ArmoryCLI PUBLIC cxx_std_11)

target_include_directories(ArmoryCLI
    ${LIBARMORYCOMMON_INCLUDE_DIRECTORIES}
)

target_link_libraries(ArmoryCLI
    ArmoryCommon
)

target_compile_definitions(ArmoryCLI
    PUBLIC -D__STDC_LIMIT_MACROS
)

find_program(LRELEASE_EXECUTABLE lrelease)

add_executable(armorydb
    main.cpp
)

set_target_properties(armorydb
    PROPERTIES RUNTIME_OUTPUT_DIRECTORY ${PROJECT_BINARY_DIR}
)

target_include_directories(armorydb
    ${LIBARMORYCOMMON_INCLUDE_DIRECTORIES}
)

target_link_libraries(armorydb
    ArmoryCLI
    ${OS_SPECIFIC_LIBS}
)

include(GNUInstallDirs)

install(TARGETS armorydb DESTINATION ${CMAKE_INSTALL_BINDIR})

add_executable(BIP150KeyManager
    KeyManager.cpp
)

set_target_properties(BIP150KeyManager
    PROPERTIES RUNTIME_OUTPUT_DIRECTORY ${PROJECT_BINARY_DIR}
)

target_include_directories(BIP150KeyManager
    ${LIBARMORYCOMMON_INCLUDE_DIRECTORIES}
)

target_link_libraries(BIP150KeyManager
    ArmoryCLI
    ${OS_SPECIFIC_LIBS}
)

install(TARGETS BIP150KeyManager DESTINATION ${CMAKE_INSTALL_BINDIR})

string_option(WITH_CLIENT "build python client" OFF)

find_package(Python2 COMPONENTS Development QUIET)

find_program(SWIG_EXECUTABLE swig)

if(WITH_CLIENT STREQUAL AUTO)
    # currently swig sometimes fails on clang
    if(Python2_Development_FOUND AND SWIG_EXECUTABLE AND (NOT CMAKE_CXX_COMPILER_ID STREQUAL Clang))
        set(WITH_CLIENT ON)
    else()
        set(WITH_CLIENT OFF)
    endif()
endif()

if(WITH_CLIENT)
    if(NOT Python2_Development_FOUND)
        message(FATAL_ERROR "python 2 development files not found, install python-dev")
    endif()

    if(NOT SWIG_EXECUTABLE)
        message(FATAL_ERROR "swig not found")
    endif()

    set(CPPBLOCKUTILS_SOURCES
        ${PROJECT_BINARY_DIR}/CppBlockUtils_wrap.cxx
    )

    unset(SWIG_OPTS)

    if(CMAKE_COMPILER_IS_GNUCXX)
        set(SWIG_OPTS -D__GNUC__)
    elseif(CMAKE_CXX_COMPILER_ID STREQUAL Clang)
        set(SWIG_OPTS -D__CLANG__)
    endif()

    if(CMAKE_C_SIZEOF_DATA_PTR EQUAL 8) # 64 bit
        set(SWIG_OPTS ${SWIG_OPTS} -D__LP64__)
    endif()

    add_custom_command(
        OUTPUT ${PROJECT_BINARY_DIR}/CppBlockUtils_wrap.cxx
        COMMAND ${SWIG_EXECUTABLE} -c++ -python -threads ${SWIG_OPTS} -o ${PROJECT_BINARY_DIR}/CppBlockUtils_wrap.cxx ${CMAKE_CURRENT_SOURCE_DIR}/CppBlockUtils.i
        DEPENDS CppBlockUtils.i
        WORKING_DIRECTORY ${PROJECT_BINARY_DIR}
    )

    set(CPPBLOCKUTILS_LINK_LIBRARIES
        ArmoryCommon
        Python2::Python
    )

    add_library(CppBlockUtils
        SHARED
        ${CPPBLOCKUTILS_SOURCES}
    )

    set_target_properties(CppBlockUtils
        PROPERTIES LIBRARY_OUTPUT_DIRECTORY ${PROJECT_BINARY_DIR}
    )

    # remove "lib" prefix
    set_target_properties(CppBlockUtils
        PROPERTIES PREFIX ""
    )

    target_include_directories(CppBlockUtils
        PUBLIC Python2::Python
    )

    # copy CppBlockUtils.so to _CppBlockUtils.so as well, why I don't know
    add_custom_command(
        TARGET CppBlockUtils POST_BUILD
        COMMAND ${CMAKE_COMMAND} -E copy
            ${PROJECT_BINARY_DIR}/CppBlockUtils${CMAKE_SHARED_LIBRARY_SUFFIX}
            ${PROJECT_BINARY_DIR}/_CppBlockUtils${CMAKE_SHARED_LIBRARY_SUFFIX}
        WORKING_DIRECTORY ${PROJECT_BINARY_DIR}
    )

    target_link_libraries(CppBlockUtils
        ${CPPBLOCKUTILS_LINK_LIBRARIES}
    )

    # rewrite prefix for armory script
    add_custom_command(
        OUTPUT  ${PROJECT_BINARY_DIR}/armory
        COMMAND ${CMAKE_COMMAND} -Dscript_name=armory
                                 -Dscript_file=${PROJECT_SOURCE_DIR}/dpkgfiles/armory
                                 -Dscript_output_file=${PROJECT_BINARY_DIR}/armory
                                 -Dscript_dir=${PROJECT_BINARY_DIR}
                                 -Dprefix=${CMAKE_INSTALL_PREFIX}
                                 -P ${PROJECT_SOURCE_DIR}/cmake/scripts/RewriteArmoryScriptPrefix.cmake
        WORKING_DIRECTORY ${PROJECT_BINARY_DIR}
    )

    add_custom_target(armory_script DEPENDS ${PROJECT_BINARY_DIR}/armory)

    add_dependencies(CppBlockUtils armory_script)

    install(PROGRAMS ${PROJECT_BINARY_DIR}/armory DESTINATION ${CMAKE_INSTALL_BINDIR})

    install(CODE "file(MAKE_DIRECTORY ${CMAKE_INSTALL_LIBDIR}/armory/armoryengine)")

    install(CODE "file(MAKE_DIRECTORY ${CMAKE_INSTALL_DATAROOTDIR}/applications)") # share/applications

    install(
        TARGETS CppBlockUtils
        DESTINATION ${CMAKE_INSTALL_LIBDIR}/armory
    )

    # copy the underscore prefixed version too
    install(
        FILES ${PROJECT_BINARY_DIR}/_CppBlockUtils${CMAKE_SHARED_LIBRARY_SUFFIX}
        DESTINATION ${CMAKE_INSTALL_LIBDIR}/armory
    )

    install(FILES
        ../armorycolors.py
        ../armorymodels.py
        ../ArmoryQt.py
        ../dynamicImport.py
        ../guardian.py
        ../jasvet.py
        ../LICENSE.py
        ../qrcodenative.py
        ../qtdefines.py
        ../qtdialogs.py
        ../SDM.py
        ../setup.py
        ../subprocess_win.py
        ../update_version.py
        ../writeNSISCompilerArgs.py
        ${PROJECT_BINARY_DIR}/CppBlockUtils.py
        ${PROJECT_BINARY_DIR}/qrc_img_resources.py

        DESTINATION ${CMAKE_INSTALL_LIBDIR}/armory
    )

    install(DIRECTORY ../armoryengine DESTINATION ${CMAKE_INSTALL_LIBDIR}/armory)

    install(DIRECTORY ../img
            DESTINATION ${CMAKE_INSTALL_DATAROOTDIR}/armory
            PATTERN ".DS_Store" EXCLUDE
    )
endif()

option(ENABLE_TESTS "build tests binaries" OFF)

if(ENABLE_TESTS)
    add_subdirectory(gtest)
endif()
