set(CMAKE_CXX_STANDARD 14)
set(CMAKE_CXX_STANDARD_REQUIRED ON)
set(CMAKE_POSITION_INDEPENDENT_CODE ON)
set(CMAKE_CXX_EXTENSIONS OFF)

set(TEST_SOURCES
    TestUtils.cpp
    NodeUnitTest.cpp
)

add_executable(BIP151RekeyTest
    BIP151RekeyTest.cpp
    ${TEST_SOURCES}
)
set_target_properties(BIP151RekeyTest
    PROPERTIES RUNTIME_OUTPUT_DIRECTORY ${PROJECT_BINARY_DIR}
)
target_include_directories(BIP151RekeyTest
    ${LIBARMORYCOMMON_INCLUDE_DIRECTORIES}
)
target_link_libraries(BIP151RekeyTest
    ${GTEST_LIB}
    ArmoryCommon
    ${OS_SPECIFIC_LIBS}
)

add_executable(ContainerTests
    ContainerTests.cpp
<<<<<<< HEAD
)

target_link_libraries(ContainerTests
    gtest
)

set_target_properties(ContainerTests PROPERTIES RUNTIME_OUTPUT_DIRECTORY ${PROJECT_BINARY_DIR})

add_executable(BIP151RekeyTest
    BIP151RekeyTest.cpp
)

target_link_libraries(BIP151RekeyTest
    gtest
)

set_target_properties(BIP151RekeyTest PROPERTIES RUNTIME_OUTPUT_DIRECTORY ${PROJECT_BINARY_DIR})

add_executable(SupernodeTests
    SupernodeTests.cpp
)

target_link_libraries(SupernodeTests
    gtest
)

set_target_properties(SupernodeTests PROPERTIES RUNTIME_OUTPUT_DIRECTORY ${PROJECT_BINARY_DIR})

add_executable(CppBlockUtilsTests
    CppBlockUtilsTests.cpp
)

target_link_libraries(CppBlockUtilsTests
    gtest
)

set_target_properties(CppBlockUtilsTests PROPERTIES RUNTIME_OUTPUT_DIRECTORY ${PROJECT_BINARY_DIR})

add_executable(WalletTests
    WalletTests.cpp
)

target_link_libraries(WalletTests
    gtest
)

set_target_properties(WalletTests PROPERTIES RUNTIME_OUTPUT_DIRECTORY ${PROJECT_BINARY_DIR})

add_executable(SignerTests
    SignerTests.cpp
)

target_link_libraries(SignerTests
    gtest
)

set_target_properties(SignerTests PROPERTIES RUNTIME_OUTPUT_DIRECTORY ${PROJECT_BINARY_DIR})
=======
    ${TEST_SOURCES}
)
set_target_properties(ContainerTests
    PROPERTIES RUNTIME_OUTPUT_DIRECTORY ${PROJECT_BINARY_DIR}
)
target_include_directories(ContainerTests
    ${LIBARMORYCOMMON_INCLUDE_DIRECTORIES}
)
target_link_libraries(ContainerTests
    ${GTEST_LIB}
    ArmoryCommon
    ${OS_SPECIFIC_LIBS}
)

add_executable(CppBlockUtilsTests
    CppBlockUtilsTests.cpp
    ${TEST_SOURCES}
)
set_target_properties(CppBlockUtilsTests
    PROPERTIES RUNTIME_OUTPUT_DIRECTORY ${PROJECT_BINARY_DIR}
)
target_include_directories(CppBlockUtilsTests
    ${LIBARMORYCOMMON_INCLUDE_DIRECTORIES}
)
target_link_libraries(CppBlockUtilsTests
    ${GTEST_LIB}
    ArmoryCommon
    ${OS_SPECIFIC_LIBS}
)

# Seems to be outdated - re-enable when fixed
#add_executable(DB1kIterTest
#    DB1kIterTest.cpp
#    ${TEST_SOURCES}
#)
#set_target_properties(DB1kIterTest
#    PROPERTIES RUNTIME_OUTPUT_DIRECTORY ${PROJECT_BINARY_DIR}
#)
#target_include_directories(DB1kIterTest
#    ${LIBARMORYCOMMON_INCLUDE_DIRECTORIES}
#)
#target_link_libraries(DB1kIterTest
#    ${GTEST_LIB}
#    ArmoryCommon
#)

add_executable(SignerTests
    SignerTests.cpp
    ${TEST_SOURCES}
)
set_target_properties(SignerTests
    PROPERTIES RUNTIME_OUTPUT_DIRECTORY ${PROJECT_BINARY_DIR}
)
target_include_directories(SignerTests
    ${LIBARMORYCOMMON_INCLUDE_DIRECTORIES}
)
target_link_libraries(SignerTests
    ${GTEST_LIB}
    ArmoryCommon
    ${OS_SPECIFIC_LIBS}
)

add_executable(SupernodeTests
    SupernodeTests.cpp
    ${TEST_SOURCES}
)
set_target_properties(SupernodeTests
    PROPERTIES RUNTIME_OUTPUT_DIRECTORY ${PROJECT_BINARY_DIR}
)
target_include_directories(SupernodeTests
    ${LIBARMORYCOMMON_INCLUDE_DIRECTORIES}
)
target_link_libraries(SupernodeTests
    ${GTEST_LIB}
    ArmoryCommon
    ${OS_SPECIFIC_LIBS}
)

add_executable(UtilsTests
    UtilsTests.cpp
    ${TEST_SOURCES}
)
set_target_properties(UtilsTests
    PROPERTIES RUNTIME_OUTPUT_DIRECTORY ${PROJECT_BINARY_DIR}
)
target_include_directories(UtilsTests
    ${LIBARMORYCOMMON_INCLUDE_DIRECTORIES}
)
target_link_libraries(UtilsTests
    ${GTEST_LIB}
    ArmoryCommon
    ${OS_SPECIFIC_LIBS}
)

add_executable(WalletTests
    WalletTests.cpp
    ${TEST_SOURCES}
)
set_target_properties(WalletTests
    PROPERTIES RUNTIME_OUTPUT_DIRECTORY ${PROJECT_BINARY_DIR}
)
target_include_directories(WalletTests
    ${LIBARMORYCOMMON_INCLUDE_DIRECTORIES}
)
target_link_libraries(WalletTests
    ${GTEST_LIB}
    ArmoryCommon
    ${OS_SPECIFIC_LIBS}
)

add_executable(ZeroConfTests
    ZeroConfTests.cpp
    ${TEST_SOURCES}
)
set_target_properties(ZeroConfTests
    PROPERTIES RUNTIME_OUTPUT_DIRECTORY ${PROJECT_BINARY_DIR}
)
target_include_directories(ZeroConfTests
    ${LIBARMORYCOMMON_INCLUDE_DIRECTORIES}
)
target_link_libraries(ZeroConfTests
    ${GTEST_LIB}
    ArmoryCommon
    ${OS_SPECIFIC_LIBS}
)
>>>>>>> upstream/dev
