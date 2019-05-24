set(LMDB_SOURCES
    lmdbpp.cpp
    mdb.c
    midl.c
)

add_library(lmdb
    ${LMDB_SOURCES}
)

target_include_directories(lmdb
    PRIVATE lmdb/libraries/liblmdb
)

if(APPLE)
    target_compile_definitions(lmdb
        PRIVATE -DMDB_USE_POSIX_SEM=1
    )
endif()
