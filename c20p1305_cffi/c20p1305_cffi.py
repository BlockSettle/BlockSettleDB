################################################################################
#                                                                              #
# Copyright (C) 2021, goatpig.                                                 #
#  Distributed under the MIT license                                           #
#  See LICENSE-MIT or https://opensource.org/licenses/MIT                      #
#                                                                              #
################################################################################

"""
This is the CFFI setup file. Here all C methods and structs/typedefs that
need python access are first declared. The C code is then made available to
CFFI, which will invoke gcc to build the corresponding shared library. There
is also a feature to link to system and discoverable shared libs.

The CFFI model seems to favor shared libraries. It is preferable to only let
it build the narrow set of C functions that need exposed to Python and let it
link to the internal code dynamically.

The other option is to build the entire code as part of the CFFI shared lib,
which is longer and most likely innefficient if the C/C++ side needs access
to those definitions too.
"""

import cffi

ffi = cffi.FFI()

"""
cffi.FFI.cdef() takes the C declarations of the functions to pythonize (
one declaration per line).

It takes structures and typedefs as well but does not make them directly
available to Python. Custom make_new like functions that return the desired
struct/type have to be added. It's preferable to add those to a dedicated
C header for cffi's purposes, or declare them inline in the setup file, so
as to avoid polluting the original C headers.

The typical approach is to read the relevant C header files, strip them of
all precompiler directives and feed them to cdef as is. I am not comfortable
with this wide net approach. It is more work but manual inline declaration
of the strict set of functions that Python needs to see is a lot cleaner,
and less opaque for reviewers.
"""

with open('cffi_declarations.cffi') as f:
    data = ''
    for line in f:
        if line.startswith('#'):
            continue
        data += line

    ffi.cdef(data)

ffi.set_source(
    "c20p1305",
    r'''
    #include "cffi_cdecl.h"
    ''',

    #source file for the dedicated cffi code
    sources = ["cffi_cdef.c"], 

    #link time custom path for lib discovery
    library_dirs = [
        "../cppForSwig/libbtc/.libs",
        "../cppForSwig/libbtc/src/secp256k1/.libs",
        "../cppForSwig/chacha20poly1305/.libs",
        "../cppForSwig/hkdf/.libs"
        ],

    #dependencies
    libraries = ["hkdf", "btc", "chacha20poly1305", "secp256k1"]
    )

ffi.compile(verbose=True)
