lib_LTLIBRARIES = libhkdf.la
noinst_PROGRAMS =

HKDF_SOURCE_FILES = hkdf.c
INCLUDE_FILES = -I$(LIBBTC_LIBDIR)/include

libhkdf_la_SOURCES = $(HKDF_SOURCE_FILES)
libhkdf_la_CPPFLAGS = $(AM_CPPFLAGS) $(INCLUDE_FILES) -fPIC
libhkdf_la_CFLAGS = $(AM_CFLAGS)
libhkdf_la_LIBADD = $(LIBBTC_LIBDIR)/libbtc.la
libhkdf_la_LDFLAGS = $(LDFLAGS) -static