# Makefile for Bitcoin Armory - Root Makefile
SUBDIRS = cppForSwig
bin_PROGRAMS =
noinst_PROGRAMS =

EXTRA_DIST = *.py *.md LICENSE LICENSE-ATI LICENSE-MIT \
	nginx_example.conf imgList.xml autogen.sh \
	armoryengine/*.py ui/*.py \
	img/* lang/* dpkgfiles/* \
	windowsbuild/* linuxbuild/* osxbuild/*

ACLOCAL_AMFLAGS = -I build-aux/m4

lrelease:
if BUILD_CLIENT
	lrelease lang/*.ts
endif

qrc_img_resources.py: imgList.xml
if BUILD_CLIENT
	pyrcc4 -o qrc_img_resources.py imgList.xml
endif

copy-script:
# Creating redistributable binaries is a horror show with Autotools. GCC can use
# $ORIGIN to make searching for libraries relative via RPATH. libtool refuses to
# support $ORIGIN. The elder gods punish all who dare question their decision.
#
# The "ideal" method is to just dump everything into a standard folder that the
# system will search (e.g., /usr/local/lib). This isn't always ideal, or even
# possible. The workaround: Let Automake do its thing and then use an external
# tool to tell libraries to use RPATH to search local locations.
# SOURCE 1: https://wiki.debian.org/RpathIssue
# SOURCE 2: https://www.mikeash.com/pyblog/friday-qa-2009-11-06-linking-and-install-names.html
# SOURCE 3: https://github.com/conda/conda-build/issues/279
# SOURCE 4: https://longwei.github.io/rpath_origin/
if ! BUILD_DARWIN
	patchelf --set-rpath \$$ORIGIN:\$$ORIGIN/cppForSwig/.libs:\$$ORIGIN/lib:\$$ORIGIN/../lib cppForSwig/ArmoryDB
	patchelf --set-rpath \$$ORIGIN:\$$ORIGIN/lib:\$$ORIGIN/../lib cppForSwig/.libs/libArmoryCommon.so
	patchelf --set-rpath \$$ORIGIN:\$$ORIGIN/lib:\$$ORIGIN/../lib cppForSwig/.libs/libArmoryCLI.so
if BUILD_CLIENT
	patchelf --set-rpath \$$ORIGIN:\$$ORIGIN/lib:\$$ORIGIN/../lib cppForSwig/.libs/libArmoryGUI.so
	patchelf --set-rpath \$$ORIGIN:\$$ORIGIN/lib:\$$ORIGIN/../lib cppForSwig/.libs/libCppBlockUtils.so
endif
endif
	cp cppForSwig/ArmoryDB ./ArmoryDB

# Copy libwebsockets instance over to keep components happy.
	mkdir -p lib
if BUILD_DARWIN
	cp -L $(LWS_LIB_LOC)/libwebsockets.dylib ./lib/
else
	cp -R $(LWS_LIB_LOC)/libwebsockets.so* ./lib/
endif

# SWIG code and requirements.
if BUILD_CLIENT
	cp cppForSwig/CppBlockUtils.py ./CppBlockUtils.py
if BUILD_DARWIN
# Autotools insists on looking for shared libraries (-install_name flag during
# compilation) in /usr/local/lib. Unsure how to safely override the setting.
# We also can't rely on the user installing libraries elsewhere. So, by default,
# CppBlockUtils will choke when it attempts to load any shared library to which
# it's linked. The workaround: Let Automake do its thing and then use an
# external tool (installed by Xcode) to tell CppBlockUtils.so where to actually
# find shared libraries it needs.
# SOURCE 1: https://www.mikeash.com/pyblog/friday-qa-2009-11-06-linking-and-install-names.html
# SOURCE 2: https://github.com/conda/conda-build/issues/279
# Alt target name (useful for debugging?): @executable_path/py/usr/local/lib/liblmdb.0.dylib
	install_name_tool -change /usr/local/lib/liblmdb.0.dylib @loader_path/../liblmdb.0.dylib ./cppForSwig/.libs/libCppBlockUtils.dylib
	cp cppForSwig/.libs/libCppBlockUtils.dylib ./_CppBlockUtils.so
else
	cp cppForSwig/.libs/libCppBlockUtils.so ./_CppBlockUtils.so
endif
endif

.PHONY: copy-script lrelease qrc_img_resources.py

all-local: copy-script lrelease qrc_img_resources.py


#target to clean up pre autotools installation left overs
uninstall-old:
	rm -f $(DESTDIR)$(prefix)/bin/ArmoryDB

install-exec-hook: uninstall-old
if BUILD_CLIENT
	mkdir -p $(DESTDIR)$(prefix)/lib/armory/ui
	mkdir -p $(DESTDIR)$(prefix)/lib/armory/armoryengine
	mkdir -p $(DESTDIR)$(prefix)/lib/armory/lang
	mkdir -p $(DESTDIR)$(prefix)/share/applications
	cp *.py *.so README.md $(DESTDIR)$(prefix)/lib/armory
	cp -r ui/* $(DESTDIR)$(prefix)/lib/armory/ui
	cp -r armoryengine/* $(DESTDIR)$(prefix)/lib/armory/armoryengine
	cp lang/*.qm $(DESTDIR)$(prefix)/lib/armory/lang
endif

	mkdir -p $(DESTDIR)$(prefix)/bin
# Sometimes, uninstall-old deletes a valid ArmoryDB. Copy again to be safe.
	cp ArmoryDB $(DESTDIR)$(prefix)/bin
	cp -R $(LWS_LIB_LOC)/libwebsockets.so* $(DESTDIR)$(prefix)/lib/

# See the earlier comment about Autotools, redistributables, and RPATH. (Linux
# uses patchelf, Macs use install_name_tool, which is installed by Xcode.) While
# not strictly necessary, change the Mac's shared library IDs so that they're
# not absolute. (Strangely, some frameworks are also hard-coded inside the
# shared libraries, but they don't cause problems. Just ignore them.)
if BUILD_DARWIN
	install_name_tool -change $(DESTDIR)$(prefix)/lib/libArmoryCommon.0.dylib @loader_path/../libArmoryCommon.0.dylib $(DESTDIR)$(prefix)/lib/armory/_CppBlockUtils.so
	install_name_tool -change $(DESTDIR)$(prefix)/lib/libArmoryCommon.0.dylib @loader_path/libArmoryCommon.0.dylib $(DESTDIR)$(prefix)/lib/libArmoryCLI.0.dylib
	install_name_tool -id @rpath/libCppBlockUtils.0.dylib $(DESTDIR)$(prefix)/lib/armory/_CppBlockUtils.so
	install_name_tool -id @rpath/libfcgi.0.dylib $(DESTDIR)$(prefix)/lib/libfcgi.0.dylib
	install_name_tool -id @rpath/libArmoryCommon.0.dylib $(DESTDIR)$(prefix)/lib/libArmoryCommon.0.dylib
	install_name_tool -id @rpath/libArmoryCLI.0.dylib $(DESTDIR)$(prefix)/lib/libArmoryCLI.0.dylib
	install_name_tool -id @rpath/libArmoryGUI.0.dylib $(DESTDIR)$(prefix)/lib/libArmoryGUI.0.dylib
	install_name_tool -change $(DESTDIR)$(prefix)/lib/libArmoryCommon.0.dylib @loader_path/../lib/libArmoryCommon.0.dylib $(DESTDIR)$(prefix)/bin/ArmoryDB
	install_name_tool -change $(DESTDIR)$(prefix)/lib/libArmoryCLI.0.dylib @loader_path/../lib/libArmoryCLI.0.dylib $(DESTDIR)$(prefix)/bin/ArmoryDB
if USE_CRYPTOPP
	install_name_tool -change $(DESTDIR)$(prefix)/lib/libcryptopp.0.dylib @loader_path/libcryptopp.0.dylib $(DESTDIR)$(prefix)/lib/libArmoryCommon.0.dylib
	install_name_tool -change $(DESTDIR)$(prefix)/lib/libcryptopp.0.dylib @loader_path/libcryptopp.0.dylib $(DESTDIR)$(prefix)/lib/libArmoryCLI.0.dylib
	install_name_tool -id @rpath/libcryptopp.0.dylib $(DESTDIR)$(prefix)/lib/libcryptopp.0.dylib
	install_name_tool -change $(DESTDIR)$(prefix)/lib/libcryptopp.0.dylib @loader_path/../lib/libcryptopp.0.dylib $(DESTDIR)$(prefix)/bin/ArmoryDB
endif
if BUILD_CLIENT
	rm -f $(DESTDIR)$(prefix)/lib/libCppBlockUtils.*
	install_name_tool -change $(DESTDIR)$(prefix)/lib/libArmoryGUI.0.dylib @loader_path/../libArmoryGUI.0.dylib $(DESTDIR)$(prefix)/lib/armory/_CppBlockUtils.so
	install_name_tool -change $(DESTDIR)$(prefix)/lib/libArmoryCommon.0.dylib @loader_path/libArmoryCommon.0.dylib $(DESTDIR)$(prefix)/lib/libArmoryGUI.0.dylib
if USE_CRYPTOPP
	install_name_tool -change $(DESTDIR)$(prefix)/lib/libcryptopp.0.dylib @loader_path/libcryptopp.0.dylib $(DESTDIR)$(prefix)/lib/libArmoryGUI.0.dylib
	install_name_tool -change $(DESTDIR)$(prefix)/lib/libcryptopp.0.dylib @loader_path/../libcryptopp.0.dylib $(DESTDIR)$(prefix)/lib/armory/_CppBlockUtils.so
endif
endif
endif

# No need to install test binaries.
if BUILD_TESTS
	rm -f $(DESTDIR)$(prefix)/bin/*Tests
endif

# Skip Linux-specific steps on OSX.
if ! BUILD_DARWIN
if BUILD_CLIENT
	rsync -rupE --exclude="img/.DS_Store" img $(DESTDIR)$(prefix)/share/armory/
	sed "s: /usr: $(prefix):g" < dpkgfiles/armory > $(DESTDIR)$(prefix)/bin/armory
	chmod +x $(DESTDIR)$(prefix)/bin/armory
endif
endif

uninstall-hook: uninstall-old
	rm -rf $(DESTDIR)$(prefix)/lib/armory
	rm -rf $(DESTDIR)$(prefix)/bin/armory
	rm -f  $(DESTDIR)$(prefix)/share/applications/armory*
	rm -rf $(DESTDIR)$(prefix)/share/armory

clean-local:
	rm -f ArmoryDB
	rm -f lib/*
	rm -f CppBlockUtils.py
	rm -f _CppBlockUtils.so
	rm -f CppBlockUtils.pyc
