
SUBDIRS = tests
# We kind of want openconnect to be built before we try to test it
check-recursive: openconnect$(EXEEXT)
# And even *building* some of tests/*.c needs libopenconnect
install-recursive: libopenconnect.la
all-recursive: libopenconnect.la

if BUILD_WWW
SUBDIRS += www
endif
if USE_NLS
SUBDIRS += po
endif
if BUILD_NSIS
noinst_DATA = openconnect-installer.exe
endif

lib_LTLIBRARIES = libopenconnect.la
sbin_PROGRAMS = openconnect
man8_MANS = openconnect.8

AM_CFLAGS = @WFLAGS@
AM_CPPFLAGS = -DLOCALEDIR="\"$(localedir)\""

openconnect_SOURCES = xml.c main.c
openconnect_CFLAGS = $(AM_CFLAGS) $(SSL_CFLAGS) $(DTLS_SSL_CFLAGS) \
	$(LIBXML2_CFLAGS) $(JSON_CFLAGS) $(LIBPROXY_CFLAGS) \
	$(ZLIB_CFLAGS) $(LIBSTOKEN_CFLAGS) $(LIBPSKC_CFLAGS) \
	$(GSSAPI_CFLAGS) $(INTL_CFLAGS) $(ICONV_CFLAGS) \
	$(LIBPCSCLITE_CFLAGS)
openconnect_LDADD = libopenconnect.la $(SSL_LIBS) $(LIBXML2_LIBS) \
	$(LIBPROXY_LIBS) $(INTL_LIBS) $(ICONV_LIBS)

if OPENCONNECT_WIN32
openconnect_SOURCES += openconnect.rc
endif
library_srcs = ssl.c http.c textbuf.c http-auth.c auth-common.c auth-html.c library.c compat.c lzs.c mainloop.c script.c ntlm.c digest.c mtucalc.c openconnect-internal.h
lib_srcs_cisco = auth.c cstp.c
lib_srcs_juniper = oncp.c lzo.c auth-juniper.c
lib_srcs_pulse = pulse.c
lib_srcs_globalprotect = gpst.c win32-ipicmp.h auth-globalprotect.c
lib_srcs_array = array.c
lib_srcs_oath = oath.c
lib_srcs_oidc = oidc.c
lib_srcs_ppp = ppp.c ppp.h
lib_srcs_nullppp = nullppp.c
lib_srcs_f5 = f5.c
lib_srcs_fortinet = fortinet.c
lib_srcs_checkpoint = cp.c
lib_srcs_json = jsondump.c

library_srcs += $(lib_srcs_juniper) $(lib_srcs_cisco) $(lib_srcs_oath) \
		$(lib_srcs_globalprotect) $(lib_srcs_pulse) \
		$(lib_srcs_oidc) $(lib_srcs_ppp) $(lib_srcs_nullppp) \
		$(lib_srcs_f5) $(lib_srcs_fortinet) $(lib_srcs_checkpoint) \
		$(lib_srcs_json) $(lib_srcs_array)

lib_srcs_gnutls = gnutls.c gnutls_tpm.c gnutls_tpm2.c
lib_srcs_openssl = openssl.c openssl-pkcs11.c
lib_srcs_win32 = wintun.c tun-win32.c sspi.c
lib_srcs_posix = tun.c
lib_srcs_gssapi = gssapi.c
lib_srcs_iconv = iconv.c
lib_srcs_yubikey = yubikey.c
lib_srcs_stoken = stoken.c
lib_srcs_esp = esp.c esp-seqno.c
lib_srcs_dtls = dtls.c

POTFILES = $(openconnect_SOURCES) gnutls-esp.c gnutls-dtls.c openssl-esp.c openssl-dtls.c \
	   $(lib_srcs_esp) $(lib_srcs_dtls) gnutls_tpm2_esys.c gnutls_tpm2_ibm.c \
	   $(lib_srcs_openssl) $(lib_srcs_gnutls) $(library_srcs) \
	   $(lib_srcs_win32) $(lib_srcs_posix) $(lib_srcs_gssapi) $(lib_srcs_iconv) \
	   $(lib_srcs_yubikey) $(lib_srcs_stoken) $(lib_srcs_oidc)

if OPENCONNECT_LIBPCSCLITE
library_srcs += $(lib_srcs_yubikey)
endif
if OPENCONNECT_STOKEN
library_srcs += $(lib_srcs_stoken)
endif
if OPENCONNECT_GSSAPI
library_srcs += $(lib_srcs_gssapi)
endif
if OPENCONNECT_GNUTLS
library_srcs += $(lib_srcs_gnutls)
lib_srcs_esp += gnutls-esp.c
lib_srcs_dtls += gnutls-dtls.c
endif
if OPENCONNECT_TSS2_ESYS
library_srcs += gnutls_tpm2_esys.c
endif
if OPENCONNECT_TSS2_IBM
library_srcs += gnutls_tpm2_ibm.c
endif
if OPENCONNECT_OPENSSL
library_srcs += $(lib_srcs_openssl)
lib_srcs_esp += openssl-esp.c
lib_srcs_dtls += openssl-dtls.c
endif
if OPENCONNECT_DTLS
lib_srcs_cisco += $(lib_srcs_dtls)
endif
if OPENCONNECT_ESP
lib_srcs_juniper += $(lib_srcs_esp)
endif
if OPENCONNECT_ICONV
library_srcs += $(lib_srcs_iconv)
endif
if BUILTIN_JSON
library_srcs += json/json.c json/json.h
endif
if OPENCONNECT_WIN32
library_srcs += $(lib_srcs_win32)
.rc.o:
	$(WINDRES) $^ -o $@
%.o : %.rc
	$(WINDRES) $^ -o $@
else
library_srcs += $(lib_srcs_posix)
endif


libopenconnect_la_SOURCES = version.c $(library_srcs)
libopenconnect_la_CFLAGS = $(AM_CFLAGS) $(SSL_CFLAGS) $(DTLS_SSL_CFLAGS) \
	$(LIBXML2_CFLAGS) $(LIBPROXY_CFLAGS) $(ZLIB_CFLAGS) $(P11KIT_CFLAGS) \
	$(TSS_CFLAGS) $(LIBSTOKEN_CFLAGS) $(LIBPSKC_CFLAGS) $(GSSAPI_CFLAGS) \
	$(INTL_CFLAGS) $(ICONV_CFLAGS) $(LIBPCSCLITE_CFLAGS) $(LIBP11_CFLAGS) \
	$(LIBLZ4_CFLAGS) $(JSON_CFLAGS)
libopenconnect_la_LIBADD = $(SSL_LIBS) $(DTLS_SSL_LIBS) \
	$(LIBXML2_LIBS) $(LIBPROXY_LIBS) $(ZLIB_LIBS) $(P11KIT_LIBS) \
	$(TSS_LIBS) $(LIBSTOKEN_LIBS) $(LIBPSKC_LIBS) $(GSSAPI_LIBS) \
	$(INTL_LIBS) $(ICONV_LIBS) $(LIBPCSCLITE_LIBS) $(LIBP11_LIBS)\
	$(LIBLZ4_LIBS) ${JSON_LIBS}

if OPENBSD_LIBTOOL
# OpenBSD's libtool doesn't have -version-number, but its -version-info arg
# does what GNU libtool's -version-number does. Which arguably is what the
# GNU -version-info arg ought to do too. I hate libtool.
LT_VER_ARG = -version-info
else
LT_VER_ARG = -version-number
endif
libopenconnect_la_LDFLAGS = $(LT_VER_ARG) @APIMAJOR@:@APIMINOR@ -no-undefined
noinst_HEADERS = openconnect-internal.h openconnect.h gnutls.h lzo.h
include_HEADERS = openconnect.h
if HAVE_VSCRIPT
libopenconnect_la_LDFLAGS += @VSCRIPT_LDFLAGS@,libopenconnect.map
libopenconnect_la_DEPENDENCIES = libopenconnect.map
endif

if OPENCONNECT_JNI
if JNI_STANDALONE
libopenconnect_la_SOURCES += jni.c
libopenconnect_la_CFLAGS += $(JNI_CFLAGS) -Wno-missing-declarations
else
lib_LTLIBRARIES += libopenconnect-wrapper.la
libopenconnect_wrapper_la_SOURCES = jni.c
libopenconnect_wrapper_la_CFLAGS = $(AM_CFLAGS) $(JNI_CFLAGS) -Wno-missing-declarations
libopenconnect_wrapper_la_LIBADD = libopenconnect.la
endif
endif

pkgconfig_DATA = openconnect.pc

EXTRA_DIST = AUTHORS version.sh COPYING.LGPL openconnect.ico $(POTFILES) openconnect.nsi.in
EXTRA_DIST += json/AUTHORS json/LICENSE json/json.c json/json.h
EXTRA_DIST += $(shell cd "$(top_srcdir)" && \
		git ls-tree HEAD -r --name-only -- android/ java/ trojans/ bash/ 2>/dev/null)

DISTCLEANFILES = $(pkgconfig_DATA) version.c

pkglibexec_SCRIPTS = trojans/csd-post.sh trojans/csd-wrapper.sh trojans/tncc-wrapper.py \
	trojans/hipreport.sh trojans/hipreport-android.sh trojans/tncc-emulate.py

bashcompletiondir = $(datadir)/bash-completion/completions
bashcompletion_DATA = bash/openconnect

# main.c includes version.c
openconnect-main.$(OBJEXT): version.c

version.c: $(library_srcs) $(lib_openssl_srcs) $(lib_gnutls_srcs) \
	   $(openconnect_SOURCES) Makefile.am configure.ac \
	   openconnect.h openconnect-internal.h version.sh @GITVERSIONDEPS@
	@cd $(srcdir) && ./version.sh $(abs_builddir)/version.c

AUTHORS: @GITVERSIONDEPS@
	@git shortlog -sen > AUTHORS

tmp-dist: uncommitted-check
	$(MAKE) $(AM_MAKEFLAGS) VERSION=$(patsubst v%,%,$(shell git describe --tags)) DISTHOOK=0 dist

tmp-distdir: uncommitted-check
	$(MAKE) $(AM_MAKEFLAGS) VERSION=$(patsubst v%,%,$(shell git describe --tags)) DISTHOOK=0 distdir

uncommitted-check:
	@if ! git update-index --refresh --unmerged || \
	    ! git diff-index --name-only --exit-code HEAD; then \
		echo "*** ERROR: Uncommitted changes in above files"; exit 1; fi

DISTHOOK=1
dist-hook: uncommitted-check
	@if [ $(DISTHOOK) = 1 ]; then \
	    if ! git rev-parse --verify v$(VERSION) &> /dev/null; then \
		echo "*** ERROR: Version v$(VERSION) is not tagged"; exit 1; fi ; \
	    if ! git diff --name-only --exit-code v$(VERSION) HEAD > /dev/null; then \
		echo "*** ERROR: Git checkout not at version v$(VERSION)"; exit 1; fi ; \
	fi

sign-dist: dist
	@for a in $(DIST_ARCHIVES); do \
		gpg --default-key 67E2F359 --detach-sign -a $$a ; \
	done

tag: uncommitted-check
	@if git rev-parse --verify v$(VERSION) &> /dev/null; then \
		echo "*** ERROR: Version v$(VERSION) is already tagged"; exit 1; fi
	@sed 's/AC_INIT.*/AC_INIT(openconnect, $(VERSION))/' -i $(srcdir)/configure.ac
	@sed 's/^v=.*/v="v$(VERSION)"/' -i $(srcdir)/version.sh
	@( echo '1,/<!-- latest-release-start -->/p' ;\
	   echo '/<!-- latest-release-end -->/,$$p' ;\
	   echo  '/<!-- latest-release-start -->/a\' ;\
	   echo  'The latest release is <a href="https://www.infradead.org/openconnect/download/openconnect-$(VERSION).tar.gz">OpenConnect v$(VERSION)</a>\' ;\
	   echo  '<i>(<a href="https://www.infradead.org/openconnect/download/openconnect-$(VERSION).tar.gz.asc">PGP signature</a>)</i>,\' ;\
	   echo 'released on $(shell date +%Y-%m-%d) with the following changelog:</p>\' ;\
	   sed '0,/<b>OpenConnect HEAD/d;/<\/ul><br\/>/,$$d;s/$$/\\/' $(srcdir)/www/changelog.xml ;\
	   echo '     </ul>' ) | \
	 sed -n -f - -i $(srcdir)/www/download.xml
	@( echo "s/Last modified: .*/Last modified: $(shell date)/" ;\
	   echo '/  <li><b>OpenConnect HEAD/a\' ;\
	   echo '     <ul>\' ;\
	   echo '       <li><i>No changelog entries yet</i></li>\';\
	   echo '     </ul><br/>\' ;  echo '  </li>\' ;\
	   echo '  <li><b><a href="https://www.infradead.org/openconnect/download/openconnect-$(VERSION).tar.gz">OpenConnect v$(VERSION)</a></b>\' ;\
	   echo '     <i>(<a href="https://www.infradead.org/openconnect/download/openconnect-$(VERSION).tar.gz.asc">PGP signature</a>)</i> &#8212; $(shell date +%Y-%m-%d)' ) | \
		sed -f - -i $(srcdir)/www/changelog.xml
	@echo '/API version [0-9]\+\.[0-9]\+:$$/s/:/ (v$(VERSION); $(shell date +%Y-%m-%d)):/' | \
		sed -f - -i $(srcdir)/openconnect.h
# stupid syntax highlighting '
	@cd $(srcdir) && git commit -s -m "Tag version $(VERSION)" configure.ac version.sh www/download.xml www/changelog.xml openconnect.h
	@git tag v$(VERSION)
	@cd $(srcdir) && ./autogen.sh

update-po: po/$(PACKAGE).pot
	@cd $(top_srcdir); if ! git diff-index --name-only --exit-code HEAD -- po/; then \
		echo "*** ERROR: Uncommitted changes in above files"; exit 1; \
	else \
		> po/LINGUAS; \
		for a in po/*.po; do \
			msgmerge -q -N -F $$a $(abs_builddir)/po/$(PACKAGE).pot > $$a.merge ; \
			msgattrib -F --no-fuzzy --no-obsolete $$a.merge > $$a ; \
			rm $$a.merge ; \
			if msgattrib --translated $$a | grep -q msgstr; then \
				echo $$a | sed 's%^po/\(.*\)\.po%\1%' >> po/LINGUAS ; \
			fi ; \
		done && \
		if ! git update-index -q --refresh --unmerged || \
		   ! git diff-index --name-only --exit-code HEAD -- po/ >/dev/null; then \
			git commit -s -m "Resync translations with sources" -- po/ ; \
		else \
			echo No changes to commit ; \
		fi; \
	fi

po/$(PACKAGE).pot: $(POTFILES) version.sh
	@echo "Regenerating $@" ; rm -f $@ && \
	xgettext --directory=$(top_srcdir) --from-code=UTF-8 \
	  --sort-by-file --add-comments --keyword=_ --keyword=N_ \
	  --package-name="@PACKAGE@" --package-version="@VERSION@" \
	  --msgid-bugs-address=openconnect-devel@lists.infradead.org \
	  -o $@ $(POTFILES)

ACLOCAL_AMFLAGS = -I m4

if BUILD_NSIS
DISTCLEANFILES += .*.dll.d .*.exe.d file-list*.txt instfiles.nsh uninstfiles.nsh vpnc-script-win.js openconnect.nsi openconnect-installer.exe

if OPENCONNECT_WINTUN
WINTUN_DLL = .libs/wintun.dll
DISTCLEANFILES += $(WINTUN_DLL)
endif

export V AM_DEFAULT_VERBOSITY bindir OBJDUMP

# This Makefile has no rules to create these, just uses them to track
# dependencies on file-list.txt if it already exists.
-include .openconnect.exe.d
-include .wintun.dll.d

file-list.txt: Makefile.dlldeps openconnect$(EXEEXT) libopenconnect.la $(WINTUN_DLL)
	@$(MAKE) --no-print-directory -f $< $@

# OpenVPN TAP driver for Windows Vista/2003 and newer
# (see https://community.openvpn.net/openvpn/wiki/GettingTapWindows)
TAPDRIVER = tap-windows-9.21.2.exe
TAPSHA256 = 645bee92ba4e9f32ddfdd9f8519dc1b9f9ff0b0a8e87e342f08d39da77e499a9

$(TAPDRIVER):
	curl https://build.openvpn.net/downloads/releases/tap-windows-9.21.2.exe -o $@

# Validate file and also let make find it in VPATH
file-list-$(TAPDRIVER).txt: $(TAPDRIVER)
	echo $(TAPSHA256) $< | sha256sum -c
	echo $< > $@

WINTUNDRIVER = wintun-0.10.2.zip
WINTUNSHA256 = fcd9f62f1bd5a550fcb9c21fbb5d6a556214753ccbbd1a3ebad4d318ec9dcbef

$(WINTUNDRIVER):
	curl https://www.wintun.net/builds/$(WINTUNDRIVER) -o $@

.libs/wintun.dll: $(WINTUNDRIVER)
	echo $(WINTUNSHA256) $< | sha256sum -c
	unzip -DD -o -j -d .libs $< wintun/bin/$(WINTUN_ARCH)/wintun.dll

# Latest vpnc-script-win.js
vpnc-script-win.js:
	curl https://gitlab.com/openconnect/vpnc-scripts/raw/master/vpnc-script-win.js -o $@

# Let make find the file in VPATH
file-list-%.txt: %
	echo $< > $@

# Rather than trying to get clever in NSIS and iterate over lists,
# just emit raw snippets to be included separately in the install
# and uninstall sections.
instfiles.nsh: file-list.txt file-list-vpnc-script-win.js.txt file-list-$(TAPDRIVER).txt
	$(AM_V_GEN) cat $^ | while read FILE; do echo "File \"$${FILE}\"" ; done > $@

uninstfiles.nsh: file-list.txt file-list-vpnc-script-win.js.txt file-list-$(TAPDRIVER).txt
	$(AM_V_GEN) cat $^ | while read FILE; do echo "Delete /rebootok \"\$$INSTDIR\\\\$${FILE##*/}\"" ; done > $@

# Theoretically makensis can define symbols with the -D command line
# option and much of this could just be done that way, but I couldn't
# get it to work and life's too short.
openconnect.nsi: version.c
	$(AM_V_GEN) VERSION=$$(cut -f2 -d\" version.c); \
	PROD_VERSION=$$(echo "$$VERSION" | perl -ne 'm|v(\d+)\.(\d+)(?:\.git\.\|\-)?(\d+)?(?:-g.+\|.*)|; print "$$1.$$2." . ($$3 or "0") . ".0"'); \
	if egrep -q '^#define OPENCONNECT_GNUTLS' config.h; then \
	    TLS_LIBRARY=GnuTLS; \
	elif egrep -q '^#define OPENCONNECT_OPENSSL' config.h; then \
	    TLS_LIBRARY=OpenSSL; \
	else \
	    TLS_LIBRARY="Unknown TLS library"; \
	fi; \
	( echo "VIProductVersion \"$$PROD_VERSION\""; \
	  echo "VIAddVersionKey ProductVersion \"$$VERSION\""; \
	  echo "VIAddVersionKey Comments \"OpenConnect multi-protocol VPN client for Windows (command-line version, built with $$TLS_LIBRARY). For more information, visit https://www.infradead.org/openconnect/\""; \
	  echo "!include $(srcdir)/openconnect.nsi.in" ) > $@

AM_V_MAKENSIS = $(am__v_MAKENSIS_$(V))
am__v_MAKENSIS_ = $(am__v_MAKENSIS_$(AM_DEFAULT_VERBOSITY))
am__v_MAKENSIS_0 = @echo "  MAKENSIS   " $@;
am__v_MAKENSIS_1 =

openconnect-installer.exe: openconnect.nsi instfiles.nsh uninstfiles.nsh $(srcdir)/openconnect.nsi.in html-recursive
	$(AM_V_MAKENSIS) $(MAKENSIS) $<

endif
