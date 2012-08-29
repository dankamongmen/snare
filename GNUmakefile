SHELL:=bash -o pipefail

.DELETE_ON_ERROR:

.PHONY: all install deinstall default build fulltest test sfiltertest clean mrproper FORCE

# BSD Ports Collection makefiles set some variables to be exported (CFLAGS, for
# instance). We don't want our CFLAGS to be propagated out to libsfilter etc,
# so mark all variables unexported unless explicitly set for export within this
# makefile. This has the effect of defeating CFLAGS settings intended for the
# Port Collection's entirety; we ought generate our own local CFLAGS variables
# based off inherited CFLAGS, instead. FIXME.
unexport CFLAGS

XMLBIN:=$(shell which xmlstarlet 2> /dev/null || which xml 2> /dev/null || echo xml)
TAGBIN:=$(shell which exctags 2> /dev/null || which ctags 2> /dev/null || echo ctags)

ifeq ($(shell uname),Linux)
READLINK:=readlink -f
DFLAGS+=-D_FILE_OFFSET_BITS=64 -D_FORTIFY_SOURCE=2 -D_GNU_SOURCE
AMALWAREARCH:=deb4
DLSYMLFLAGS:=-ldl
THREAD_IFLAGS:=-pthread
THREAD_LFLAGS:=-lpthread
else
ifeq ($(shell uname),FreeBSD)
READLINK:=realpath
DFLAGS+=-D_THREAD_SAFE -D_POSIX_PTHREAD_SEMANTICS -D_P1003_1B_VISIBLE
AMALWAREARCH:=freebsd6
THREAD_IFLAGS:=-pthread
MFLAGS32:=-rpath /usr/lib32 -B/usr/lib32
endif
endif

THREAD_IFLAGS+=-include pthread.h

MAKEFILE:=GNUmakefile

CUNIT:=cunit
SNARE:=snare
CROSIER:=crosier
POLTEST:=poltest
NTLMHASH:=ntlmhash
BONWARE:=bonware
BASSDRUM:=bassdrum

# Internal deps for derived directories
BINDIR:=bin
LIBDIR:=lib
SCRIPTDIR:=sbin
SNARECONFDIR:=etc/$(SNARE)
CROSIERCONFDIR:=etc/$(CROSIER)
BASSDRUMCONFDIR:=etc/$(BASSDRUM)

# Output directories for build.
OUT:=.out
BINOUT:=$(OUT)/$(BINDIR)
LIBOUT:=$(OUT)/$(LIBDIR)
SNARELIBOUT:=$(OUT)/snarelib
DEPOUT:=$(OUT)/dep
OBJOUT:=$(OUT)/obj

# Output directory for install
PREFIX?=/usr/local

# Hierarchal filesystem backing store implies grouping by directory and, by
# idiom, file suffix. Alias directories as our root objects -- each binary
# gets its own source directory in APPSRCDIR.
BINARIES:=$(SNARE) $(POLTEST) $(NTLMHASH) $(BONWARE)
BIN:=$(addprefix $(BINOUT)/,$(BINARIES))
APPSRCDIR:=src
ERSATZ:=$(OUT)/ersatz
HANDLERLIB:=swps.so
UNITTESTING:=$(CUNIT)-$(SNARE).so $(CUNIT)-$(BASSDRUM).so
UNITTESTLIB:=$(addprefix $(LIBOUT)/,$(UNITTESTING))
LIB:=$(UNITTESTLIB) $(addprefix $(SNARELIBOUT)/,$(HANDLERLIB))

# librep
REPLFLAGS:=$(shell pkg-config --libs librep)
# libdank
DANKCFLAGS:=$(shell pkg-config --cflags libdank)
DANKLFLAGS:=$(shell pkg-config --libs libdank) $(shell xml2-config --libs)
# SmartFilter
SFILTER:=$(APPSRCDIR)/sfilter/lib/control
SFCFLAGS:=-I$(SFILTER)
SFLFLAGS:=-L$(SFILTER) -lsfcontrol
# SCUR Anti-Malware
AMALWARE:=unfree/antimalware/$(AMALWAREARCH)
AMCFLAGS:=-Iunfree
AMLFLAGS:=-L$(AMALWARE) -lscanm_p
# libbon (Anti-Malware wrapper, with 64-to-32 SYSV shmem bridge)
BONDIR:=$(APPSRCDIR)/libbon
LIBBON:=$(LIBOUT)/libbon.so
BONLFLAGS:=-L$(LIBOUT) -lbon
# pcre
PCRELFLAGS:=$(shell pkg-config --libs libpcre)

# ICAP server and bassdrum ICAP handler
SNARE_DIR:=$(APPSRCDIR)/$(SNARE)
HANDLER_DIR:=$(APPSRCDIR)/handler
POLICY_DIR:=$(APPSRCDIR)/policy
UTIL_DIR:=$(APPSRCDIR)/util
MOB_CLT_DIR:=$(APPSRCDIR)/mobile_client_utils
NTLM_UTIL_DIR:=$(APPSRCDIR)/ntlm_util
# 64-bit wrapper for Anti-Malware
BONWARE_DIR:=$(APPSRCDIR)/bonware
# Policy testing application
POLTEST_DIR:=$(APPSRCDIR)/$(POLTEST)
NTLMHASH_DIR:=$(APPSRCDIR)/$(NTLMHASH)

# Versioning code, which relies in part on svnversion(1)'s output
SVNURI:=svn+ssh://svn.research.sys/svn/bassdrum/trunk
SNARESVNURI:=svn+ssh://svn.research.sys/svn/chakra/trunk
SVNREVISION:=$(shell svnversion . $(SVNURI) | tr ":" "_")
SNARESVNREVISION:=$(shell svnversion $(SNARE_DIR) $(SNARESVNURI) | tr ":" "_")
VERSIONSRC:=$(SNARE_DIR)/version.c
PROD_VER:=trunk-c$(SNARESVNREVISION)

# Target-specific FOO_DIR + common DIRS -> FOO_DIRS. Each set of paths must
# include all source files necessary to build its associated end target.
SNARE_DIRS:=$(SNARE_DIR)
POLTEST_DIRS:=$(POLICY_DIR) $(POLTEST_DIR) $(UTIL_DIR)
NTLMHASH_DIRS:=$(NTLMHASH_DIR) $(NTLM_UTIL_DIR)
BONWARE_DIRS:=$(BONWARE_DIR)
LIBBON_DIRS:=$(BONDIR)
HANDLER_DIRS:=$(HANDLER_DIR) $(POLICY_DIR) $(UTIL_DIR) $(MOB_CLT_DIR) $(NTLM_UTIL_DIR)

# Unit testing includes common and all binary-specific code in that language.
CUNIT_BASSDRUM_DIRS:=$(SNARE_DIR) $(HANDLER_DIR) $(POLICY_DIR) $(UTIL_DIR) $(MOB_CLT_DIR) \
	$(APPSRCDIR)/$(CUNIT)-$(BASSDRUM) $(NTLM_UTIL_DIR)
CUNIT_SNARE_DIRS:=$(SNARE_DIR) $(APPSRCDIR)/$(CUNIT)-$(SNARE)

CSRCDIRS:=$(CUNIT_BASSDRUM_DIRS) $(APPSRCDIR)/$(CUNIT)-$(SNARE) $(POLTEST_DIR) $(BONWARE_DIR) $(BONDIR)
CSRC:=$(shell find $(CSRCDIRS) -name .svn -prune -o -type f -name \*.c -print)
CXXSRC:=$(shell find $(CSRCDIRS) -name .svn -prune -o -type f -name \*.cc -print)
EXTSRC:=$(shell find $(SFILTER) -name .svn -prune -o -type f -name \*.c -print)
INC:=$(shell find $(CSRCDIRS) $(SFILTER) -name .svn -prune -o -type f -name \*.h -print)

SNARECSRC:=$(foreach dir, $(SNARE_DIRS), $(filter $(dir)/%, $(CSRC)))
SNARECXXSRC:=$(foreach dir, $(SNARE_DIRS), $(filter $(dir)/%, $(CXXSRC)))
HANDLERCSRC:=$(foreach dir, $(HANDLER_DIRS), $(filter $(dir)/%, $(CSRC)))
HANDLERCXXSRC:=$(foreach dir, $(HANDLER_DIRS), $(filter $(dir)/%, $(CXXSRC)))
POLTESTCSRC:=$(foreach dir, $(POLTEST_DIRS), $(filter $(dir)/%, $(CSRC)))
POLTESTCXXSRC:=$(foreach dir, $(POLTEST_DIRS), $(filter $(dir)/%, $(CXXSRC)))
NTLMHASHCSRC:=$(foreach dir, $(NTLMHASH_DIRS), $(filter $(dir)/%, $(CSRC)))
CUNITBASSDRUMCSRC:=$(foreach dir, $(CUNIT_BASSDRUM_DIRS), $(filter $(dir)/%, $(CSRC)))
CUNITBASSDRUMCXXSRC:=$(foreach dir, $(CUNIT_BASSDRUM_DIRS), $(filter $(dir)/%, $(CXXSRC)))
CUNITSNARECSRC:=$(foreach dir, $(CUNIT_SNARE_DIRS), $(filter $(dir)/%, $(CSRC)))
CUNITSNARECXXSRC:=$(foreach dir, $(CUNIT_SNARE_DIRS), $(filter $(dir)/%, $(CXXSRC)))
BONWARECSRC:=$(foreach dir, $(BONWARE_DIRS), $(filter $(dir)/%, $(CSRC)))
BONWARECXXSRC:=$(foreach dir, $(BONWARE_DIRS), $(filter $(dir)/%, $(CXXSRC)))
LIBBONCSRC:=$(foreach dir, $(LIBBON_DIRS), $(filter $(dir)/%, $(CSRC)))
LIBBONCXXSRC:=$(foreach dir, $(LIBBON_DIRS), $(filter $(dir)/%, $(CXXSRC)))

SNAREOBJS:=$(addprefix $(OBJOUT)/,$(SNARECXXSRC:%.cc=%.o) $(SNARECSRC:%.c=%.o))
HANDLEROBJS:=$(addprefix $(OBJOUT)/,$(HANDLERCXXSRC:%.cc=%.o) $(HANDLERCSRC:%.c=%.o))
POLTESTOBJS:=$(addprefix $(OBJOUT)/,$(filter-out $(APPSRCDIR)/$(SNARE)/$(SNARE).o,$(POLTESTCXXSRC:%.cc=%.o) $(POLTESTCSRC:%.c=%.o)))
#NTLMHASHOBJS:=$(addprefix $(OBJOUT)/,$(filter-out $(APPSRCDIR)/$(SNARE)/$(SNARE).o,$(NTLMHASHCSRC:%.c=%.o)))
NTLMHASHOBJS:=$(addprefix $(OBJOUT)/,$(NTLMHASH_DIR)/ntlmhash.o $(NTLM_UTIL_DIR)/ntlm_util.o)
CUNITBASSDRUMOBJS:=$(addprefix $(OBJOUT)/,$(filter-out $(APPSRCDIR)/$(SNARE)/$(SNARE).o,$(CUNITBASSDRUMCXXSRC:%.cc=%.o) $(CUNITBASSDRUMCSRC:%.c=%.o)))
CUNITSNAREOBJS:=$(addprefix $(OBJOUT)/,$(filter-out $(APPSRCDIR)/$(SNARE)/$(SNARE).o,$(CUNITSNARECXXSRC:%.cc=%.o) $(CUNITSNARECSRC:%.c=%.o)))
BONWAREOBJS:=$(addprefix $(OBJOUT)/,$(filter-out $(APPSRCDIR)/$(SNARE)/$(SNARE).o,$(BONWARECXXSRC:%.cc=%.o) $(BONWARECSRC:%.c=%.o)))
LIBBONOBJS:=$(addprefix $(OBJOUT)/,$(filter-out $(APPSRCDIR)/$(SNARE)/$(SNARE).o,$(LIBBONCXXSRC:%.cc=%.o) $(LIBBONCSRC:%.c=%.o)))

# -Wflags we can't use due to stupidity
#  -Wconversion (BSD headers choke for mode_t auuuuugh)
#  -Wpadded (lib/utils/rfc2396.h)
#  -Wpacked: scur anti-malware headers
# -Wflags we can't use due to gcc version:
#  -Winvalid-pch -Wold-style-definition
# -Wflags we can't use due to bugs in our code FIXME:
#  -Wstrict-aliasing=2
WXXFLAGS+=-Wall -W -Wundef -Wshadow -Wsign-compare -Wpointer-arith -Wcast-qual \
	-Wfloat-equal -Wdisabled-optimization -Wcast-align -Werror
WFLAGS:=$(WXXFLAGS) -Wmissing-declarations -Wbad-function-cast \
	-Wnested-externs -Wdeclaration-after-statement -Wmissing-prototypes \
	-Wstrict-prototypes -Wextra
DFLAGS+=-D_REENTRANT
IFLAGS+=-I$(APPSRCDIR) -I$(ERSATZ)
FFLAGS+=-O2 -fomit-frame-pointer -finline-functions -pipe -rdynamic -fpic

MFLAGS32+=-m32

IFLAGS:=$(THREAD_IFLAGS) $(DANKCFLAGS) $(IFLAGS)

PREPROCFLAGS:=$(DFLAGS) $(IFLAGS)
CFLAGS:=-std=gnu99 $(PREPROCFLAGS) $(FFLAGS) $(WFLAGS) $(SFCFLAGS) $(AMCFLAGS)
CFLAGS32:=-std=gnu99 $(PREPROCFLAGS) $(FFLAGS) $(MFLAGS32) $(WFLAGS) $(SFCFLAGS) $(AMCFLAGS)
CXXFLAGS:=$(PREPROCFLAGS) $(FFLAGS) $(WXXFLAGS)

SNARERNG:=$(SNARECONFDIR)/$(SNARE).rng
SNARECONF:=$(SNARECONFDIR)/$(SNARE).conf
CROSIERCONF:=$(CROSIERCONFDIR)/$(CROSIER).conf
BASSDRUMRNG:=$(BASSDRUMCONFDIR)/policy.rng
BASSDRUMCONF:=$(BASSDRUMCONFDIR)/policy.xml
ROOTCA:=$(BASSDRUMCONFDIR)/WebwasherRootCA.pem
CATEGORY_XML:=tools/category_data/catset.xml

default: test

all: default

# Required for Ports
POLICYKEY:=$(BASSDRUMCONFDIR)/policy.rsa
POLICYSSH:=$(BASSDRUMCONFDIR)/ssh_config
LOGROTATE:=$(BASSDRUMCONFDIR)/logrotate.conf
MIBFILES:=$(addprefix tools/mibs/,$(addsuffix -MIB.txt,SCC SCC-SNARE))
SNAREMAN:=doc/$(SNARE)/$(SNARE).8
INSTALL:=install -v
install: build $(POLICYKEY) $(POLICYSSH) $(SNAREMAN) $(SNARERNG) $(SNARECONF) $(BASSDRUMCONF) $(CROSIERCONF) $(BASSDRUMRNG) $(MIBFILES) $(ROOTCA) $(LOGROTATE)
	@[ -d $(PREFIX)/man/man8 ] || mkdir -m 0755 -p $(PREFIX)/man/man8
	@$(INSTALL) -m 0644 $(SNAREMAN) $(PREFIX)/man/man8
	@[ -d $(PREFIX)/lib ] || mkdir -m 0755 -p $(PREFIX)/lib
	@$(INSTALL) -m 0644 $(addprefix $(SNARELIBOUT)/,$(HANDLERLIB)) $(AMALWARE)/libscanm_p.so $(SFILTER)/libsfcontrol.so $(LIBBON) $(PREFIX)/lib
	@[ -d $(PREFIX)/bin ] || mkdir -m 0755 -p $(PREFIX)/bin
	@$(INSTALL) $(BINOUT)/$(BONWARE) $(PREFIX)/bin
	@[ -d $(PREFIX)/sbin ] || mkdir -m 0755 -p $(PREFIX)/sbin
	@$(INSTALL) $(BINOUT)/$(POLTEST) $(BINOUT)/$(SNARE) $(PREFIX)/sbin
	@$(INSTALL) $(addprefix sbin/$(SNARE)-,logdump shutdown snmp) $(PREFIX)/sbin
	@$(INSTALL) $(addprefix tools/,antimalware-download $(BASSDRUM)-dumpstate $(BASSDRUM)-reconfig $(BASSDRUM)-setup pull_policy swps-checksetup swps-health swps-triage update-fs-antimalware) $(PREFIX)/sbin
	@[ -d $(PREFIX)/etc/$(BASSDRUM) ] || mkdir -m 0755 -p $(PREFIX)/etc/$(BASSDRUM)
	@[ -d $(PREFIX)/etc/$(CROSIER) ] || mkdir -m 0755 -p $(PREFIX)/etc/$(CROSIER)
	@[ -d $(PREFIX)/etc/$(SNARE) ] || mkdir -m 0755 -p $(PREFIX)/etc/$(SNARE)
	@$(INSTALL) -m 0644 $(ROOTCA) $(POLICYSSH) $(LOGROTATE) $(PREFIX)/etc/$(BASSDRUM)
	@[ -d $(PREFIX)/share/examples/$(BASSDRUM) ] || mkdir -m 0755 -p $(PREFIX)/share/examples/$(BASSDRUM)
	@[ -d $(PREFIX)/share/examples/$(CROSIER) ] || mkdir -m 0755 -p $(PREFIX)/share/examples/$(CROSIER)
	@[ -d $(PREFIX)/share/examples/$(SNARE) ] || mkdir -m 0755 -p $(PREFIX)/share/examples/$(SNARE)
	@$(INSTALL) -m 0600 $(POLICYKEY) $(PREFIX)/share/examples/$(BASSDRUM)
	@$(INSTALL) -m 0644 $(BASSDRUMCONF) $(PREFIX)/share/examples/$(BASSDRUM)
	@$(INSTALL) -m 0644 $(CROSIERCONF) $(PREFIX)/share/examples/$(CROSIER)
	@$(INSTALL) -m 0644 $(SNARECONF) $(PREFIX)/share/examples/$(SNARE)
	@[ -d $(PREFIX)/share/snmp/mibs ] || mkdir -m 0755 -p $(PREFIX)/share/snmp/mibs
	@$(INSTALL) -m 0644 $(MIBFILES) $(PREFIX)/share/snmp/mibs
	@[ -d $(PREFIX)/share/xml/$(BASSDRUM) ] || mkdir -m 0755 -p $(PREFIX)/share/xml/$(BASSDRUM)
	@[ -d $(PREFIX)/share/xml/$(SNARE) ] || mkdir -m 0755 -p $(PREFIX)/share/xml/$(SNARE)
	@$(INSTALL) -m 0644 $(BASSDRUMRNG) $(PREFIX)/share/xml/$(BASSDRUM)
	@$(INSTALL) -m 0644 $(SNARERNG) $(PREFIX)/share/xml/$(SNARE)
	@[ -d $(PREFIX)/var/lib/$(BASSDRUM) ] || mkdir -m 0755 -p $(PREFIX)/var/lib/$(BASSDRUM)
	@[ -d $(PREFIX)/var/lib/$(BONWARE) ] || mkdir -m 0755 -p $(PREFIX)/var/lib/$(BONWARE)
	@cd unfree/antimalware/$(AMALWAREARCH)/updates && find . ! -path \*/.svn\* -print0 | cpio -0 -d -p -v --sparse -u --force-local $(PREFIX)/var/lib/$(BONWARE)/updates
	@[ -d $(PREFIX)/var/run/$(SNARE) ] || mkdir -m 0755 -p $(PREFIX)/var/run/$(SNARE)
	@[ -d $(PREFIX)/var/log/$(SNARE) ] || mkdir -m 0755 -p $(PREFIX)/var/log/$(SNARE)
	@[ -d $(PREFIX)/var/log/old$(SNARE) ] || mkdir -m 0755 -p $(PREFIX)/var/log/old$(SNARE)

deinstall:
	@rm -rf $(PREFIX)/man/man8/$(SNAREMAN)
	@rm -rf $(addprefix $(PREFIX)/bin/,$(BONWARE))
	@rm -rf $(addprefix $(PREFIX)/lib/,libscanm_p.so libsfcontrol.so $(notdir $(HANDLERLIB) $(LIBBON)))
	@rm -rf $(addprefix $(PREFIX)/sbin/$(SNARE)-,logdump shutdown snmp)
	@rm -rf $(addprefix $(PREFIX)/sbin/$(BASSDRUM)-,dumpstate reconfig setup)
	@rm -rf $(addprefix $(PREFIX)/sbin/,antimalware-download $(POLTEST) pull_policy $(SNARE) swps-checksetup swps-health swps-triage update-fs-antimalware)
	@rm -rf $(addprefix $(PREFIX)/share/examples/,$(BASSDRUM) $(CROSIER) $(SNARE))
	@rm -rf $(addprefix $(PREFIX)/etc/,$(BASSDRUM) $(CROSIER) $(SNARE))
	@rm -rf $(addprefix $(PREFIX)/var/,lib/$(BASSDRUM) lib/$(BONWARE) log/old$(SNARE) log/$(SNARE) run/$(SNARE))

TAGS:=.tags

build: $(TAGS) $(BIN) $(LIB)

SNARE_CFLAGS:=$(CFLAGS)
SNARE_LFLAGS:=-Wl,--enable-new-dtags $(DANKLFLAGS) $(THREAD_LFLAGS)
BDRUM_LFLAGS:=$(SNARE_LFLAGS) $(BONLFLAGS) $(SFLFLAGS) $(REPLFLAGS) $(PCRELFLAGS) -lssl -Wl,-R/usr/local/lib
$(BINOUT)/$(SNARE): $(SNAREOBJS) $(SFILTER)/libsfcontrol.so $(LIBBON)
	@[ -d $(@D) ] || mkdir -p $(@D)
	$(CXX) $(SNARE_CFLAGS) -o $@ $(SNAREOBJS) $(SNARE_LFLAGS) -Wl,-R/usr/local/lib

$(SNARELIBOUT)/$(HANDLERLIB): $(HANDLEROBJS)
	@[ -d $(@D) ] || mkdir -p $(@D)
	$(CXX) $(CFLAGS) -shared -o $@ $(HANDLEROBJS) $(BDRUM_LFLAGS)

BONWARE_CFLAGS:=$(CFLAGS32)
BONWARE_LFLAGS:=$(AMLFLAGS) $(DLSYMLFLAGS) $(THREAD_LFLAGS) -Wl,-R/usr/local/lib
$(BINOUT)/$(BONWARE): $(BONWAREOBJS)
	@[ -d $(@D) ] || mkdir -p $(@D)
	$(CC) $(BONWARE_CFLAGS) -o $@ $(BONWAREOBJS) $(BONWARE_LFLAGS)

LIBBON_CFLAGS:=$(CFLAGS) -shared
LIBBON_LFLAGS:=$(DANKLFLAGS) $(THREAD_LFLAGS)
$(LIBBON): $(LIBBONOBJS)
	@[ -d $(@D) ] || mkdir -p $(@D)
	$(CC) $(LIBBON_CFLAGS) -o $@ $(LIBBONOBJS) $(LIBBON_LFLAGS)

POLTEST_CFLAGS:=$(CFLAGS)
POLTEST_LFLAGS:=$(DANKLFLAGS) $(SFLFLAGS) $(THREAD_LFLAGS) $(PCRELFLAGS) -lssl
$(BINOUT)/$(POLTEST): $(POLTESTOBJS) $(SFILTER)/libsfcontrol.so
	@[ -d $(@D) ] || mkdir -p $(@D)
	$(CXX) $(POLTEST_CFLAGS) -o $@ $(POLTESTOBJS) $(POLTEST_LFLAGS)

NTLMHASH_CFLAGS:=$(CFLAGS)
NTLMHASH_LFLAGS:=$(DANKLFLAGS) -lssl
$(BINOUT)/$(NTLMHASH): $(NTLMHASHOBJS)
	@[ -d $(@D) ] || mkdir -p $(@D)
	$(CC) $(NTLMHASH_CFLAGS) -o $@ $(NTLMHASHOBJS) $(NTLMHASH_LFLAGS)

CUNIT_CFLAGS:=$(CFLAGS) -shared
$(LIBOUT)/$(CUNIT)-$(SNARE).so: $(CUNITSNAREOBJS)
	@[ -d $(@D) ] || mkdir -p $(@D)
	$(CXX) $(CUNIT_CFLAGS) -o $@ $(CUNITSNAREOBJS) $(SNARE_LFLAGS)

$(LIBOUT)/$(CUNIT)-$(BASSDRUM).so: $(CUNITBASSDRUMOBJS) $(SFILTER)/libsfcontrol.so $(LIBBON)
	@[ -d $(@D) ] || mkdir -p $(@D)
	$(CXX) $(CUNIT_CFLAGS) -o $@ $(CUNITBASSDRUMOBJS) $(BDRUM_LFLAGS)

# Object files which need particular flags
$(OBJOUT)/$(APPSRCDIR)/$(SNARE)/$(SNARE).o: $(APPSRCDIR)/$(SNARE)/$(SNARE).c $(INC)
	@[ -d $(@D) ] || mkdir -p $(@D)
	$(CC) -DAPPNAME=\"$(SNARE)\" $(SNARE_CFLAGS) -c $< -o $@

$(OBJOUT)/$(APPSRCDIR)/$(SNARE)/version.o: $(VERSIONSRC) $(INC) $(ERSATZ)/svn.h
	@[ -d $(@D) ] || mkdir -p $(@D)
	$(CC) -DVERSION=\"$(PROD_VER)\" $(CFLAGS) -c -o $@ $<

# Generic rules for object files
$(OBJOUT)/$(APPSRCDIR)/$(BONWARE)/%.o: $(APPSRCDIR)/$(BONWARE)/%.c $(INC)
	@[ -d $(@D) ] || mkdir -p $(@D)
	$(CC) $(CFLAGS32) -c $< -o $@

$(OBJOUT)/%.o: %.c $(INC)
	@[ -d $(@D) ] || mkdir -p $(@D)
	$(CC) $(CFLAGS) -c $< -o $@

# xxx It's quite ugly to make all cpp files dependent on the catstring include
$(OBJOUT)/%.o: %.cc $(INC) $(ERSATZ)/sf_catstrings.inc
	@[ -d $(@D) ] || mkdir -p $(@D)
	$(CXX) $(CXXFLAGS) -c $< -o $@

$(OBJOUT)/%.s: %.c $(INC)
	@[ -d $(@D) ] || mkdir -p $(@D)
	$(CC) $(CFLAGS) -S $< -o $@

$(OBJOUT)/%.i: %.c $(INC)
	@[ -d $(@D) ] || mkdir -p $(@D)
	$(CC) $(CFLAGS) -E $< -o $@

TEST_DATA:=testing
MODULE:=$(shell pwd)/$(SNARELIBOUT)/$(HANDLERLIB)
SHITTYTESTER:=$(TEST_DATA)/$(BINDIR)/shittytester
fulltest: test $(SHITTYTESTER) sfiltertest
	$(SHITTYTESTER) http://svn.research.sys/mediawiki/index.php/Main_Page - 100 $(MODULE)
	#export MALLOC_CHECK_=2 SNARE=$(BINOUT)/$(SNARE) && . $(CROSIERCONF) && $(CUNIT) $(addprefix -o ,$(UNITTESTLIB)) -c $(TEST_DATA) -a -f
	$(BINOUT)/$(BONWARE) $(shell pwd)/$(AMALWARE)/updates $(BINOUT)/$(BONWARE) $(wildcard $(TEST_DATA)/eicar/*)

TESTAUX:=$(TEST_DATA)/$(SNARECONFDIR)/$(SNARE).conf $(TEST_DATA)/$(BASSDRUMCONF) $(TEST_DATA)/updates $(TEST_DATA)/bin/bontool $(TEST_DATA)/$(OUT)
test: build $(TEST_DEPDOTFILE) $(TESTAUX) $(SNARERNG) $(SHITTYTESTER)
	$(XMLBIN) val -e -r $(BASSDRUMRNG) $(TEST_DATA)/$(BASSDRUMCONF)
	$(XMLBIN) val -e -r $(SNARERNG) $(TEST_DATA)/$(SNARECONFDIR)/$(SNARE).conf
	env LD_LIBRARY_PATH=$(shell pwd)/$(SFILTER):$$LD_LIBRARY_PATH $(BINOUT)/$(POLTEST) $(TEST_DATA)/$(BASSDRUMCONF)
	export MALLOC_CHECK_=2 LD_LIBRARY_PATH=$(shell pwd)/$(AMALWARE):$(shell pwd)/$(LIBOUT):$(shell pwd)/$(SFILTER):$$LD_LIBRARY_PATH SNARE=$(BINOUT)/$(SNARE) && . $(CROSIERCONF) && $(CUNIT) $(addprefix -o ,$(UNITTESTLIB)) -c $(TEST_DATA) -a

sfiltertest: $(SFILTER)/test/control_test/run_self_tests.sh
	#FIXME need a sfcontrol file in $(SFILTER)/test/control_test
	#cd $(SFILTER)/test/control_test && ./run_self_tests.sh ../../../../../../$(TEST_DATA)/sfilter

$(SFILTER)/test/control_test/run_self_tests.sh: FORCE
	cd $(SFILTER)/test/control_test && $(MAKE) all

$(TEST_DATA)/$(OUT): $(OUT)
	@[ -d $(@D) ] || mkdir -p $(@D)
	ln -fsn $(shell pwd)/$< $@

$(TEST_DATA)/bin/bontool: $(BINOUT)/$(BONWARE)
	@[ -d $(@D) ] || mkdir -p $(@D)
	ln -vfsn $(shell pwd)/$< $@

$(TEST_DATA)/updates: unfree/antimalware/$(AMALWAREARCH)/updates
	@[ -d $(@D) ] || mkdir -p $(@D)
	ln -vfsn $(shell pwd)/$< $@

$(TEST_DATA)/$(SNARECONFDIR)/$(SNARE).conf: $(SNARECONF)
	@[ -d $(@D) ] || mkdir -p $(@D)
	ln -vfsn $(shell pwd)/$< $@

$(TEST_DATA)/$(BASSDRUMCONF): $(BASSDRUMCONF)
	@[ -d $(@D) ] || mkdir -p $(@D)
	ln -vfsn $(shell pwd)/$< $@

$(TAGS): $(MAKEFILE) $(CSRC) $(CXXSRC) $(EXTSRC) $(INC)
	@[ -d $(@D) ] || mkdir -p $(@D)
	$(TAGBIN) -f $@ $^

$(SFILTER)/libsfcontrol.so: FORCE
	cd $(SFILTER) && $(MAKE) link

# Generated code lives in $(ERSATZ)
# Category names
$(ERSATZ)/sf_catstrings.inc: $(CATEGORY_XML)
	@[ -d $(@D) ] || mkdir -p $(@D)
	tools/category_data/transform_xml_for_cc.py $< $@

$(ERSATZ)/svn.h: FORCE
	@[ -d $(@D) ] || mkdir -p $(@D)
	echo "\"$(SVNREVISION)\"" > $@

clean:
	svn --xml --no-ignore status | $(XMLBIN) sel -t -m //entry -i "wc-status[@item='ignored']" -v @path -n | grep -v $(TAGS) | xargs rm -rvf
	cd $(SFILTER) && $(MAKE) cleanall

mrproper: clean
	rm -vf $(TAGS)
