MAINTAINERCLEANFILES = $(srcdir)/Makefile.in

SUBDIRS = common keyconv util dump

if BUILD_MIGRATE
SUBDIRS += migrate
endif

SUBDIRS += test

EXTRA_DIST =	$(srcdir)/CMakeLists.txt \
		$(srcdir)/win32/*.cpp
