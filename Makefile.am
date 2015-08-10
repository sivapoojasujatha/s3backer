
#
# s3backer - FUSE-based single file backing store via Amazon S3
# 
# Copyright 2008-2011 Archie L. Cobbs <archie@dellroad.org>
# 
# This program is free software; you can redistribute it and/or
# modify it under the terms of the GNU General Public License
# as published by the Free Software Foundation; either version 2
# of the License, or (at your option) any later version.
# 
# This program is distributed in the hope that it will be useful,
# but WITHOUT ANY WARRANTY; without even the implied warranty of
# MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
# GNU General Public License for more details.
# 
# You should have received a copy of the GNU General Public License
# along with this program; if not, write to the Free Software
# Foundation, Inc., 51 Franklin Street, Fifth Floor, Boston, MA
# 02110-1301, USA.
#

bin_PROGRAMS=       cloudbacker

noinst_PROGRAMS=    tester

noinst_HEADERS=     cloudbacker.h \
			block_cache.h \
			block_part.h \
			dcache.h \
			ec_protect.h \
			erase.h \
			fuse_ops.h \
			hash.h \
                        gsb_http_io.h \
                        s3b_http_io.h \
			reset.h \
			test_io.h \
			cloudbacker_config.h \
			auth_conf.h \
			http_gio.h 

man_MANS=           cloudbacker.1

docdir=             $(datadir)/doc/packages/$(PACKAGE)

doc_DATA=           CHANGES COPYING README INSTALL TODO

EXTRA_DIST=         CHANGES s3backer.1 s3backer.spec

cloudbacker_SOURCES=   main.c \
		    block_cache.c \
		    block_part.c \
		    dcache.c \
		    ec_protect.c \
		    erase.c \
		    fuse_ops.c \
		    hash.c \
		    reset.c \
		    cloudbacker_config.c \
		    test_io.c \
		    gitrev.c \
		    http_gio.c

tester_SOURCES=     tester.c \
		    block_cache.c \
		    block_part.c \
		    dcache.c \
		    ec_protect.c \
		    erase.c \
		    hash.c \
		    reset.c \
		    cloudbacker_config.c \
		    test_io.c \
		    gitrev.c \
		    http_gio.c

AM_CFLAGS=          $(FUSE_CFLAGS)

SUBDIRS=            debian

gitrev.c:
			printf 'const char *const cloudbacker_version = "%s";\n' "`git describe`" > gitrev.c

