#!/bin/sh

#
# Script to clean out generated GNU auto* gunk.
#

set -e

echo "cleaning up"
rm -rf autom4te*.cache scripts aclocal.m4 configure config.log config.status .deps stamp-h1
rm -f config.h.in config.h.in~ config.h
rm -f scripts TAGS
find . \( -name Makefile -o -name Makefile.in \) -print0 | xargs -0 rm -f
rm -f gitrev.c cloudbacker.spec
rm -f *.o s3backer tester
rm -f s3backer-?.?.?.tar.gz

