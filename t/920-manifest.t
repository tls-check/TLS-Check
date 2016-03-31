#!perl
use 5.006;
use strict;
use warnings FATAL => 'all';
use Test::More;

unless ( $ENV{RELEASE_TESTING} || $ENV{TEST_AUTHOR} )
   {
   plan( skip_all => "Author tests not required for installation (set TEST_AUTHOR)" );
   }

my $min_tcm = 0.9;
eval "use Test::CheckManifest $min_tcm";
plan skip_all => "Test::CheckManifest $min_tcm required" if $@;

ok_manifest();
