#!/usr/bin/env perl

use strict;
use warnings;

use Test::More;

my $IGNORE_MODULES = qr{^$};


=begin internal note

Test Numbering:

  0xx: init
  1xx: external extras
  2xx: base class(es)
  3xx: output
  4xx: checks base & helper classes
  5xx: checks phase 1
  6xx: 
  7xx: 
  8xx: Bugs
  9xx: Style etc

=cut



#
# Lade-Tests überspringen, wenn wir unter Devel::Cover laufen
# Das ist sehr langsam, insbesondere unter Windows
# Und bringt nicht wirklich etwas, da die MOdule auch später noch geladen werden.
#

#if ( $INC{'Devel/Cover.pm'} )
#   {
#   Test::More::plan( skip_all => "Skip the load tests with 'testcover'(Devel::Cover)!" );
#   }


eval "use Test::Pod::Coverage 1.04";

if ($@)
   {
   diag "Need Test::Pod::Coverage to find all modules automatically...";
   plan tests => 1;
   use_ok('Security::TLSCheck');
   }
else
   {
   my @modules = grep { not $_ =~ $IGNORE_MODULES } all_modules();
   plan tests => scalar @modules;
   use_ok($_) for @modules;
   }                                               

