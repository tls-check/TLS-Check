#!/usr/bin/env perl

use strict;
use warnings;
use FindBin qw($Bin);
use lib "$Bin/../lib";

#
# For usage see 
#   tls-check.pl --help!
#
# For a project overview, see the README.md of the Distribution.
#


#use Security::TLSCheck::App;
use Security::TLSCheck::App extends => "Security::TLSCheck::Result::CSV";

my $app = Security::TLSCheck::App->new_with_options();
$app->run;


