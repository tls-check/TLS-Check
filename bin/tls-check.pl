#!/usr/bin/env perl

use strict;
use warnings;
use FindBin qw($Bin);
use lib "$Bin/../lib";

#use Security::TLSCheck::App;
use Security::TLSCheck::App extends => "Security::TLSCheck::Result::CSV";

my $app = Security::TLSCheck::App->new_with_options();
$app->run;


