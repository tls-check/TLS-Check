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

use Security::TLSCheck::App::Parallel extends => "Security::TLSCheck::Result::CSV";


# TODO: Hack: preload all SSL libraries / init internal states!
# Preload later required libraries (for parallel fork mode)
use HTTP::Response;
use HTTP::Request;
use LWP::Protocol::https;
use LWP::Protocol::http;
use Mozilla::CA;
use IO::Socket::SSL;
use LWP::Simple;
use Net::SMTP;

use Net::SSL::CipherSuites;
use Net::SSL::Handshake;
use Net::SSL::GetServerProperties;

# Hack: do an SSL request: LWP should preload all modules.
# TODO: Remove and use everything manually.
getstore( "https://wurzelgnom.a-blast.org/", "/dev/null" );


my $app = Security::TLSCheck::App::Parallel->new_with_options();
$app->run;
