#!/usr/bin/env perl

use strict;
use warnings;
use FindBin qw($Bin);
use lib "$Bin/../lib";

#use Security::TLSCheck::App;
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

getstore( "https://wurzelgnom.a-blast.org/", "/dev/null" );



# this should be done already in the module?!? not sure ...
BEGIN
{
   eval "use Security::TLSCheck::Checks::$_;"
      foreach qw(DNS Web Mail Dummy CipherStrength MailCipherStrength AgeDE Heartbleed CipherStrengthOnlyValidCerts);
};


my $app = Security::TLSCheck::App::Parallel->new_with_options();
$app->run;
