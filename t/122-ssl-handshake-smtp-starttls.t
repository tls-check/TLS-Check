#!/usr/bin/env perl

use 5.010;
use strict;
use warnings FATAL => 'all';
use Test::More;
use Test::Exception;
use Test::Deep;
use Test::Differences;

use English qw( -no_match_vars );

use Data::Dumper;

# plan tests => 1234;

use Net::SSL::Handshake qw(:all);
use Net::SSL::Handshake::StartTLS::SMTP;
use Net::SSL::GetServerProperties;



my $prop;

lives_ok(
   sub {
      $prop = Net::SSL::GetServerProperties->new(
                                                  host            => "mail.a-blast.org",
                                                  port            => 25,
                                                  handshake_class => "Net::SSL::Handshake::StartTLS::SMTP",
                                                );
   },
   "Net::SSL::GetServerProperties->new with handshake_class Net::SSL::Handshake::StartTLS::SMTP does not die"
        );

ok( $prop, "Server Properties object ..." );
lives_ok( sub { $prop->get_properties; }, "Run get all properties" );

ok( $prop->supports_tlsv12, "Supports TLS 1.2" );
ok( $prop->supports_tlsv11, "Supports TLS 1.1" );
ok( $prop->supports_tlsv1,  "Supports TLS 1.0" );
ok( $prop->supports_sslv3,  "Supports SSLv3" );    # uuuh, this server supports junky SSLv3.0 :/
ok( !$prop->supports_sslv2, "Supports SSLv2" );


# diag join " ", $prop->accepted_ciphers->names;


# Again:
#
#lives_ok(
#   sub {
#      $prop = Net::SSL::GetServerProperties->new(
#                                                  host            => "mail.a-blast.org",
#                                                  port            => 25,
#                                                  handshake_class => "Net::SSL::Handshake::StartTLS::SMTP",
#                                                );
#   },
#   "Net::SSL::GetServerProperties->new with handshake_class Net::SSL::Handshake::StartTLS::SMTP does not die"
#        );
#
#ok( $prop, "Server Properties object ..." );
#lives_ok( sub { $prop->get_properties; }, "Run get all properties" );
#
#ok( $prop->supports_tlsv12,  "Supports TLS 1.2" );
#ok( $prop->supports_tlsv11,  "Supports TLS 1.1" );
#ok( $prop->supports_tlsv1,  "Supports TLS 1.0" );
#
#
#diag join " ", $prop->accepted_ciphers->names;
#



#use Data::Dumper;
#$prop->ciphers_to_check->remove($prop->ciphers_to_check);
#diag Dumper $prop;



done_testing();



