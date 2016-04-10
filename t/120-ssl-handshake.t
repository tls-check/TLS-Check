#!/usr/bin/env perl

#
# Run a lot of tests with the SSL/TLS-Handshake
#
# TODO:
#  * allow different SSL/TLS implementations
#  * check cipher-suites / protocols of each implementation
#  * put all checks in subs and run them with all implementations
#  * ...
#

use 5.010;
use strict;
use warnings FATAL => 'all';
use Test::More;
use Test::Exception;
use Test::Deep;
use Test::Differences;
use English qw( -no_match_vars );
use IO::Socket::INET;
use IPC::Run qw(start);

use Data::Dumper;

my $server_port = 44300;
my $openssl     = "/Users/alvar/Documents/Code/externes/openssl-chacha/installdir/bin/openssl";
$openssl = "openssl" unless -x $openssl;

my $openssl_ciphers = qx($openssl ciphers);
diag $openssl_ciphers if $ENV{TRAVIS};


BEGIN
{
   plan tests => 215;
   use_ok( "Net::SSL::Handshake", ":all" );
   use_ok("Net::SSL::CipherSuites");
   use_ok("Net::SSL::GetServerProperties");
}



# TODO:
# check which cipher-suites are supported for later tests

throws_ok( sub { Net::SSL::Handshake->new(); }, qr(Attribute .ciphers. is required), "ciphers required" );


throws_ok( sub { my $s = Net::SSL::Handshake->new( ciphers => Net::SSL::CipherSuites->new )->socket; },
           qr(need parameter socket or host),
           "New Net::SSL::Handshake without socket or host etc" );

throws_ok(
   sub {
      my $s = Net::SSL::Handshake->new( host => "localhost", port => 12345, ciphers => Net::SSL::CipherSuites->new )->socket;
   },
   qr(Can't connect to),
   "New Net::SSL::Handshake without listening server"
         );


sub start_openssl
   {
   my $param = shift;

   my @cmd = ( $openssl, qw(s_server -quiet -cert t/ssl/server.pem), split( /[\s'"]+/, $param ) );
   my ( $in, $out, $err );
   my $run;
   lives_ok(
      sub {
         $run = start( \@cmd, \$in, \$out, \$err );
         return 1;
      },
      "Start OpenSSL-Server: $param"
           );

   sleep 1;
   $run->pump_nb;
   if ($err)
      {
      # diag "Error starting OpenSSL:\n$err";
      eval { stop_openssl($run) };
      return;
      }

   return $run;

   } ## end sub start_openssl

sub stop_openssl
   {
   my $run = shift;

   lives_ok( sub { $run->kill_kill; }, "Stop OpenSSL-Server OK." );
   return;
   }


my $handshake;
my $server = start_openssl("-www -accept $server_port -ssl2");
lives_ok(
   sub {
      $handshake = Net::SSL::Handshake->new(
                                             host        => "localhost",
                                             port        => $server_port,
                                             ciphers     => Net::SSL::CipherSuites->new_by_tag("SSLv2"),
                                             ssl_version => $SSLv2,
                                           );
   },
   "New Handshake Object"
        );

SKIP:
   {
   skip "Can't start OpenSSL with -ssl2", 14 unless $server;


   lives_ok( sub { my $socket = $handshake->socket; }, "Can get Socket for Handshake" );
   lives_ok( sub { $handshake->hello; }, "Hello!" );

   ok( $handshake->accepted_ciphers->count, "Some Ciphers accepted" );

   undef $handshake;
   lives_ok(
      sub {
         $handshake = Net::SSL::Handshake->new(
                            host    => "localhost",
                            port    => $server_port,
                            ciphers => Net::SSL::CipherSuites->new_by_name(qw(DES-CBC3-SHA DES-CBC3-MD5 RC2-CBC-MD5 EXP-RC4-MD5)),
                            ssl_version => $SSLv2,
         );
      },
      "Handshake Object, only some ciphers"
           );

   lives_ok( sub { $handshake->hello; }, "Hello, selected ciphers" );

   is( $handshake->accepted_ciphers->count, 3, "Some Ciphers accepted" );
   ok( $handshake->ok, "Handshake OK" );

   cmp_deeply( [ map { $ARG->{shortname} } @{ $handshake->accepted_ciphers->ciphers } ],
               [qw(DES-CBC3-MD5 RC2-CBC-MD5 EXP-RC4-MD5)],
               "Found Ciphers correct" );


   # try v3 connection with v2 ciphers

   undef $handshake;
   lives_ok(
      sub {
         $handshake = Net::SSL::Handshake->new(
                            host    => "localhost",
                            port    => $server_port,
                            ciphers => Net::SSL::CipherSuites->new_by_name(qw(DES-CBC3-SHA DES-CBC3-MD5 RC2-CBC-MD5 EXP-RC4-MD5)),
                            ssl_version => $SSLv3,
         );
      },
      "Handshake Object v3, only some v2 ciphers"
           );

   throws_ok( sub { $handshake->hello; }, qr(Can't use SSLv2-only Cipher), "Hello, selected ciphers" );
   ok( !$handshake->ok, "Handshake not OK" );


   # try v2 connection with v3 client and compatible ciphers

   undef $handshake;
   lives_ok(
      sub {
         $handshake = Net::SSL::Handshake->new(
                                                host        => "localhost",
                                                port        => $server_port,
                                                ciphers     => Net::SSL::CipherSuites->new_by_name(qw(IDEA-CBC-SHA NULL-MD5)),
                                                ssl_version => $SSLv3,
                                              );
      },
      "Handshake Object v3, v2/v3 compatible ciphers"
           );

   throws_ok( sub { $handshake->hello; }, qr(Nothing received), "Can't do SSLv3 Handshake to SSLv2 Server" );
   ok( !$handshake->ok, "Handshake not OK" );



   stop_openssl($server);

   } ## end SKIP:

#
# New server v2
#

$server = start_openssl("-www -accept $server_port -ssl2 -cipher 'DES-CBC3-MD5:RC2-CBC-MD5:EXP-RC4-MD5'");

undef $handshake;

lives_ok(
   sub {
      $handshake = Net::SSL::Handshake->new(
                                             host        => "localhost",
                                             port        => $server_port,
                                             ciphers     => Net::SSL::CipherSuites->new_by_tag("SSLv2"),
                                             ssl_version => $SSLv2,
                                           );
   },
   "Handshake Object, allowed all v2-Ciphers"
        );

SKIP:
   {
   skip "Can't start OpenSSL with -ssl2 -cipher 'DES-CBC3-MD5:RC2-CBC-MD5:EXP-RC4-MD5'", 3 unless $server;


   lives_ok( sub { $handshake->hello; }, "Hello, selected ciphers" );

   is( $handshake->accepted_ciphers->count, 3, "Correct number of Ciphers accepted" );
   $handshake->accepted_ciphers->order_by_code;

   cmp_deeply( [ map { $ARG->{shortname} } @{ $handshake->accepted_ciphers->ciphers } ],
               [qw(EXP-RC4-MD5 RC2-CBC-MD5 DES-CBC3-MD5)],
               "From all SSLv2 ciphers find only accepted" );



   stop_openssl($server);

   }

#
# SSLv3 server
#

$server = start_openssl("-www -accept $server_port -ssl3");

undef $handshake;

lives_ok(
   sub {
      $handshake = Net::SSL::Handshake->new(
                                             host        => "localhost",
                                             port        => $server_port,
                                             ciphers     => Net::SSL::CipherSuites->new_by_tag("SSLv3"),
                                             ssl_version => $SSLv3,
                                           );
   },
   "Handshake Object, allowed all v3-Ciphers"
        );
SKIP:
   {
   skip "Can't start OpenSSL with -ssl3", 2 unless $server;


   lives_ok( sub { $handshake->hello; }, "Hello, SSLv3" );

   ok( $handshake->accepted_ciphers->count, "Some Ciphers accepted" );

   stop_openssl($server);

   }

$server
   = start_openssl(
   "-www -accept $server_port -ssl3 -cipher 'ECDHE-RSA-AES256-GCM-SHA384:ECDHE-ECDSA-AES256-GCM-SHA384:ECDHE-RSA-AES256-SHA384:EDH-DSS-DES-CBC-SHA:DH-RSA-DES-CBC-SHA:DH-DSS-DES-CBC-SHA:DES-CBC-SHA'"
   );

undef $handshake;

lives_ok(
   sub {
      $handshake = Net::SSL::Handshake->new(
                                             host        => "localhost",
                                             port        => $server_port,
                                             ciphers     => Net::SSL::CipherSuites->new_by_tag("CAMELLIA"),
                                             ssl_version => $SSLv3,
                                           );
   },
   "Handshake Object, only Camellia Ciphers"
        );

SKIP:
   {
   skip
      "Can't start OpenSSL with -ssl3 -cipher 'ECDHE-RSA-AES256-GCM-SHA384:ECDHE-ECDSA-AES256-GCM-SHA384:ECDHE-RSA-AES256-SHA384:EDH-DSS-DES-CBC-SHA:DH-RSA-DES-CBC-SHA:DH-DSS-DES-CBC-SHA:DES-CBC-SHA'",
      11
      unless $server;

   lives_ok( sub { $handshake->hello; }, "Hello SSLv3, but without acceptable ciphers" );

   #diag Dumper $handshake;

   is( $handshake->accepted_ciphers->count, 0, "0 Ciphers accepted" );
   ok( $handshake->alert,           "Alert-Flag set" );
   ok( $handshake->no_cipher_found, "no_cipher_found-Flag set" );
   ok( !$handshake->ok,             "Handshake not OK" );


   #
   # SSLv2 client to v3 server
   #

   undef $handshake;
   lives_ok(
      sub {
         $handshake = Net::SSL::Handshake->new(
                                                host        => "localhost",
                                                port        => $server_port,
                                                ciphers     => Net::SSL::CipherSuites->new_by_tag("SSLv2"),
                                                ssl_version => $SSLv2,
                                              );
      },
      "Handshake Object, SSLv2 (for v3 server)"
           );

   throws_ok( sub { $handshake->hello; }, qr(), "Hello SSLv2 to v3 server" );


   undef $handshake;
   lives_ok(
      sub {
         $handshake = Net::SSL::Handshake->new(
                                                host        => "localhost",
                                                port        => $server_port,
                                                ciphers     => Net::SSL::CipherSuites->new_by_tag(qw(SSLv3 TLSv12)),
                                                ssl_version => $TLSv12,
                                              );
      },
      "Handshake Object, TLSv12 (for v3 server)"
           );

   lives_ok( sub { $handshake->hello; }, "Hello TLSv12 to v3 server" );

   TODO:
      {
      # TODO: check wich is the right/wrong result
      # with some openSSL it is OK, with others not ...
      local $TODO = "Looks like this is dependant of OpenSSL version; check it!";
      ok( $handshake->accepted_ciphers->count, "Cipher accepted" );
      }
   is( $handshake->server_version, $SSLv3, "Server is SSLv3 server" );

   stop_openssl($server);

   } ## end SKIP:

#
# Start TLSv12 Server
# With bettercrypto ciphers
#

$server
   = start_openssl(
   "-www -accept $server_port -tls1_2 -cipher 'DHE-RSA-AES256-GCM-SHA384:DHE-RSA-AES256-SHA256:ECDHE-RSA-AES256-GCM-SHA384:ECDHE-RSA-AES256-SHA384'"
   );

undef $handshake;
lives_ok(
   sub {
      $handshake = Net::SSL::Handshake->new(
                                             host        => "localhost",
                                             port        => $server_port,
                                             ciphers     => Net::SSL::CipherSuites->new_by_tag(qw(bettercrypto_a)),
                                             ssl_version => $TLSv12,
                                           );
   },
   "Handshake Object, TLSv12, bettercrypto a cipher suites"
        );


SKIP:
   {
   skip
      "Can't start OpenSSL with -tls1_2 -cipher 'DHE-RSA-AES256-GCM-SHA384:DHE-RSA-AES256-SHA256:ECDHE-RSA-AES256-GCM-SHA384:ECDHE-RSA-AES256-SHA384'",
      9
      unless $server;



   lives_ok( sub { $handshake->hello; }, "TLSv12 Handshake to TLSv12 Server with bettercrypto A ..." );

   ok( $handshake->accepted_ciphers->count, "Cipher accepted" );
   is( $handshake->server_version, $TLSv12, "Server is TLSv12 server" );
   ok( $handshake->ok, "Handshake OK" );



   # Check connection with SSLv3 client
   undef $handshake;
   lives_ok(
      sub {
         $handshake = Net::SSL::Handshake->new(
                                           host    => "localhost",
                                           port    => $server_port,
                                           ciphers => Net::SSL::CipherSuites->new_by_tag(qw(SSLv3 bettercrypto_b bettercrypto_a)),
                                           ssl_version => $SSLv3,
         );
      },
      "Handshake Object, TLSv12, bettercrypto a cipher suites"
           );

   lives_ok( sub { $handshake->hello; }, "SSLv3 Handshake to TLSv12 Server with  ..." );

   is( $handshake->accepted_ciphers->count, 0,      "Cipher not accepted" );
   is( $handshake->server_version,          $SSLv3, "TLS-Server responds SSLv3" );
   ok( !$handshake->ok, "Handshake not OK" );


   stop_openssl($server);

   } ## end SKIP:

#
# new TLS 1.2, TLS 1.1, TLS 1.0 server with standard cipher suites
#

$server = start_openssl("-www -accept $server_port -tls1 -tls1_1 -tls1_2");

# client betterrypto A TLS 1.2
undef $handshake;
lives_ok(
   sub {
      $handshake = Net::SSL::Handshake->new(
                                           host    => "localhost",
                                           port    => $server_port,
                                           ciphers => Net::SSL::CipherSuites->new_by_tag(qw(SSLv3 TLSv12 bettercrypto_b))->unique,
                                           ssl_version => $TLSv12,
      );
   },
   "Handshake Object, TLSv12, bettercrypto a cipher suites"
        );


SKIP:
   {
   skip "Can't start OpenSSL with -tls1 -tls1_1 -tls1_2", 24
      unless $server;


   lives_ok( sub { $handshake->hello; }, "TLSv12 Handshake to TLSv12 Server with bettercrypto A ..." );

   ok( $handshake->accepted_ciphers->count, "Cipher accepted" );
   is( $handshake->server_version, $TLSv12, "Server is TLSv12 server" );
   ok( $handshake->ok, "Handshake OK" );


   # client SSLv3, and bettercrypto ciphers; but TLS 1.2 server
   undef $handshake;
   lives_ok(
      sub {
         $handshake = Net::SSL::Handshake->new(
                                           host    => "localhost",
                                           port    => $server_port,
                                           ciphers => Net::SSL::CipherSuites->new_by_tag(qw(SSLv3 TLSv12 bettercrypto_b))->unique,
                                           ssl_version => $SSLv3,
         );
      },
      "Handshake Object, TLSv12"
           );

   lives_ok( sub { $handshake->hello; }, "SSLv3 Handshake to TLSv12 Server with  ..." );

   is( $handshake->accepted_ciphers->count, 0,      "Cipher not accepted" );
   is( $handshake->server_version,          $SSLv3, "TLS-Server responds SSLv3" );
   ok( !$handshake->ok, "Handshake not OK for SSLv3 client to TLS 1.2 only server" );



   # Client tls 1.0,
   undef $handshake;
   lives_ok(
      sub {
         $handshake = Net::SSL::Handshake->new(
                                           host    => "localhost",
                                           port    => $server_port,
                                           ciphers => Net::SSL::CipherSuites->new_by_tag(qw(SSLv3 TLSv12 bettercrypto_b))->unique,
                                           ssl_version => $TLSv1,
         );
      },
      "Handshake Object, TLSv1"
           );

   lives_ok( sub { $handshake->hello; }, "TLSv1 Handshake to TLSv12 Server" );

   is( $handshake->accepted_ciphers->count, 0,      "Cipher not accepted" );
   is( $handshake->server_version,          $TLSv1, "TLS-Server responds TLSv1" );
   ok( !$handshake->ok,
       "Handshake NOT OK for TLSv1 client to TLS 1.2/1.1/1.0 server (seems that openssl does not support this)" );


   # Client TLS 1.1

   undef $handshake;
   lives_ok(
      sub {
         $handshake = Net::SSL::Handshake->new(
                                           host    => "localhost",
                                           port    => $server_port,
                                           ciphers => Net::SSL::CipherSuites->new_by_tag(qw(SSLv3 TLSv12 bettercrypto_b))->unique,
                                           ssl_version => $TLSv11,
         );
      },
      "Handshake Object, TLSv1, bettercrypto a cipher suites"
           );

   lives_ok( sub { $handshake->hello; }, "TLSv11 Handshake to TLSv12 Server with  ..." );

   is( $handshake->accepted_ciphers->count, 0,       "Cipher not accepted" );
   is( $handshake->server_version,          $TLSv11, "TLS-Server responds TLSv11" );
   ok( !$handshake->ok,
       "Handshake NOT OK for TLSv11 client to TLS 1.2/1.1/1.0 server  (seems that openssl does not support this)" );


   # Client TLS 1.2

   undef $handshake;
   lives_ok(
      sub {
         $handshake = Net::SSL::Handshake->new(
                                           host    => "localhost",
                                           port    => $server_port,
                                           ciphers => Net::SSL::CipherSuites->new_by_tag(qw(SSLv3 TLSv12 bettercrypto_b))->unique,
                                           ssl_version => $TLSv12,
         );
      },
      "Handshake Object, TLSv1, bettercrypto a cipher suites"
           );

   lives_ok( sub { $handshake->hello; }, "TLSv12 Handshake to TLSv12 Server with  ..." );

   is( $handshake->accepted_ciphers->count, 1,       "Cipher accepted" );
   is( $handshake->server_version,          $TLSv12, "TLS-Server responds TLSv12" );
   ok( $handshake->ok, "Handshake  OK for TLSv12 client to TLS 1.2 only server" );


   stop_openssl($server);

   } ## end SKIP:

#
# new TLS 1.2 only server with standard cipher suites
#

$server = start_openssl("-www -accept $server_port -tls1_2");

# client betterrypto A TLS 1.2
undef $handshake;
lives_ok(
   sub {
      $handshake = Net::SSL::Handshake->new(
                                             host        => "localhost",
                                             port        => $server_port,
                                             ciphers     => Net::SSL::CipherSuites->new_by_tag(qw(bettercrypto_a)),
                                             ssl_version => $TLSv12,
                                           );
   },
   "Handshake Object, TLSv12, bettercrypto a cipher suites"
        );


SKIP:
   {
   skip "Can't start OpenSSL with  -tls1_2", 24
      unless $server;

   lives_ok( sub { $handshake->hello; }, "TLSv12 Handshake to TLSv12 Server with bettercrypto A ..." );

   ok( $handshake->accepted_ciphers->count, "Cipher accepted" );
   is( $handshake->server_version, $TLSv12, "Server is TLSv12 server" );
   ok( $handshake->ok, "Handshake OK" );


   # client SSLv3, and bettercrypto ciphers; but TLS 1.2 server
   undef $handshake;
   lives_ok(
      sub {
         $handshake = Net::SSL::Handshake->new(
                                           host    => "localhost",
                                           port    => $server_port,
                                           ciphers => Net::SSL::CipherSuites->new_by_tag(qw(SSLv3 TLSv12 bettercrypto_b))->unique,
                                           ssl_version => $SSLv3,
         );
      },
      "Handshake Object, TLSv12"
           );

   lives_ok( sub { $handshake->hello; }, "SSLv3 Handshake to TLSv12 Server with  ..." );

   is( $handshake->accepted_ciphers->count, 0,      "Cipher not accepted" );
   is( $handshake->server_version,          $SSLv3, "TLS-Server responds SSLv3" );
   ok( !$handshake->ok, "Handshake not OK for SSLv3 client to TLS 1.2 only server" );



   # Client tls 1.0,
   undef $handshake;
   lives_ok(
      sub {
         $handshake = Net::SSL::Handshake->new(
                                           host    => "localhost",
                                           port    => $server_port,
                                           ciphers => Net::SSL::CipherSuites->new_by_tag(qw(SSLv3 TLSv12 bettercrypto_b))->unique,
                                           ssl_version => $TLSv1,
         );
      },
      "Handshake Object, TLSv1, bettercrypto a cipher suites"
           );

   lives_ok( sub { $handshake->hello; }, "TLSv1 Handshake to TLSv12 Server with  ..." );

   is( $handshake->accepted_ciphers->count, 0,      "Cipher not accepted" );
   is( $handshake->server_version,          $TLSv1, "TLS-Server responds TLSv1" );
   ok( !$handshake->ok, "Handshake not OK for TLSv1 client to TLS 1.2 only server" );


   # Client TLS 1.1

   undef $handshake;
   lives_ok(
      sub {
         $handshake = Net::SSL::Handshake->new(
                                           host    => "localhost",
                                           port    => $server_port,
                                           ciphers => Net::SSL::CipherSuites->new_by_tag(qw(SSLv3 TLSv12 bettercrypto_b))->unique,
                                           ssl_version => $TLSv11,
         );
      },
      "Handshake Object, TLSv1, bettercrypto a cipher suites"
           );

   lives_ok( sub { $handshake->hello; }, "TLSv11 Handshake to TLSv12 Server with  ..." );

   is( $handshake->accepted_ciphers->count, 0,       "Cipher not accepted" );
   is( $handshake->server_version,          $TLSv11, "TLS-Server responds TLSv11" );
   ok( !$handshake->ok, "Handshake not OK for TLSv11 client to TLS 1.2 only server" );


   # Client TLS 1.2

   undef $handshake;
   lives_ok(
      sub {
         $handshake = Net::SSL::Handshake->new(
                                           host    => "localhost",
                                           port    => $server_port,
                                           ciphers => Net::SSL::CipherSuites->new_by_tag(qw(SSLv3 TLSv12 bettercrypto_b))->unique,
                                           ssl_version => $TLSv12,
         );
      },
      "Handshake Object, TLSv1, bettercrypto a cipher suites"
           );

   lives_ok( sub { $handshake->hello; }, "TLSv12 Handshake to TLSv12 Server with  ..." );

   is( $handshake->accepted_ciphers->count, 1,       "Cipher accepted" );
   is( $handshake->server_version,          $TLSv12, "TLS-Server responds TLSv12" );
   ok( $handshake->ok, "Handshake  OK for TLSv12 client to TLS 1.2 only server" );



   stop_openssl($server);

   } ## end SKIP:

##########################################################################################
#
# Checks for Net::SSL::GetServerProperties
#
##########################################################################################


$server = start_openssl("-www -accept $server_port -tls1_2");

my $prop;
lives_ok( sub { $prop = Net::SSL::GetServerProperties->new( host => "localhost", port => $server_port, ); },
          "New get Server Properties ..." );


SKIP:
   {
   skip "Can't start OpenSSL with -tls1_2", 22
      unless $server;

   lives_ok( sub { $prop->get_properties; }, "Run get all properties" );

   ok( $prop->supports_tlsv12,  "Supports TLS 1.2" );
   ok( !$prop->supports_tlsv11, "Does not support TLS 1.1" );
   ok( !$prop->supports_tlsv1,  "Does not support TLS 1.0" );
   ok( !$prop->supports_sslv3,  "Does not support SSLv3" );
   ok( !$prop->supports_sslv2,  "Does not support SSLv2" );

   ok( $prop->supports_any_bc_a,      "Supports at least any Bettercrypto A cipher suite" );
   ok( $prop->supports_any_bc_b,      "Supports at least any Bettercrypto B cipher suite" );
   ok( $prop->supports_any_bsi_pfs,   "Supports at least any BSI pfs cipher suite with PFS" );
   ok( $prop->supports_any_bsi_nopfs, "Supports at least any BSI (no) pfs cipher suite" );

   ok( !$prop->supports_only_bc_a,      "Does not support only Bettercrypto A cipher suites" );
   ok( !$prop->supports_only_bc_b,      "Does not support only Bettercrypto B cipher suites" );
   ok( !$prop->supports_only_bsi_pfs,   "Does not support only BSI pfs cipher suites with PFS" );
   ok( !$prop->supports_only_bsi_nopfs, "Does not support only BSI (no) pfs cipher suites" );


   TODO:
      {
      local $TODO = "Scores are changes, check new results";

      is( $prop->score,              35,  "Score for this server" );
      is( $prop->score_ciphersuites, 35,  "CipherSuites Score for this server" );
      is( $prop->score_tlsversion,   100, "TLS Version Score for this server" );

      }

   is( $prop->firefox_cipher,
       "ECDHE_RSA_WITH_AES_128_GCM_SHA256",
       "Firefox would use ECDHE_RSA_WITH_AES_128_GCM_SHA256 as cipher suite" );
   is( $prop->safari_cipher,
       "ECDHE_RSA_WITH_AES_256_CBC_SHA384",
       "Safari would use ECDHE_RSA_WITH_AES_256_CBC_SHA384 as cipher suite" );
   is( $prop->chrome_cipher,
       "ECDHE_RSA_WITH_AES_128_GCM_SHA256",
       "Chrome would use ECDHE_RSA_WITH_AES_128_GCM_SHA256 as cipher suite" );
   is( $prop->ie8win7_cipher,
       "ECDHE_RSA_WITH_AES_256_CBC_SHA",
       "IE 8 on Windows 7 would use ECDHE_RSA_WITH_AES_256_CBC_SHA as cipher suite" );
   is( $prop->ie11win10_cipher,
       "ECDHE_RSA_WITH_AES_256_GCM_SHA384",
       "IE 8 on Windows 7 would use ECDHE_RSA_WITH_AES_256_GCM_SHA384 as cipher suite" );

   stop_openssl($server);

   } ## end SKIP:

#
# Bettercrypto A
#

$server
   = start_openssl(
   "-www -accept $server_port -tls1_2 -cipher 'DHE-RSA-AES256-GCM-SHA384:DHE-RSA-AES256-SHA256:ECDHE-RSA-AES256-GCM-SHA384:ECDHE-RSA-AES256-SHA384'"
   );

undef $prop;
lives_ok( sub { $prop = Net::SSL::GetServerProperties->new( host => "localhost", port => $server_port, ); },
          "New get Server Properties ..." );


SKIP:
   {
   skip "Can't start OpenSSL with -tls1_2", 17
      unless $server;

   lives_ok( sub { $prop->get_properties; }, "Run get all properties" );

   ok( $prop->supports_tlsv12,  "Supports TLS 1.2" );
   ok( !$prop->supports_tlsv11, "Does not support TLS 1.1" );
   ok( !$prop->supports_tlsv1,  "Does not support TLS 1.0" );
   ok( !$prop->supports_sslv3,  "Does not support SSLv3" );
   ok( !$prop->supports_sslv2,  "Does not support SSLv2" );

   ok( $prop->supports_any_bc_a,      "Supports at least any Bettercrypto A cipher suite" );
   ok( $prop->supports_any_bc_b,      "Supports at least any Bettercrypto B cipher suite" );
   ok( $prop->supports_any_bsi_pfs,   "Supports at least any BSI pfs cipher suite with PFS" );
   ok( $prop->supports_any_bsi_nopfs, "Supports at least any BSI (no) pfs cipher suite" );

   ok( $prop->supports_only_bc_a,      "Support only Bettercrypto A cipher suites" );
   ok( $prop->supports_only_bc_b,      "Support only Bettercrypto B cipher suites" );
   ok( $prop->supports_only_bsi_pfs,   "Support only BSI pfs cipher suites with PFS" );
   ok( $prop->supports_only_bsi_nopfs, "Support only BSI (no) pfs cipher suites" );

   TODO:
      {
      local $TODO = "Changed score calculation ...";
      is( $prop->score, 100, "Score for this server" );
      }

   my @cipher_names = sort $prop->supported_cipher_names;
   my $cipher_names = [ sort @{ $prop->supported_cipher_names } ];

   # IANA Names! With CBC, missing in big list at CipherSuites.pm
   my @bc_a = qw(
      DHE_RSA_WITH_AES_256_GCM_SHA384
      DHE_RSA_WITH_AES_256_CBC_SHA256
      ECDHE_RSA_WITH_AES_256_GCM_SHA384
      ECDHE_RSA_WITH_AES_256_CBC_SHA384
      );

   # TODO:
   # travis fails with ECDHE_...
   TODO:
      {
      local $TODO = "Some OpenSSL-Vesions don't have ECDHE_RSA_WITH_AES_256...???"
         unless $openssl_ciphers =~ m{ECDHE-RSA-AES256};
      cmp_deeply( $cipher_names, [@cipher_names], "list/scalar context cipher names OK" );
      cmp_deeply( $cipher_names, bag(@bc_a), "Really only bettercrypto a ciphers" );
      }


   stop_openssl($server);

   } ## end SKIP:


#
# SSLv3 Server
#

$server = start_openssl("-www -accept $server_port -ssl3");

undef $prop;
lives_ok( sub { $prop = Net::SSL::GetServerProperties->new( host => "localhost", port => $server_port, ); },
          "New get Server Properties ..." );

SKIP:
   {
   skip "Can't start OpenSSL with -tls1_2", 15
      unless $server;

   lives_ok( sub { $prop->get_properties; }, "Run get all properties" );

   ok( !$prop->supports_tlsv12, "Does not support TLS 1.2" );
   ok( !$prop->supports_tlsv11, "Does not support TLS 1.1" );
   ok( !$prop->supports_tlsv1,  "Does not support TLS 1.0" );
   ok( $prop->supports_sslv3,   "Supports SSLv3" );
   ok( !$prop->supports_sslv2,  "Does not support SSLv2" );

   ok( !$prop->supports_any_bc_a,      "Does not support at least any Bettercrypto A cipher suite" );
   ok( $prop->supports_any_bc_b,       "Supports at least any Bettercrypto B cipher suite" );
   ok( !$prop->supports_any_bsi_pfs,   "Does not support at least any BSI pfs cipher suite with PFS" );
   ok( !$prop->supports_any_bsi_nopfs, "Does not support at least any BSI (no) pfs cipher suite" );

   ok( !$prop->supports_only_bc_a,      "Does not support only Bettercrypto A cipher suites" );
   ok( !$prop->supports_only_bc_b,      "Does not support only Bettercrypto B cipher suites" );
   ok( !$prop->supports_only_bsi_pfs,   "Does not support only BSI pfs cipher suites with PFS" );
   ok( !$prop->supports_only_bsi_nopfs, "Does not support only BSI (no) pfs cipher suites" );

   TODO:
      {
      local $TODO = "Changed score calculation ...";
      is( $prop->score, 0, "Score for this server" );
      }


   stop_openssl($server);

   } ## end SKIP:

#
# SSLv2 Server
#

$server = start_openssl("-www -accept $server_port -ssl2");

undef $prop;
lives_ok( sub { $prop = Net::SSL::GetServerProperties->new( host => "localhost", port => $server_port, ); },
          "New get Server Properties ..." );

SKIP:
   {
   skip "Can't start OpenSSL with -ssl2", 15
      unless $server;

   lives_ok( sub { $prop->get_properties; }, "Run get all properties" ) or diag "with Server $openssl";

   ok( !$prop->supports_tlsv12, "Does not support TLS 1.2" );
   ok( !$prop->supports_tlsv11, "Does not support TLS 1.1" );
   ok( !$prop->supports_tlsv1,  "Does not support TLS 1.0" );
   ok( !$prop->supports_sslv3,  "Does not support SSLv3" );
   ok( $prop->supports_sslv2,   "Supports SSLv2" );

   ok( !$prop->supports_any_bc_a,      "Does not support at least any Bettercrypto A cipher suite" );
   ok( !$prop->supports_any_bc_b,      "Does not support at least any Bettercrypto B cipher suite" );
   ok( !$prop->supports_any_bsi_pfs,   "Does not support at least any BSI pfs cipher suite with PFS" );
   ok( !$prop->supports_any_bsi_nopfs, "Does not support at least any BSI (no) pfs cipher suite" );

   ok( !$prop->supports_only_bc_a,      "Does not support only Bettercrypto A cipher suites" );
   ok( !$prop->supports_only_bc_b,      "Does not support only Bettercrypto B cipher suites" );
   ok( !$prop->supports_only_bsi_pfs,   "Does not support only BSI pfs cipher suites with PFS" );
   ok( !$prop->supports_only_bsi_nopfs, "Does not support only BSI (no) pfs cipher suites" );

   TODO:
      {
      local $TODO = "Changed score calculation ...";
      is( $prop->score, 0, "Score for this server" );
      }


   stop_openssl($server);

   } ## end SKIP:

#
# Check for the wrong "is BSI" filter (fixed bug)
#


my @ciphers = qw(
   AES128-GCM-SHA256
   AES128-SHA
   AES256-SHA
   ECDHE-RSA-AES128-GCM-SHA256
   ECDHE-RSA-AES256-SHA
   ECDHE-RSA-AES128-SHA
   RC4-SHA
   RC4-MD5
   DES-CBC3-SHA);

my $ciphers = join( ":", @ciphers );

$server = start_openssl("-www -accept $server_port -no_ssl2 -cipher '$ciphers'");



undef $prop;
lives_ok( sub { $prop = Net::SSL::GetServerProperties->new( host => "localhost", port => $server_port, ); },
          "New get Server Properties ..." );

SKIP:
   {
   skip "Can't start OpenSSL with -no_ssl2 -cipher '$ciphers'", 17
      unless $server;


   lives_ok( sub { $prop->get_properties; }, "Run get all properties" ) or diag "failed with Server $openssl";


   ok( $prop->supports_tlsv12, "Supports TLS 1.2" );
   ok( $prop->supports_tlsv11, "Supports TLS 1.1" );
   ok( $prop->supports_tlsv1,  "Supports TLS 1.0" );
   ok( $prop->supports_sslv3,  "Supports SSLv3" );
   ok( !$prop->supports_sslv2, "Does not support SSLv2" );

   ok( !$prop->supports_any_bc_a, "Does not support at least one Bettercrypto A cipher suite" );
   ok( $prop->supports_any_bc_b,  "Supports at least one Bettercrypto B cipher suite" );
   SKIP:
      {
      skip "This OpenSSL doesn't support ECDHE-RSA-AES256-Ciphers" unless $openssl_ciphers =~ m{ECDHE-RSA-AES256};
      ok( $prop->supports_any_bsi_pfs,   "Supports at least one  BSI pfs cipher suite with PFS" );
      ok( $prop->supports_any_bsi_nopfs, "Supports at least one BSI (no) pfs cipher suite" );
      }

   ok( !$prop->supports_only_bc_a,      "Does not support only Bettercrypto A cipher suites" );
   ok( !$prop->supports_only_bc_b,      "Does not support only Bettercrypto B cipher suites" );
   ok( !$prop->supports_only_bsi_pfs,   "Does not support only BSI pfs cipher suites with PFS" );
   ok( !$prop->supports_only_bsi_nopfs, "Does not support only BSI (no) pfs cipher suites" );

   ok( $prop->supports_weak,               "Supports weak cipher suites" );
   ok( !$prop->supports_only_bsi_versions, "Does not support only BSI allowed versions" );


   TODO:
      {
      local $TODO = "Changed score calculation ...";
      is( $prop->score, 0, "Score for this server" );
      }

   stop_openssl($server);

   } ## end SKIP:

done_testing();

