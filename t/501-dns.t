#!/usr/bin/env perl

use 5.010;
use strict;
use warnings FATAL => 'all';
use Test::More;
use Test::Exception;
use Test::MockObject;
use Test::MockObject::Extends;
use Test::Differences;

use English qw( -no_match_vars );

use Log::Log4perl::EasyCatch;                      # initialises Logging!

plan tests => 139;


#
# All DNS Tests running on tls-check.alvar-freude.de
# which should be OK, but needs networking!
#

# Internal temp: when changing addresses set NS directly to avoid DNS cache
# TODO: wrong results without setting the authoritative Nameserver! Check why!
$ENV{RES_NAMESERVERS} = "nsa0.schlundtech.de";

#$ENV{RES_NAMESERVERS} = "8.8.8.8";


use_ok("Security::TLSCheck");
can_ok( "Security::TLSCheck", qw(domain) );

use_ok("Security::TLSCheck::Checks::DNS");
can_ok( "Security::TLSCheck::Checks::DNS", qw(run_check) );


#
# test the (manual) summary methods
#

sub create_check_with
   {
   my %params = @ARG;

   my $check = Security::TLSCheck::Checks::DNS->new( instance => Test::MockObject->new() );
   $check = Test::MockObject::Extends->new($check);
   $check->set_always( $ARG => $params{$ARG} ) foreach keys %params;

   return $check;
   }

# check if supports is OK
my $check = create_check_with( count_ipv4 => 1, count_ipv4_www => 1 );
ok( $check->supports_ipv4, "support IPv4, domain and www" );

$check = create_check_with( count_ipv4 => 0, count_ipv4_www => 2 );
ok( $check->supports_ipv4, "support IPv4, only www" );

$check = create_check_with( count_ipv4 => 3, count_ipv4_www => 0 );
ok( $check->supports_ipv4, "support IPv4, only domain" );

$check = create_check_with( count_ipv4 => 0, count_ipv4_www => 0 );
ok( !$check->supports_ipv4, "does not support IPv4" );


$check = create_check_with( count_ipv6 => 1, count_ipv6_www => 1 );
ok( $check->supports_ipv6, "support ipv6, domain and www" );

$check = create_check_with( count_ipv6 => 0, count_ipv6_www => 2 );
ok( $check->supports_ipv6, "support ipv6, only www" );

$check = create_check_with( count_ipv6 => 3, count_ipv6_www => 0 );
ok( $check->supports_ipv6, "support ipv6, only domain" );

$check = create_check_with( count_ipv6 => 0, count_ipv6_www => 0 );
ok( !$check->supports_ipv6, "does not support ipv6" );

# Only IPv4 OK
$check = create_check_with( count_ipv4 => 0, count_ipv4_www => 1, count_ipv6 => 0, count_ipv6_www => 0 );
ok( $check->only_ipv4, "does only support IPv4" );

$check = create_check_with( count_ipv4 => 1, count_ipv4_www => 1, count_ipv6 => 0, count_ipv6_www => 0 );
ok( $check->only_ipv4, "does only support IPv4 (2)" );

$check = create_check_with( count_ipv4 => 1, count_ipv4_www => 0, count_ipv6 => 0, count_ipv6_www => 0 );
ok( $check->only_ipv4, "does only support IPv4 (3)" );


$check = create_check_with( count_ipv4 => 0, count_ipv4_www => 1, count_ipv6 => 1, count_ipv6_www => 0 );
ok( !$check->only_ipv4, "does not only support IPv4" );

$check = create_check_with( count_ipv4 => 1, count_ipv4_www => 1, count_ipv6 => 1, count_ipv6_www => 0 );
ok( !$check->only_ipv4, "does not only support IPv4 (2)" );

$check = create_check_with( count_ipv4 => 1, count_ipv4_www => 0, count_ipv6 => 1, count_ipv6_www => 0 );
ok( !$check->only_ipv4, "does not only support IPv4 (3)" );


$check = create_check_with( count_ipv4 => 0, count_ipv4_www => 1, count_ipv6 => 0, count_ipv6_www => 1 );
ok( !$check->only_ipv4, "does not only support IPv4 (4)" );

$check = create_check_with( count_ipv4 => 1, count_ipv4_www => 1, count_ipv6 => 1, count_ipv6_www => 1 );
ok( !$check->only_ipv4, "does not only support IPv4 (5)" );

$check = create_check_with( count_ipv4 => 0, count_ipv4_www => 0, count_ipv6 => 0, count_ipv6_www => 1 );
ok( !$check->only_ipv4, "does not only support IPv4 (6)" );


# Only IPv6 OK
$check = create_check_with( count_ipv6 => 0, count_ipv6_www => 1, count_ipv4 => 0, count_ipv4_www => 0 );
ok( $check->only_ipv6, "does only support ipv6" );

$check = create_check_with( count_ipv6 => 1, count_ipv6_www => 1, count_ipv4 => 0, count_ipv4_www => 0 );
ok( $check->only_ipv6, "does only support ipv6 (2)" );

$check = create_check_with( count_ipv6 => 1, count_ipv6_www => 0, count_ipv4 => 0, count_ipv4_www => 0 );
ok( $check->only_ipv6, "does only support ipv6 (3)" );


$check = create_check_with( count_ipv6 => 0, count_ipv6_www => 1, count_ipv4 => 1, count_ipv4_www => 0 );
ok( !$check->only_ipv6, "does not only support ipv6" );

$check = create_check_with( count_ipv6 => 1, count_ipv6_www => 1, count_ipv4 => 1, count_ipv4_www => 0 );
ok( !$check->only_ipv6, "does not only support ipv6 (2)" );

$check = create_check_with( count_ipv6 => 1, count_ipv6_www => 0, count_ipv4 => 1, count_ipv4_www => 0 );
ok( !$check->only_ipv6, "does not only support ipv6 (3)" );


$check = create_check_with( count_ipv6 => 0, count_ipv6_www => 1, count_ipv4 => 0, count_ipv4_www => 1 );
ok( !$check->only_ipv6, "does not only support ipv6 (4)" );

$check = create_check_with( count_ipv6 => 1, count_ipv6_www => 1, count_ipv4 => 1, count_ipv4_www => 1 );
ok( !$check->only_ipv6, "does not only support ipv6 (5)" );

$check = create_check_with( count_ipv6 => 0, count_ipv6_www => 0, count_ipv4 => 0, count_ipv4_www => 1 );
ok( !$check->only_ipv6, "does not only support ipv6 (6)" );


# NS only v4 and v6

$check = create_check_with( count_ipv4_ns => 2, count_ipv6_ns => 0 );
ok( $check->only_ipv4_ns, "only IPv4 NS" );

$check = create_check_with( count_ipv4_ns => 2, count_ipv6_ns => 1 );
ok( !$check->only_ipv4_ns, "not only IPv4 NS" );


$check = create_check_with( count_ipv4_ns => 0, count_ipv6_ns => 1 );
ok( $check->only_ipv6_ns, "only IPv6 NS" );

$check = create_check_with( count_ipv4_ns => 2, count_ipv6_ns => 1 );
ok( !$check->only_ipv6_ns, "not only IPv6 NS" );


# MX only v4 and v6

$check = create_check_with( count_ipv4_mx => 2, count_ipv6_mx => 0 );
ok( $check->only_ipv4_mx, "only IPv4 mx" );

$check = create_check_with( count_ipv4_mx => 2, count_ipv6_mx => 1 );
ok( !$check->only_ipv4_mx, "not only IPv4 mx" );


$check = create_check_with( count_ipv4_mx => 0, count_ipv6_mx => 1 );
ok( $check->only_ipv6_mx, "only IPv6 mx" );

$check = create_check_with( count_ipv4_mx => 2, count_ipv6_mx => 1 );
ok( !$check->only_ipv6_mx, "not only IPv6 mx" );


# When neighter ipv4 nor ipv6 the only_ Methods return false!

$check = create_check_with( count_ipv4_ns => 0, count_ipv6_ns => 0 );
ok( !$check->only_ipv4_ns, "not only IPv4: neighter IPv4 nor IPv6 NS" );

$check = create_check_with( count_ipv4_ns => 0, count_ipv6_ns => 0 );
ok( !$check->only_ipv6_ns, "not only IPv6: neighter IPv4 nor IPv6 NS" );


$check = create_check_with( count_ipv4_mx => 0, count_ipv6_mx => 0 );
ok( !$check->only_ipv4_mx, "not only IPv4: neighter IPv4 nor IPv6 mx" );

$check = create_check_with( count_ipv4_mx => 0, count_ipv6_mx => 0 );
ok( !$check->only_ipv6_mx, "not only IPv6: neighter IPv4 nor IPv6 mx" );



# === Summary tests finished ===========================================


#
# Tests with real domain
# A better approach would be to mock Net::DNS Methods!
#

$check
   = Security::TLSCheck::Checks::DNS->new( instance => Security::TLSCheck->new( domain => "nstest.tls-check.alvar-freude.de" ) );

ok( $check, "check object created" );


my @ns;

TODO:
   {
   local $TODO = "looks like here is a bug (in my DNS or in Code or in test!)";
   @ns = $check->get_ns;
   eq_or_diff( [ sort @ns ],
               [qw( ns1.tls-check.alvar-freude.de ns2.tls-check.alvar-freude.de ns3.tls-check.alvar-freude.de )],
               "Nameserver OK (nstest.tls-check.alvar-freude.de)" )
      or diag "==> maybe not a bug, but network problems or changed DNS?";
   }

$check = Security::TLSCheck::Checks::DNS->new( instance => Security::TLSCheck->new( domain => "tls-check.alvar-freude.de" ) );

my @mx = $check->get_mx;
eq_or_diff( \@mx,
            [qw( mx1.tls-check.alvar-freude.de mx2.tls-check.alvar-freude.de mx3.tls-check.alvar-freude.de  )],
            "Mail Exchanger OK (alvar-freude.de)" )
   or diag "==> maybe not a bug, but network problems or changed DNS?";


$check = Security::TLSCheck::Checks::DNS->new(
                                         instance => Security::TLSCheck->new( domain => "has-no-mx.tls-check.alvar-freude.de" ) );

@mx = $check->get_mx;
is( scalar @mx, 0, "No MX for has-no-mx.tls-check.alvar-freude.de" );


$check = Security::TLSCheck::Checks::DNS->new(
                          instance => Security::TLSCheck->new( domain => "does.not.exist.neverever.tls-check.alvar-freude.de" ) );

@ns = $check->get_ns;
is( scalar @ns, 0, "zero result" );

# TODO: fix this. Why empty on FreeBS?
TODO:
   {
   local $TODO = "On FreeBSD error is empty; check this test!";
   is( $check->error, "NXDOMAIN", "no NS for nonexistant domain" );
   }


#
# IPv6 documentation prefix: 2001:db8::/32
# http://tools.ietf.org/html/rfc5156#section-2.6
#
#

# mx3.tls-check: 2001:db8::23:42:0:1
# ipv6.tls-check: 2001:db8::23:42:1:1
# double: 127.23.42.50 + 127.23.42.51
#         2001:db8::23:42:2:1 + 2001:db8::23:42:2:2


$check = Security::TLSCheck::Checks::DNS->new( instance => Security::TLSCheck->new( domain => "tls-check.alvar-freude.de" ) );

my @ips = $check->_get_ip("tls-check.alvar-freude.de");
eq_or_diff( \@ips, [qw(127.23.42.21)], "get_ip, default" ) or diag "==> network check!";

@ips = $check->_get_ip( "tls-check.alvar-freude.de", "A" );
eq_or_diff( \@ips, [qw(127.23.42.21)], "get_ip, A" ) or diag "==> network check!";

@ips = $check->_get_ip( "tls-check.alvar-freude.de", "AAAA" );
eq_or_diff( \@ips, [], "get_ip, AAAA" ) or diag "==> network check!";


@ips = $check->_get_ip( "ipv6.tls-check.alvar-freude.de", "A" );
eq_or_diff( \@ips, [], "get_ip, ipv6 domain but A" ) or diag "==> network check!";

@ips = $check->_get_ip( "ipv6.tls-check.alvar-freude.de", "AAAA" );
eq_or_diff( \@ips, [qw(2001:db8:0:0:23:42:1:1)], "get_ip, ipv6 " ) or diag "==> network check!";


#
# === Full Check =======================================================
#

my $domain = "tls-check.alvar-freude.de";
$check = Security::TLSCheck::Checks::DNS->new( instance => Security::TLSCheck->new( domain => "$domain" ) );

my @result = map { { name => $ARG->{info}{name}, type => $ARG->{info}{type}, value => $ARG->{value}, } } @{ $check->run_check };

my $expected = [
                 { name => "# Nameserver",     type => "count", value => 0, },
                 { name => "# Mail Exchanger", type => "count", value => 3, },
                 { name => "Domain IPv4",      type => "flag",  value => 1, },
                 { name => "Domain IPv6",      type => "flag",  value => 0, },
                 { name => "NS IPv4",          type => "flag",  value => 0, },
                 { name => "NS IPv6",          type => "flag",  value => 0, },
                 { name => "MX IPv4",          type => "flag",  value => 1, },
                 { name => "MX IPv6",          type => "flag",  value => 1, },
                 { name => "Domain only IPv4", type => "flag",  value => 1, },
                 { name => "Domain only IPv6", type => "flag",  value => 0, },
                 { name => "NS only IPv4",     type => "flag",  value => 0, },
                 { name => "NS only IPv6",     type => "flag",  value => 0, },
                 { name => "MX only IPv4",     type => "flag",  value => 0, },
                 { name => "MX only IPv6",     type => "flag",  value => 0, },
               ];

TODO:
   {
   local $TODO = "add more results to test!";
   eq_or_diff( \@result, $expected, "complete run for $domain" );
   }

# Now check all internal values

# all moose traits correct?
eq_or_diff( [ $check->all_ns ],       $check->ns,       "ns via all_ns or ns is the same for $domain" );
eq_or_diff( [ $check->all_mx ],       $check->mx,       "mx via all_mx or mx is the same for $domain" );
eq_or_diff( [ $check->all_ipv4 ],     $check->ipv4,     "ipv4 via all_ipv4 or ipv4 is the same for $domain" );
eq_or_diff( [ $check->all_ipv6 ],     $check->ipv6,     "ipv6 via all_ipv6 or ipv6 is the same for $domain" );
eq_or_diff( [ $check->all_ipv4_www ], $check->ipv4_www, "ipv4_www via all_ipv4_www or ipv4_www is the same for $domain" );
eq_or_diff( [ $check->all_ipv6_www ], $check->ipv6_www, "ipv6_www via all_ipv6_www or ipv6_www is the same for $domain" );
eq_or_diff( [ $check->all_ipv4_ns ],  $check->ipv4_ns,  "ipv4_ns via all_ipv4_ns or ipv4_ns is the same for $domain" );
eq_or_diff( [ $check->all_ipv6_ns ],  $check->ipv6_ns,  "ipv6_ns via all_ipv6_ns or ipv6_ns is the same for $domain" );
eq_or_diff( [ $check->all_ipv4_mx ],  $check->ipv4_mx,  "ipv4_mx via all_ipv4_mx or ipv4_mx is the same for $domain" );
eq_or_diff( [ $check->all_ipv6_mx ],  $check->ipv6_mx,  "ipv6_mx via all_ipv6_mx or ipv6_mx is the same for $domain" );

# values
eq_or_diff( $check->mx, [ map { "mx$ARG.$domain" } 1 .. 3 ], "mx for $domain" );
eq_or_diff( $check->ns,       [qw()],                        "ns for $domain" );
eq_or_diff( $check->ipv4,     [qw( 127.23.42.21 )],          "ipv4 for $domain" );
eq_or_diff( $check->ipv6,     [qw()],                        "ipv6 for $domain" );
eq_or_diff( $check->ipv4_www, [qw()],                        "ipv4_www for $domain" );
eq_or_diff( $check->ipv6_www, [qw()],                        "ipv6_www for $domain" );
eq_or_diff( $check->ipv4_ns,  [qw()],                        "ipv4_ns for $domain" );
eq_or_diff( $check->ipv6_ns,  [qw()],                        "ipv6_ns for $domain" );
eq_or_diff( $check->ipv4_mx,  [qw(127.23.42.1 127.23.42.2)], "ipv4_mx for $domain" );
eq_or_diff( $check->ipv6_mx,  [qw(2001:db8:0:0:23:42:0:3)],  "ipv6_mx for $domain" );


#
# domain nstest ...
#

$domain = "nstest.tls-check.alvar-freude.de";
$check  = Security::TLSCheck::Checks::DNS->new( instance => Security::TLSCheck->new( domain => "$domain" ) );
@result = map { { name => $ARG->{info}{name}, type => $ARG->{info}{type}, value => $ARG->{value}, } } @{ $check->run_check };


$expected = [
              { name => "# Nameserver",     type => "count", value => 3, },
              { name => "# Mail Exchanger", type => "count", value => 0, },
              { name => "Domain IPv4",      type => "flag",  value => 0, },
              { name => "Domain IPv6",      type => "flag",  value => 0, },
              { name => "NS IPv4",          type => "flag",  value => 1, },
              { name => "NS IPv6",          type => "flag",  value => 0, },
              { name => "MX IPv4",          type => "flag",  value => 0, },
              { name => "MX IPv6",          type => "flag",  value => 0, },
              { name => "Domain only IPv4", type => "flag",  value => 0, },
              { name => "Domain only IPv6", type => "flag",  value => 0, },
              { name => "NS only IPv4",     type => "flag",  value => 1, },
              { name => "NS only IPv6",     type => "flag",  value => 0, },
              { name => "MX only IPv4",     type => "flag",  value => 0, },
              { name => "MX only IPv6",     type => "flag",  value => 0, },
            ];

TODO:
   {
   local $TODO = "add more results to test!";
   eq_or_diff( \@result, $expected, "complete run for $domain" );
   }

$check = Security::TLSCheck::Checks::DNS->new( instance => Security::TLSCheck->new( domain => "$domain" ) );
@result
   = map { { name => $ARG->{info}{name}, type => $ARG->{info}{type}, value => $ARG->{value}, } } @{ scalar $check->run_check };



TODO:
   {
   local $TODO = "add more results to test!";
   eq_or_diff( \@result, $expected, "result in scalar context as expected" );
   }

$check = Security::TLSCheck::Checks::DNS->new( instance => Security::TLSCheck->new( domain => "$domain" ) );
my @r = $check->run_check;
$check = Security::TLSCheck::Checks::DNS->new( instance => Security::TLSCheck->new( domain => "$domain" ) );
my $r = $check->run_check;

eq_or_diff( $r, @r, "result in scalar and list context is identical" );


# Now check all internal values

# all moose traits correct?
eq_or_diff( [ $check->all_ns ],       $check->ns,       "ns via all_ns or ns is the same for $domain" );
eq_or_diff( [ $check->all_mx ],       $check->mx,       "mx via all_mx or mx is the same for $domain" );
eq_or_diff( [ $check->all_ipv4 ],     $check->ipv4,     "ipv4 via all_ipv4 or ipv4 is the same for $domain" );
eq_or_diff( [ $check->all_ipv6 ],     $check->ipv6,     "ipv6 via all_ipv6 or ipv6 is the same for $domain" );
eq_or_diff( [ $check->all_ipv4_www ], $check->ipv4_www, "ipv4_www via all_ipv4_www or ipv4_www is the same for $domain" );
eq_or_diff( [ $check->all_ipv6_www ], $check->ipv6_www, "ipv6_www via all_ipv6_www or ipv6_www is the same for $domain" );
eq_or_diff( [ $check->all_ipv4_ns ],  $check->ipv4_ns,  "ipv4_ns via all_ipv4_ns or ipv4_ns is the same for $domain" );
eq_or_diff( [ $check->all_ipv6_ns ],  $check->ipv6_ns,  "ipv6_ns via all_ipv6_ns or ipv6_ns is the same for $domain" );
eq_or_diff( [ $check->all_ipv4_mx ],  $check->ipv4_mx,  "ipv4_mx via all_ipv4_mx or ipv4_mx is the same for $domain" );
eq_or_diff( [ $check->all_ipv6_mx ],  $check->ipv6_mx,  "ipv6_mx via all_ipv6_mx or ipv6_mx is the same for $domain" );

# values

TODO:
   {
   local $TODO = "looks like a bug – in test?";
   eq_or_diff( [ sort $check->all_ns ], [ map { "ns$ARG.tls-check.alvar-freude.de" } 1 .. 3 ], "ns for $domain" );
   }
eq_or_diff( $check->mx,       [qw()], "mx for $domain" );
eq_or_diff( $check->ipv4,     [qw()], "ipv4 for $domain" );
eq_or_diff( $check->ipv6,     [qw()], "ipv6 for $domain" );
eq_or_diff( $check->ipv4_www, [qw()], "ipv4_www for $domain" );
eq_or_diff( $check->ipv6_www, [qw()], "ipv6_www for $domain" );

TODO:
   {
   local $TODO = "looks like a bug – in test?";
   eq_or_diff( [ sort $check->all_ipv4_ns ], [qw(127.23.42.11 127.23.42.12)], "ipv4_ns for $domain" );
   }

eq_or_diff( $check->ipv6_ns, [qw()], "ipv6_ns for $domain" );
eq_or_diff( $check->ipv4_mx, [qw()], "ipv4_mx for $domain" );
eq_or_diff( $check->ipv6_mx, [qw()], "ipv6_mx for $domain" );


#
# domain double
#

$domain = "double.tls-check.alvar-freude.de";
$check  = Security::TLSCheck::Checks::DNS->new( instance => Security::TLSCheck->new( domain => "$domain" ) );
@result = map { { name => $ARG->{info}{name}, type => $ARG->{info}{type}, value => $ARG->{value}, } } @{ $check->run_check };

$expected = [
              { name => "# Nameserver",     type => "count", value => 0, },
              { name => "# Mail Exchanger", type => "count", value => 0, },
              { name => "Domain IPv4",      type => "flag",  value => 1, },
              { name => "Domain IPv6",      type => "flag",  value => 1, },
              { name => "NS IPv4",          type => "flag",  value => 0, },
              { name => "NS IPv6",          type => "flag",  value => 0, },
              { name => "MX IPv4",          type => "flag",  value => 0, },
              { name => "MX IPv6",          type => "flag",  value => 0, },
              { name => "Domain only IPv4", type => "flag",  value => 0, },
              { name => "Domain only IPv6", type => "flag",  value => 0, },
              { name => "NS only IPv4",     type => "flag",  value => 0, },
              { name => "NS only IPv6",     type => "flag",  value => 0, },
              { name => "MX only IPv4",     type => "flag",  value => 0, },
              { name => "MX only IPv6",     type => "flag",  value => 0, },
            ];

TODO:
   {
   local $TODO = "add more results to test!";
   eq_or_diff( \@result, $expected, "complete run for $domain" );
   }



# Now check all internal values

# all moose traits correct?
eq_or_diff( [ $check->all_ns ],       $check->ns,       "ns via all_ns or ns is the same for $domain" );
eq_or_diff( [ $check->all_mx ],       $check->mx,       "mx via all_mx or mx is the same for $domain" );
eq_or_diff( [ $check->all_ipv4 ],     $check->ipv4,     "ipv4 via all_ipv4 or ipv4 is the same for $domain" );
eq_or_diff( [ $check->all_ipv6 ],     $check->ipv6,     "ipv6 via all_ipv6 or ipv6 is the same for $domain" );
eq_or_diff( [ $check->all_ipv4_www ], $check->ipv4_www, "ipv4_www via all_ipv4_www or ipv4_www is the same for $domain" );
eq_or_diff( [ $check->all_ipv6_www ], $check->ipv6_www, "ipv6_www via all_ipv6_www or ipv6_www is the same for $domain" );
eq_or_diff( [ $check->all_ipv4_ns ],  $check->ipv4_ns,  "ipv4_ns via all_ipv4_ns or ipv4_ns is the same for $domain" );
eq_or_diff( [ $check->all_ipv6_ns ],  $check->ipv6_ns,  "ipv6_ns via all_ipv6_ns or ipv6_ns is the same for $domain" );
eq_or_diff( [ $check->all_ipv4_mx ],  $check->ipv4_mx,  "ipv4_mx via all_ipv4_mx or ipv4_mx is the same for $domain" );
eq_or_diff( [ $check->all_ipv6_mx ],  $check->ipv6_mx,  "ipv6_mx via all_ipv6_mx or ipv6_mx is the same for $domain" );

# values
eq_or_diff( $check->ns, [qw()], "ns for $domain" );
eq_or_diff( $check->mx, [qw()], "mx for $domain" );
eq_or_diff( [ sort $check->all_ipv4 ], [qw( 127.23.42.50 127.23.42.51 )], "ipv4 for $domain" );
eq_or_diff( [ sort $check->all_ipv6 ], [qw( 2001:db8:0:0:23:42:2:1 2001:db8:0:0:23:42:2:2)], "ipv6 for $domain" );
eq_or_diff( $check->ipv4_www, [qw()], "ipv4_www for $domain" );
eq_or_diff( $check->ipv6_www, [qw()], "ipv6_www for $domain" );
eq_or_diff( $check->ipv4_ns,  [qw()], "ipv4_ns for $domain" );
eq_or_diff( $check->ipv6_ns,  [qw()], "ipv6_ns for $domain" );
eq_or_diff( $check->ipv4_mx,  [qw()], "ipv4_mx for $domain" );
eq_or_diff( $check->ipv6_mx,  [qw()], "ipv6_mx for $domain" );



#
# domain ipv6
#

$domain = "ipv6.tls-check.alvar-freude.de";
$check  = Security::TLSCheck::Checks::DNS->new( instance => Security::TLSCheck->new( domain => "$domain" ) );
@result = map { { name => $ARG->{info}{name}, type => $ARG->{info}{type}, value => $ARG->{value}, } } @{ $check->run_check };


$expected = [
              { name => "# Nameserver",     type => "count", value => 0, },
              { name => "# Mail Exchanger", type => "count", value => 0, },
              { name => "Domain IPv4",      type => "flag",  value => 0, },
              { name => "Domain IPv6",      type => "flag",  value => 1, },
              { name => "NS IPv4",          type => "flag",  value => 0, },
              { name => "NS IPv6",          type => "flag",  value => 0, },
              { name => "MX IPv4",          type => "flag",  value => 0, },
              { name => "MX IPv6",          type => "flag",  value => 0, },
              { name => "Domain only IPv4", type => "flag",  value => 0, },
              { name => "Domain only IPv6", type => "flag",  value => 1, },
              { name => "NS only IPv4",     type => "flag",  value => 0, },
              { name => "NS only IPv6",     type => "flag",  value => 0, },
              { name => "MX only IPv4",     type => "flag",  value => 0, },
              { name => "MX only IPv6",     type => "flag",  value => 0, },
            ];

TODO:
   {
   local $TODO = "add more results to test!";
   eq_or_diff( \@result, $expected, "complete run for $domain" );
   }


# Now check all internal values

# all moose traits correct?
eq_or_diff( [ $check->all_ns ],       $check->ns,       "ns via all_ns or ns is the same for $domain" );
eq_or_diff( [ $check->all_mx ],       $check->mx,       "mx via all_mx or mx is the same for $domain" );
eq_or_diff( [ $check->all_ipv4 ],     $check->ipv4,     "ipv4 via all_ipv4 or ipv4 is the same for $domain" );
eq_or_diff( [ $check->all_ipv6 ],     $check->ipv6,     "ipv6 via all_ipv6 or ipv6 is the same for $domain" );
eq_or_diff( [ $check->all_ipv4_www ], $check->ipv4_www, "ipv4_www via all_ipv4_www or ipv4_www is the same for $domain" );
eq_or_diff( [ $check->all_ipv6_www ], $check->ipv6_www, "ipv6_www via all_ipv6_www or ipv6_www is the same for $domain" );
eq_or_diff( [ $check->all_ipv4_ns ],  $check->ipv4_ns,  "ipv4_ns via all_ipv4_ns or ipv4_ns is the same for $domain" );
eq_or_diff( [ $check->all_ipv6_ns ],  $check->ipv6_ns,  "ipv6_ns via all_ipv6_ns or ipv6_ns is the same for $domain" );
eq_or_diff( [ $check->all_ipv4_mx ],  $check->ipv4_mx,  "ipv4_mx via all_ipv4_mx or ipv4_mx is the same for $domain" );
eq_or_diff( [ $check->all_ipv6_mx ],  $check->ipv6_mx,  "ipv6_mx via all_ipv6_mx or ipv6_mx is the same for $domain" );

# values
eq_or_diff( $check->ns,       [qw()],                         "ns for $domain" );
eq_or_diff( $check->mx,       [qw()],                         "mx for $domain" );
eq_or_diff( $check->ipv4,     [qw()],                         "ipv4 for $domain" );
eq_or_diff( $check->ipv6,     [qw( 2001:db8:0:0:23:42:1:1 )], "ipv6 for $domain" );
eq_or_diff( $check->ipv4_www, [qw()],                         "ipv4_www for $domain" );
eq_or_diff( $check->ipv6_www, [qw()],                         "ipv6_www for $domain" );
eq_or_diff( $check->ipv4_ns,  [qw()],                         "ipv4_ns for $domain" );
eq_or_diff( $check->ipv6_ns,  [qw()],                         "ipv6_ns for $domain" );
eq_or_diff( $check->ipv4_mx,  [qw()],                         "ipv4_mx for $domain" );
eq_or_diff( $check->ipv6_mx,  [qw()],                         "ipv6_mx for $domain" );

