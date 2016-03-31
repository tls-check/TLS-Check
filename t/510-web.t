#!/usr/bin/env perl

use 5.010;
use strict;
use warnings FATAL => 'all';
use Test::More;
use Test::Exception;
use Test::Differences;
use Test::LWP::UserAgent;

use English qw( -no_match_vars );

use Security::TLSCheck;


plan tests => 118;

use_ok("LWP::Protocol::https");
use_ok("Security::TLSCheck::Checks::Web");
can_ok( "Security::TLSCheck::Checks::Web", qw(run_check) );


# TODO:
# checks for ssl_opts!


#
# Test invalid domain
#

my $check = Security::TLSCheck::Checks::Web->new( instance => Security::TLSCheck->new( domain => "nonexistent.invalid" ) );
ok( $check, "check object built" );

#$check->_http_response( $check->_do_request("http") );
#$check->_https_response( $check->_do_request("https") );


ok( ( not $check->http_active ),          "no HTTP active for nonexistant.invalid" );
ok( ( not $check->https_active ),         "no HTTPS active for nonexistant.invalid" );
ok( ( not $check->http_ok ),              "no HTTP OK for nonexistant.invalid" );
ok( ( not $check->https_ok ),             "no HTTPS OK for nonexistant.invalid" );
ok( ( not $check->redirects_to_https ),   "no HTTP=>HTTPS redirect for nonexistant.invalid" );
ok( ( not defined $check->hsts_max_age ), "no HSTS max age" );
ok( ( not $check->disables_hsts ),        "HSTS not disabled" );

my $expected = [
   { name => "HTTP active",               type => "flag",  value => 0, },
   { name => "HTTP OK",                   type => "flag",  value => 0, },
   { name => "HTTPS active",              type => "flag",  value => 0, },
   { name => "HTTPS host verified",       type => "flag",  value => 0, },
   { name => "HTTPS cert verified",       type => "flag",  value => 0, },
   { name => "HTTPS wrong host, cert OK", type => "flag",  value => 0, },
   { name => "HTTPS all verified",        type => "flag",  value => 0, },
   { name => "HTTPS OK",                  type => "flag",  value => 0, },
   { name => "HTTPS all verified and OK", type => "flag",  value => 0, },
   { name => "Redirect to HTTPS",         type => "flag",  value => 0, },
   { name => "Redirect to HTTP",          type => "flag",  value => 0, },
   { name => "Supports HSTS",             type => "flag",  value => 0, },
   { name => "HSTS max age",              type => "int",   value => undef, },
   { name => "Disables HSTS",             type => "flag",  value => 0, },
   { name => "Used cipher suite",         type => "group", value => undef, },
   { name => "Certificate issuer",        type => "group", value => undef, },
   { name => "Server full string",        type => "group", value => undef, },
   { name => "Server name",               type => "group", value => undef, },
   { name => "Server name/major version", type => "group", value => undef, },
   { name => "Supports HPKP",             type => "flag",  value => 0, },
   { name => "Supports HPKP report",      type => "flag",  value => 0, },

               ];
my @result = map { { name => $ARG->{info}{name}, type => $ARG->{info}{type}, value => $ARG->{value}, } } @{ $check->run_check };
eq_or_diff( \@result, $expected, "complete result for nonexistent.invalid" );


my $ua = Test::LWP::UserAgent->new;


#
# Only HTTP, WWW
#

my $domain = "only-http.tls-check";
$ua->map_response( qr(^http://www.$domain)x, HTTP::Response->new( 200, "OK" ) );
$ua->map_response(
                   qr(^https://www.$domain)x,
                   HTTP::Response->new(
                                        500,
                                        "Can't connect to www.only-http.tls-check:443",
                                        [ "Client-Warning" => "Internal response" ], "",
                                      )
                 );

$check = Security::TLSCheck::Checks::Web->new( _ua      => $ua,
                                               instance => Security::TLSCheck->new( domain => $domain, ), );

ok( ( $check->http_active ),              "HTTP active for $domain" );
ok( ( not $check->https_active ),         "no HTTPS active for $domain" );
ok( ( $check->http_ok ),                  "HTTP OK for $domain" );
ok( ( not $check->https_ok ),             "no HTTPS OK for $domain" );
ok( ( not $check->redirects_to_https ),   "no HTTP=>HTTPS redirect for $domain" );
ok( ( not defined $check->hsts_max_age ), "no HSTS max age for $domain" );
ok( ( not $check->disables_hsts ),        "HSTS not disabled for $domain" );



$expected = [
              { name => "HTTP active",               type => "flag",  value => 1, },
              { name => "HTTP OK",                   type => "flag",  value => 1, },
              { name => "HTTPS active",              type => "flag",  value => 0, },
              { name => "HTTPS host verified",       type => "flag",  value => 0, },
              { name => "HTTPS cert verified",       type => "flag",  value => 0, },
              { name => "HTTPS wrong host, cert OK", type => "flag",  value => 0, },
              { name => "HTTPS all verified",        type => "flag",  value => 0, },
              { name => "HTTPS OK",                  type => "flag",  value => 0, },
              { name => "HTTPS all verified and OK", type => "flag",  value => 0, },
              { name => "Redirect to HTTPS",         type => "flag",  value => 0, },
              { name => "Redirect to HTTP",          type => "flag",  value => 0, },
              { name => "Supports HSTS",             type => "flag",  value => 0, },
              { name => "HSTS max age",              type => "int",   value => undef, },
              { name => "Disables HSTS",             type => "flag",  value => 0, },
              { name => "Used cipher suite",         type => "group", value => undef, },
              { name => "Certificate issuer",        type => "group", value => undef, },
              { name => "Server full string",        type => "group", value => undef, },
              { name => "Server name",               type => "group", value => undef, },
              { name => "Server name/major version", type => "group", value => undef, },
              { name => "Supports HPKP",             type => "flag",  value => 0, },
              { name => "Supports HPKP report",      type => "flag",  value => 0, },
            ];

@result = map { { name => $ARG->{info}{name}, type => $ARG->{info}{type}, value => $ARG->{value}, } } @{ $check->run_check };

eq_or_diff( \@result, $expected, "Only reacheable via HTTP, on www.$domain" );



#
# HTTPS and HTTP
#
$domain = "http-and-https.tls-check";
$ua->map_response( qr(^http://www.$domain)x,  HTTP::Response->new( 200, "OK" ) );
$ua->map_response( qr(^https://www.$domain)x, HTTP::Response->new( 200, "OK" ) );

$check = Security::TLSCheck::Checks::Web->new( _ua      => $ua,
                                               instance => Security::TLSCheck->new( domain => $domain, ), );

ok( ( $check->http_active ),              "HTTP active for $domain" );
ok( ( $check->https_active ),             "no HTTPS active for $domain" );
ok( ( $check->http_ok ),                  "HTTP OK for $domain" );
ok( ( $check->https_ok ),                 "no HTTPS OK for $domain" );
ok( ( not $check->redirects_to_https ),   "no HTTP=>HTTPS redirect for $domain" );
ok( ( not defined $check->hsts_max_age ), "no HSTS max age for $domain" );
ok( ( not $check->disables_hsts ),        "HSTS not disabled for $domain" );


$expected = [
              { name => "HTTP active",               type => "flag",  value => 1, },
              { name => "HTTP OK",                   type => "flag",  value => 1, },
              { name => "HTTPS active",              type => "flag",  value => 1, },
              { name => "HTTPS host verified",       type => "flag",  value => 1, },
              { name => "HTTPS cert verified",       type => "flag",  value => 1, },
              { name => "HTTPS wrong host, cert OK", type => "flag",  value => 0, },
              { name => "HTTPS all verified",        type => "flag",  value => 1, },
              { name => "HTTPS OK",                  type => "flag",  value => 1, },
              { name => "HTTPS all verified and OK", type => "flag",  value => 1, },
              { name => "Redirect to HTTPS",         type => "flag",  value => 0, },
              { name => "Redirect to HTTP",          type => "flag",  value => 0, },
              { name => "Supports HSTS",             type => "flag",  value => 0, },
              { name => "HSTS max age",              type => "int",   value => undef, },
              { name => "Disables HSTS",             type => "flag",  value => 0, },
              { name => "Used cipher suite",         type => "group", value => undef, },
              { name => "Certificate issuer",        type => "group", value => undef, },
              { name => "Server full string",        type => "group", value => undef, },
              { name => "Server name",               type => "group", value => undef, },
              { name => "Server name/major version", type => "group", value => undef, },
              { name => "Supports HPKP",             type => "flag",  value => 0, },
              { name => "Supports HPKP report",      type => "flag",  value => 0, },
            ];

@result = map { { name => $ARG->{info}{name}, type => $ARG->{info}{type}, value => $ARG->{value}, } } @{ $check->run_check };

eq_or_diff( \@result, $expected, "reacheable via HTTP and HTTPS on www.$domain" );


#
# only without www HTTPS and HTTP
#

$domain = "without-www-http-and-https.tls-check";
$ua->map_response( qr(^http://$domain)x,  HTTP::Response->new( 200, "OK" ) );
$ua->map_response( qr(^https://$domain)x, HTTP::Response->new( 200, "OK" ) );

$check = Security::TLSCheck::Checks::Web->new( _ua      => $ua,
                                               instance => Security::TLSCheck->new( domain => $domain, ), );

ok( ( $check->http_active ),              "HTTP active for $domain" );
ok( ( $check->https_active ),             "no HTTPS active for $domain" );
ok( ( $check->http_ok ),                  "HTTP OK for $domain" );
ok( ( $check->https_ok ),                 "no HTTPS OK for $domain" );
ok( ( not $check->redirects_to_https ),   "no HTTP=>HTTPS redirect for $domain" );
ok( ( not defined $check->hsts_max_age ), "no HSTS max age for $domain" );
ok( ( not $check->disables_hsts ),        "HSTS not disabled for $domain" );


$expected = [
              { name => "HTTP active",               type => "flag",  value => 1, },
              { name => "HTTP OK",                   type => "flag",  value => 1, },
              { name => "HTTPS active",              type => "flag",  value => 1, },
              { name => "HTTPS host verified",       type => "flag",  value => 1, },
              { name => "HTTPS cert verified",       type => "flag",  value => 1, },
              { name => "HTTPS wrong host, cert OK", type => "flag",  value => 0, },
              { name => "HTTPS all verified",        type => "flag",  value => 1, },
              { name => "HTTPS OK",                  type => "flag",  value => 1, },
              { name => "HTTPS all verified and OK", type => "flag",  value => 1, },
              { name => "Redirect to HTTPS",         type => "flag",  value => 0, },
              { name => "Redirect to HTTP",          type => "flag",  value => 0, },
              { name => "Supports HSTS",             type => "flag",  value => 0, },
              { name => "HSTS max age",              type => "int",   value => undef, },
              { name => "Disables HSTS",             type => "flag",  value => 0, },
              { name => "Used cipher suite",         type => "group", value => undef, },
              { name => "Certificate issuer",        type => "group", value => undef, },
              { name => "Server full string",        type => "group", value => undef, },
              { name => "Server name",               type => "group", value => undef, },
              { name => "Server name/major version", type => "group", value => undef, },
              { name => "Supports HPKP",             type => "flag",  value => 0, },
              { name => "Supports HPKP report",      type => "flag",  value => 0, },
            ];

@result = map { { name => $ARG->{info}{name}, type => $ARG->{info}{type}, value => $ARG->{value}, } } @{ $check->run_check };

eq_or_diff( \@result, $expected, "Only reacheable via HTTP, on www.$domain" );



#
# 404 error
#

$domain = "err404.tls-check";
$ua->map_response( qr(^http://www.$domain)x, HTTP::Response->new( 404, "NOT FOUND" ) );
$ua->map_response( qr(^https://www.$domain)x,
                   HTTP::Response->new( 404, "Not Found", [ "Strict-Transport-Security" => "max-age=987654321" ], "", ) );

$check = Security::TLSCheck::Checks::Web->new( _ua      => $ua,
                                               instance => Security::TLSCheck->new( domain => $domain, ), );

ok( ( $check->http_active ),            "HTTP active for $domain" );
ok( ( $check->https_active ),           "HTTPS active for $domain" );
ok( ( not $check->http_ok ),            "no HTTP OK for $domain" );
ok( ( not $check->https_ok ),           "no HTTPS OK for $domain" );
ok( ( not $check->redirects_to_https ), "no HTTP=>HTTPS redirect for $domain" );
ok( ( not $check->disables_hsts ),      "HSTS not disabled for $domain" );
is( $check->hsts_max_age, 987654321, "HSTS max age 987654321 for $domain" );


$expected = [
              { name => "HTTP active",               type => "flag",  value => 1, },
              { name => "HTTP OK",                   type => "flag",  value => 0, },
              { name => "HTTPS active",              type => "flag",  value => 1, },
              { name => "HTTPS host verified",       type => "flag",  value => 1, },
              { name => "HTTPS cert verified",       type => "flag",  value => 1, },
              { name => "HTTPS wrong host, cert OK", type => "flag",  value => 0, },
              { name => "HTTPS all verified",        type => "flag",  value => 1, },
              { name => "HTTPS OK",                  type => "flag",  value => 0, },
              { name => "HTTPS all verified and OK", type => "flag",  value => 0, },
              { name => "Redirect to HTTPS",         type => "flag",  value => 0, },
              { name => "Redirect to HTTP",          type => "flag",  value => 0, },
              { name => "Supports HSTS",             type => "flag",  value => 1, },
              { name => "HSTS max age",              type => "int",   value => 987654321, },
              { name => "Disables HSTS",             type => "flag",  value => 0, },
              { name => "Used cipher suite",         type => "group", value => undef, },
              { name => "Certificate issuer",        type => "group", value => undef, },
              { name => "Server full string",        type => "group", value => undef, },
              { name => "Server name",               type => "group", value => undef, },
              { name => "Server name/major version", type => "group", value => undef, },
              { name => "Supports HPKP",             type => "flag",  value => 0, },
              { name => "Supports HPKP report",      type => "flag",  value => 0, },
            ];

@result = map { { name => $ARG->{info}{name}, type => $ARG->{info}{type}, value => $ARG->{value}, } } @{ $check->run_check };

eq_or_diff( \@result, $expected, "404 on $domain" );



#
# 404 error without www
#

$domain = "err404-without-www.tls-check";
$ua->map_response( qr(^http://$domain)x, HTTP::Response->new( 404, "NOT FOUND" ) );
$ua->map_response( qr(^https://www.$domain)x,
                   HTTP::Response->new( 404, "Not Found", [ "Strict-Transport-Security" => "max-age=123" ], "", ) );
$ua->map_response( qr(^https://$domain)x,
                   HTTP::Response->new( 404, "Not Found", [ "Strict-Transport-Security" => "max-age=987654321" ], "", ) );

$check = Security::TLSCheck::Checks::Web->new( _ua      => $ua,
                                               instance => Security::TLSCheck->new( domain => $domain, ), );

ok( ( $check->http_active ),            "HTTP active for $domain" );
ok( ( $check->https_active ),           "HTTPS active for $domain" );
ok( ( not $check->http_ok ),            "no HTTP OK for $domain" );
ok( ( not $check->https_ok ),           "no HTTPS OK for $domain" );
ok( ( not $check->redirects_to_https ), "no HTTP=>HTTPS redirect for $domain" );
ok( ( not $check->disables_hsts ),      "HSTS not disabled for $domain" );
is( $check->hsts_max_age, 123, "HSTS max age 987654321 for $domain" );


$expected = [
              { name => "HTTP active",               type => "flag",  value => 1, },
              { name => "HTTP OK",                   type => "flag",  value => 0, },
              { name => "HTTPS active",              type => "flag",  value => 1, },
              { name => "HTTPS host verified",       type => "flag",  value => 1, },
              { name => "HTTPS cert verified",       type => "flag",  value => 1, },
              { name => "HTTPS wrong host, cert OK", type => "flag",  value => 0, },
              { name => "HTTPS all verified",        type => "flag",  value => 1, },
              { name => "HTTPS OK",                  type => "flag",  value => 0, },
              { name => "HTTPS all verified and OK", type => "flag",  value => 0, },
              { name => "Redirect to HTTPS",         type => "flag",  value => 0, },
              { name => "Redirect to HTTP",          type => "flag",  value => 0, },
              { name => "Supports HSTS",             type => "flag",  value => 1, },
              { name => "HSTS max age",              type => "int",   value => 123, },
              { name => "Disables HSTS",             type => "flag",  value => 0, },
              { name => "Used cipher suite",         type => "group", value => undef, },
              { name => "Certificate issuer",        type => "group", value => undef, },
              { name => "Server full string",        type => "group", value => undef, },
              { name => "Server name",               type => "group", value => undef, },
              { name => "Server name/major version", type => "group", value => undef, },
              { name => "Supports HPKP",             type => "flag",  value => 0, },
              { name => "Supports HPKP report",      type => "flag",  value => 0, },
            ];

@result = map { { name => $ARG->{info}{name}, type => $ARG->{info}{type}, value => $ARG->{value}, } } @{ $check->run_check };

eq_or_diff( \@result, $expected, "404 on $domain" );


#
# reset Strict-Transport-Security
#
$domain = "reset-hsts.tls-check";
$ua->map_response( qr(^http://www.$domain)x, HTTP::Response->new( 200, "OK" ) );
$ua->map_response( qr(^https://www.$domain)x,
                   HTTP::Response->new( 200, "OK", [ "Strict-Transport-Security" => "max-age=0" ], "", ) );

$check = Security::TLSCheck::Checks::Web->new( _ua      => $ua,
                                               instance => Security::TLSCheck->new( domain => $domain, ), );

ok( ( $check->http_active ),            "HTTP active for $domain" );
ok( ( $check->https_active ),           "no HTTPS active for $domain" );
ok( ( $check->http_ok ),                "HTTP OK for $domain" );
ok( ( $check->https_ok ),               "no HTTPS OK for $domain" );
ok( ( not $check->redirects_to_https ), "no HTTP=>HTTPS redirect for $domain" );
ok( ( defined $check->hsts_max_age ),   "HSTS max age for $domain" );
ok( ( $check->disables_hsts ),          "HSTS disabled for $domain" );


$expected = [
   { name => "HTTP active",               type => "flag",  value => 1, },
   { name => "HTTP OK",                   type => "flag",  value => 1, },
   { name => "HTTPS active",              type => "flag",  value => 1, },
   { name => "HTTPS host verified",       type => "flag",  value => 1, },
   { name => "HTTPS cert verified",       type => "flag",  value => 1, },
   { name => "HTTPS wrong host, cert OK", type => "flag",  value => 0, },
   { name => "HTTPS all verified",        type => "flag",  value => 1, },
   { name => "HTTPS OK",                  type => "flag",  value => 1, },
   { name => "HTTPS all verified and OK", type => "flag",  value => 1, },
   { name => "Redirect to HTTPS",         type => "flag",  value => 0, },
   { name => "Redirect to HTTP",          type => "flag",  value => 0, },
   { name => "Supports HSTS",             type => "flag",  value => 0, },
   { name => "HSTS max age",              type => "int",   value => 0, },
   { name => "Disables HSTS",             type => "flag",  value => 1, },
   { name => "Used cipher suite",         type => "group", value => undef, },
   { name => "Certificate issuer",        type => "group", value => undef, },
   { name => "Server full string",        type => "group", value => undef, },
   { name => "Server name",               type => "group", value => undef, },
   { name => "Server name/major version", type => "group", value => undef, },
   { name => "Supports HPKP",             type => "flag",  value => 0, },
   { name => "Supports HPKP report",      type => "flag",  value => 0, },

            ];

@result = map { { name => $ARG->{info}{name}, type => $ARG->{info}{type}, value => $ARG->{value}, } } @{ $check->run_check };

eq_or_diff( \@result, $expected, "reacheable via HTTP and HTTPS on www.$domain" );



#
# HTTP redirects to HTTPS
#

$domain = "http-redirs-https.tls-check";

my $redir_response = HTTP::Response->new( 200, "OK" );

$ua->map_response( qr(^http://www.$domain)x, $redir_response );
$ua->map_response( qr(^https://www.$domain)x, HTTP::Response->new( 200, "OK" ) );

$check = Security::TLSCheck::Checks::Web->new( _ua      => $ua,
                                               instance => Security::TLSCheck->new( domain => $domain, ), );

ok( ( $check->http_active ),  "HTTP active for $domain" );
ok( ( $check->https_active ), "HTTPS active for $domain" );

$redir_response->request->uri( URI->new("https://---$domain---/") );

ok( ( $check->http_active ),  "with redir HTTP active for $domain" );
ok( ( $check->https_active ), "with redir HTTPS active for $domain" );

ok( ( $check->http_ok ),                  "HTTP OK for $domain" );
ok( ( $check->https_ok ),                 "no HTTPS OK for $domain" );
ok( ( $check->redirects_to_https ),       "HTTP=>HTTPS redirect for $domain" );
ok( ( not $check->redirects_to_http ),    "HTTPS=>HTTP redirect for $domain" );
ok( ( not defined $check->hsts_max_age ), "no HSTS max age for $domain" );
ok( ( not $check->disables_hsts ),        "HSTS not disabled for $domain" );


$expected = [
              { name => "HTTP active",               type => "flag",  value => 1, },
              { name => "HTTP OK",                   type => "flag",  value => 1, },
              { name => "HTTPS active",              type => "flag",  value => 1, },
              { name => "HTTPS host verified",       type => "flag",  value => 1, },
              { name => "HTTPS cert verified",       type => "flag",  value => 1, },
              { name => "HTTPS wrong host, cert OK", type => "flag",  value => 0, },
              { name => "HTTPS all verified",        type => "flag",  value => 1, },
              { name => "HTTPS OK",                  type => "flag",  value => 1, },
              { name => "HTTPS all verified and OK", type => "flag",  value => 1, },
              { name => "Redirect to HTTPS",         type => "flag",  value => 1, },
              { name => "Redirect to HTTP",          type => "flag",  value => 0, },
              { name => "Supports HSTS",             type => "flag",  value => 0, },
              { name => "HSTS max age",              type => "int",   value => undef, },
              { name => "Disables HSTS",             type => "flag",  value => 0, },
              { name => "Used cipher suite",         type => "group", value => undef, },
              { name => "Certificate issuer",        type => "group", value => undef, },
              { name => "Server full string",        type => "group", value => undef, },
              { name => "Server name",               type => "group", value => undef, },
              { name => "Server name/major version", type => "group", value => undef, },
              { name => "Supports HPKP",             type => "flag",  value => 0, },
              { name => "Supports HPKP report",      type => "flag",  value => 0, },
            ];

@result = map { { name => $ARG->{info}{name}, type => $ARG->{info}{type}, value => $ARG->{value}, } } @{ $check->run_check };

eq_or_diff( \@result, $expected, "HTTP redirs to HTTPS at $domain" );



#
# HTTPS redirects to HTTP
#

$domain = "https-redirs-http.tls-check";


$ua->map_response( qr(^http://www.$domain)x, HTTP::Response->new( 200, "OK" ) );
$ua->map_response( qr(^https://www.$domain)x, $redir_response );

$check = Security::TLSCheck::Checks::Web->new( _ua      => $ua,
                                               instance => Security::TLSCheck->new( domain => $domain, ), );

ok( ( $check->http_active ),  "HTTP active for $domain" );
ok( ( $check->https_active ), "HTTPS active for $domain" );

$redir_response->request->uri( URI->new("http://---$domain---") );

#????? $check->_https_response_nocheck->request->uri( URI->new("http://===========wiederanders====/") );


ok( ( $check->http_active ),  "with redir HTTP active for $domain" );
ok( ( $check->https_active ), "with redir HTTPS active for $domain" );

ok( ( $check->http_ok ),                  "HTTP OK for $domain" );
ok( ( $check->https_ok ),                 "no HTTPS OK for $domain" );
ok( ( not $check->redirects_to_https ),   "HTTP=>HTTPS redirect for $domain" );
ok( ( $check->redirects_to_http ),        "HTTPS=>HTTP redirect for $domain" );
ok( ( not defined $check->hsts_max_age ), "no HSTS max age for $domain" );
ok( ( not $check->disables_hsts ),        "HSTS not disabled for $domain" );

$expected = [
              { name => "HTTP active",               type => "flag",  value => 1, },
              { name => "HTTP OK",                   type => "flag",  value => 1, },
              { name => "HTTPS active",              type => "flag",  value => 1, },
              { name => "HTTPS host verified",       type => "flag",  value => 1, },
              { name => "HTTPS cert verified",       type => "flag",  value => 1, },
              { name => "HTTPS wrong host, cert OK", type => "flag",  value => 0, },
              { name => "HTTPS all verified",        type => "flag",  value => 1, },
              { name => "HTTPS OK",                  type => "flag",  value => 1, },
              { name => "HTTPS all verified and OK", type => "flag",  value => 1, },
              { name => "Redirect to HTTPS",         type => "flag",  value => 0, },
              { name => "Redirect to HTTP",          type => "flag",  value => 1, },
              { name => "Supports HSTS",             type => "flag",  value => 0, },
              { name => "HSTS max age",              type => "int",   value => undef, },
              { name => "Disables HSTS",             type => "flag",  value => 0, },
              { name => "Used cipher suite",         type => "group", value => undef, },
              { name => "Certificate issuer",        type => "group", value => undef, },
              { name => "Server full string",        type => "group", value => undef, },
              { name => "Server name",               type => "group", value => undef, },
              { name => "Server name/major version", type => "group", value => undef, },
              { name => "Supports HPKP",             type => "flag",  value => 0, },
              { name => "Supports HPKP report",      type => "flag",  value => 0, },
            ];

@result = map { { name => $ARG->{info}{name}, type => $ARG->{info}{type}, value => $ARG->{value}, } } @{ $check->run_check };

eq_or_diff( \@result, $expected, "HTTPS redirs to HTTP at $domain" );


#
#use Data::Dumper;
#
#diag Dumper( $check->_https_response );



#
# 500 internal server error but not from client, real server error
#

$domain = "err500.tls-check";
$ua->map_response( qr(^http://www.$domain)x,  HTTP::Response->new( 500, "Internal Server error" ) );
$ua->map_response( qr(^https://www.$domain)x, HTTP::Response->new( 500, "Internal Server error", ) );

$check = Security::TLSCheck::Checks::Web->new( _ua      => $ua,
                                               instance => Security::TLSCheck->new( domain => $domain, ), );

ok( ( $check->http_active ),            "HTTP active for $domain" );
ok( ( $check->https_active ),           "HTTPS active for $domain" );
ok( ( not $check->http_ok ),            "no HTTP OK for $domain" );
ok( ( not $check->https_ok ),           "no HTTPS OK for $domain" );
ok( ( not $check->redirects_to_https ), "no HTTP=>HTTPS redirect for $domain" );
ok( ( not $check->disables_hsts ),      "HSTS not disabled for $domain" );
is( $check->hsts_max_age, undef, "HSTS max age undef for $domain" );


$expected = [
              { name => "HTTP active",               type => "flag",  value => 1, },
              { name => "HTTP OK",                   type => "flag",  value => 0, },
              { name => "HTTPS active",              type => "flag",  value => 1, },
              { name => "HTTPS host verified",       type => "flag",  value => 1, },
              { name => "HTTPS cert verified",       type => "flag",  value => 1, },
              { name => "HTTPS wrong host, cert OK", type => "flag",  value => 0, },
              { name => "HTTPS all verified",        type => "flag",  value => 1, },
              { name => "HTTPS OK",                  type => "flag",  value => 0, },
              { name => "HTTPS all verified and OK", type => "flag",  value => 0, },
              { name => "Redirect to HTTPS",         type => "flag",  value => 0, },
              { name => "Redirect to HTTP",          type => "flag",  value => 0, },
              { name => "Supports HSTS",             type => "flag",  value => 0, },
              { name => "HSTS max age",              type => "int",   value => undef, },
              { name => "Disables HSTS",             type => "flag",  value => 0, },
              { name => "Used cipher suite",         type => "group", value => undef, },
              { name => "Certificate issuer",        type => "group", value => undef, },
              { name => "Server full string",        type => "group", value => undef, },
              { name => "Server name",               type => "group", value => undef, },
              { name => "Server name/major version", type => "group", value => undef, },
              { name => "Supports HPKP",             type => "flag",  value => 0, },
              { name => "Supports HPKP report",      type => "flag",  value => 0, },
            ];

@result = map { { name => $ARG->{info}{name}, type => $ARG->{info}{type}, value => $ARG->{value}, } } @{ $check->run_check };

eq_or_diff( \@result, $expected, "404 on $domain" );



#
# 500 internal server error from server, but additionally (other) client-warning
#

$domain = "err500-client-warning.tls-check";
$ua->map_response( qr(^http://www.$domain)x,
                   HTTP::Response->new( 500, "Internal Server error", [ "Client-Warning" => "a client warning" ], ) );
$ua->map_response( qr(^https://www.$domain)x,
                   HTTP::Response->new( 500, "Internal Server error", [ "Client-Warning" => "a client warning" ], ) );

$check = Security::TLSCheck::Checks::Web->new( _ua      => $ua,
                                               instance => Security::TLSCheck->new( domain => $domain, ), );

ok( ( $check->http_active ),            "HTTP active for $domain" );
ok( ( $check->https_active ),           "HTTPS active for $domain" );
ok( ( not $check->http_ok ),            "no HTTP OK for $domain" );
ok( ( not $check->https_ok ),           "no HTTPS OK for $domain" );
ok( ( not $check->redirects_to_https ), "no HTTP=>HTTPS redirect for $domain" );
ok( ( not $check->disables_hsts ),      "HSTS not disabled for $domain" );
is( $check->hsts_max_age, undef, "HSTS max age undef for $domain" );


$expected = [
              { name => "HTTP active",               type => "flag",  value => 1, },
              { name => "HTTP OK",                   type => "flag",  value => 0, },
              { name => "HTTPS active",              type => "flag",  value => 1, },
              { name => "HTTPS host verified",       type => "flag",  value => 1, },
              { name => "HTTPS cert verified",       type => "flag",  value => 1, },
              { name => "HTTPS wrong host, cert OK", type => "flag",  value => 0, },
              { name => "HTTPS all verified",        type => "flag",  value => 1, },
              { name => "HTTPS OK",                  type => "flag",  value => 0, },
              { name => "HTTPS all verified and OK", type => "flag",  value => 0, },
              { name => "Redirect to HTTPS",         type => "flag",  value => 0, },
              { name => "Redirect to HTTP",          type => "flag",  value => 0, },
              { name => "Supports HSTS",             type => "flag",  value => 0, },
              { name => "HSTS max age",              type => "int",   value => undef, },
              { name => "Disables HSTS",             type => "flag",  value => 0, },
              { name => "Used cipher suite",         type => "group", value => undef, },
              { name => "Certificate issuer",        type => "group", value => undef, },
              { name => "Server full string",        type => "group", value => undef, },
              { name => "Server name",               type => "group", value => undef, },
              { name => "Server name/major version", type => "group", value => undef, },
              { name => "Supports HPKP",             type => "flag",  value => 0, },
              { name => "Supports HPKP report",      type => "flag",  value => 0, },
            ];

@result = map { { name => $ARG->{info}{name}, type => $ARG->{info}{type}, value => $ARG->{value}, } } @{ $check->run_check };

eq_or_diff( \@result, $expected, "404 on $domain" );



#
# certificate verify failed
#

$domain = "cert-verify-failed.tls-check";
$ua->map_response( qr(^http://www.$domain)x, HTTP::Response->new( 200, "OK" ) );

$ua->map_response(
                   qr(^https://www.$domain)x,
                   HTTP::Response->new(
                                        500,
                                        "Can't connect to $domain:443 (certificate verify failed)",
                                        [ "Client-Warning" => "Internal response" ],
                                      )
                 );

$check = Security::TLSCheck::Checks::Web->new( _ua      => $ua,
                                               instance => Security::TLSCheck->new( domain => $domain, ), );

ok( ( $check->http_active ),            "HTTP active for $domain" );
ok( ( $check->https_active ),           "HTTPS active for $domain" );
ok( ( not $check->https_all_verified ), "HTTPS all verified for $domain" );
ok( ( $check->http_ok ),                "no HTTP OK for $domain" );
ok( ( not $check->https_ok ),           "no HTTPS OK for $domain" );
ok( ( not $check->redirects_to_https ), "no HTTP=>HTTPS redirect for $domain" );
ok( ( not $check->redirects_to_http ),  "no HTTPS=>HTTP redirect for $domain" );
ok( ( not $check->disables_hsts ),      "HSTS not disabled for $domain" );
is( $check->hsts_max_age, undef, "HSTS max age undef for $domain" );


$expected = [
              { name => "HTTP active",               type => "flag",  value => 1, },
              { name => "HTTP OK",                   type => "flag",  value => 1, },
              { name => "HTTPS active",              type => "flag",  value => 1, },
              { name => "HTTPS host verified",       type => "flag",  value => 0, },
              { name => "HTTPS cert verified",       type => "flag",  value => 0, },
              { name => "HTTPS wrong host, cert OK", type => "flag",  value => 0, },
              { name => "HTTPS all verified",        type => "flag",  value => 0, },
              { name => "HTTPS OK",                  type => "flag",  value => 0, },
              { name => "HTTPS all verified and OK", type => "flag",  value => 0, },
              { name => "Redirect to HTTPS",         type => "flag",  value => 0, },
              { name => "Redirect to HTTP",          type => "flag",  value => 0, },
              { name => "Supports HSTS",             type => "flag",  value => 0, },
              { name => "HSTS max age",              type => "int",   value => undef, },
              { name => "Disables HSTS",             type => "flag",  value => 0, },
              { name => "Used cipher suite",         type => "group", value => undef, },
              { name => "Certificate issuer",        type => "group", value => undef, },
              { name => "Server full string",        type => "group", value => undef, },
              { name => "Server name",               type => "group", value => undef, },
              { name => "Server name/major version", type => "group", value => undef, },
              { name => "Supports HPKP",             type => "flag",  value => 0, },
              { name => "Supports HPKP report",      type => "flag",  value => 0, },
            ];

@result = map { { name => $ARG->{info}{name}, type => $ARG->{info}{type}, value => $ARG->{value}, } } @{ $check->run_check };

eq_or_diff( \@result, $expected, "404 on $domain" );



#use Data::Dumper;

#diag Dumper $check->_http_response;
#diag Dumper $check->_https_response;

#diag Dumper $check->_ua;



my ( $key, $value ) = Security::TLSCheck::Checks::Web::_split_hsts(q{max-age=12345});
is( $key,   "max-age", "HSTS max age key" );
is( $value, 12345,     "HSTS max age value" );

( $key, $value ) = Security::TLSCheck::Checks::Web::_split_hsts(q{max-age="6789"});
is( $key,   "max-age", "HSTS max age key (quotes)" );
is( $value, 6789,      "HSTS max age value (quotes)" );

( $key, $value ) = Security::TLSCheck::Checks::Web::_split_hsts(q{max-age = 123});
is( $key,   "max-age", "HSTS max age key (spaced)" );
is( $value, 123,       "HSTS max age value (spaced)" );

( $key, $value ) = Security::TLSCheck::Checks::Web::_split_hsts(q{Max-Age=456});
is( $key,   "max-age", "HSTS max age key (upper)" );
is( $value, 456,       "HSTS max age value (upper)" );

( $key, $value ) = Security::TLSCheck::Checks::Web::_split_hsts(q{max-age = "789"});
is( $key,   "max-age", "HSTS max age key (spaced quotes)" );
is( $value, 789,       "HSTS max age value (spaced quotes)" );



