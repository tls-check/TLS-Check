#!/usr/bin/env perl

use 5.010;
use strict;
use warnings FATAL => 'all';
use FindBin qw($Bin);
use English qw( -no_match_vars );

use utf8;

use Test::More;

plan tests => 187;

package Test::DomainFilter;

use Moose;
with 'Security::TLSCheck::App::DomainFilter';

package main;


my $df = Test::DomainFilter->new();

sub df_ok
   {
   my $input   = shift;
   my $wanted  = shift;
   my $message = shift;

   my $domain = $df->filter_domain($input);

   my $wanted_defined = $wanted // "<undef>";
   $message = "'$input' => '$wanted_defined'" unless defined $message;
   return is( $domain, $wanted, $message );
   }

df_ok( "www.test.de",           "test.de" );
df_ok( "test.de",               "test.de" );
df_ok( "http://www.test.de",    "test.de" );
df_ok( "http//www.test.de",     "test.de" );
df_ok( "http:/www.test.de",     "test.de" );
df_ok( "http:www.test.de",      "test.de" );
df_ok( "http:\\\\www.test.de",  "test.de" );
df_ok( "http:\\www.test.de",    "test.de" );
df_ok( "https://www.test.de",   "test.de" );
df_ok( "https//www.test.de",    "test.de" );
df_ok( "https:/www.test.de",    "test.de" );
df_ok( "https:www.test.de",     "test.de" );
df_ok( "https:\\\\www.test.de", "test.de" );
df_ok( "https:\\www.test.de",   "test.de" );

df_ok( "//www.test.de",             "test.de" );
df_ok( "/www.test.de",              "test.de" );
df_ok( "http:http://www.test.de",   "test.de" );
df_ok( "http://http:www.test.de",   "test.de" );
df_ok( "http://http://www.test.de", "test.de" );
df_ok( "http:/http://www.test.de",  "test.de" );
df_ok( "http://http:/www.test.de",  "test.de" );


df_ok( "htttp://www.test.de", "test.de" );
df_ok( "htp://www.test.de",   "test.de" );
df_ok( "htpp://www.test.de",  "test.de" );

# some undef lists ...

foreach my $domain (qw(t-online.de arcor.de gmx.de web.de hotmail.de hotmail.com gmx.com yahoo.de yahoo.com t-online.com))
   {
   df_ok( $domain,             undef );
   df_ok( "www.$domain",       undef );
   df_ok( "testbert\@$domain", undef );
   }



df_ok( "www test.de",             "test.de" );
df_ok( "www test de",             "test.de" );
df_ok( "www test:de",             "test.de" );
df_ok( "test:de",                 "test.de" );
df_ok( "www.test:de",             "test.de" );
df_ok( "www test-de",             "test.de" );
df_ok( "test-de",                 "test.de" );
df_ok( "www.test-de",             "test.de" );
df_ok( "www test,de",             "test.de" );
df_ok( "test,de",                 "test.de" );
df_ok( "www.test,de",             "test.de" );
df_ok( "www.test de",             "test.de" );
df_ok( "test de",                 "test.de" );
df_ok( "test..de",                "test.de" );
df_ok( "www.test..de",            "test.de" );
df_ok( "www..test.de",            "test.de" );
df_ok( "www. test.de",            "test.de" );
df_ok( "test info",               "test.info" );
df_ok( "www.info",                "www.info" );
df_ok( "http://www.info",         "www.info" );
df_ok( "www.info:80",             "www.info" );
df_ok( "http://www.info:80",      "www.info" );
df_ok( "http://www.test.info:80", "test.info" );

df_ok( "www,test.de",        "test.de" );
df_ok( "test,de",            "test.de" );
df_ok( "http://www,test,de", "test.de" );


df_ok( 'hans@wurst.de',     'wurst.de' );
df_ok( 'hans@www.wurst.de', 'wurst.de' );

df_ok( 'bettina.beispiel@t-online.de',         undef );
df_ok( 'bettina.beispiel@tonline.de',          undef );
df_ok( 'bettina.beispiel@t online.de',         undef );
df_ok( 'irgendwer@arcor.de',                   undef );
df_ok( 'max-mustermann1988@gmx.de',            undef );
df_ok( 'someone@hotmail.de',                   undef );
df_ok( 'someone@hotmail.com',                  undef );
df_ok( 'www.test.de@yahoo.de',                 undef );
df_ok( 'www.t-online.de',                      undef );
df_ok( 'http://home.t-online.de/emma.example', undef );

df_ok( 'http://www.some-domain.info/hansi.hanswurst', 'some-domain.info' );
df_ok( 'http://some-domain.info/hansi.hanswurst',     'some-domain.info' );
df_ok( 'some-domain.info/hansi.hanswurst',            'some-domain.info' );
df_ok( 'http:/www.some-domain.info/hansi.hanswurst',  'some-domain.info' );
df_ok( 'http//some-domain.info/hansi.hanswurst',      'some-domain.info' );
df_ok( 'some-domain.info/hansi.hanswurst/index.html', 'some-domain.info' );

df_ok( "bettina beispiel.de",  "bettinabeispiel.de" );
df_ok( "bettina- beispiel.de", "bettina-beispiel.de" );
df_ok( "bettina -beispiel.de", "bettina-beispiel.de" );

df_ok( "mydomain.community",           "mydomain.community" );
df_ok( "mydomain.community/test",      "mydomain.community" );
df_ok( "mydomain.community/test.html", "mydomain.community" );

df_ok( "htp-online.de",             "htp-online.de" );
df_ok( "www.htp-online.de",         "htp-online.de" );
df_ok( "http-online.de",            "http-online.de" );
df_ok( "www.http-online.de",        "http-online.de" );
df_ok( "http://htp-online.de",      "htp-online.de" );
df_ok( "http://www.htp-online.de",  "htp-online.de" );
df_ok( "http://http-online.de",     "http-online.de" );
df_ok( "http://www.http-online.de", "http-online.de" );

df_ok( "www-online.de",            "www-online.de" );
df_ok( "www.www-online.de",        "www-online.de" );
df_ok( "ww-online.de",             "ww-online.de" );
df_ok( "www.ww-online.de",         "ww-online.de" );
df_ok( "http://www-online.de",     "www-online.de" );
df_ok( "http://www.www-online.de", "www-online.de" );
df_ok( "http://ww-online.de",      "ww-online.de" );
df_ok( "http://www.ww-online.de",  "ww-online.de" );

df_ok( "WWW.TEST.DE",        "test.de" );
df_ok( "TEST.DE",            "test.de" );
df_ok( "HTTP://WWW.TEST.DE", "test.de" );
df_ok( "HttP://WWW.TEST.DE", "test.de" );
df_ok( "http://WWW.TEST.DE", "test.de" );
df_ok( "www.TEST.DE",        "test.de" );
df_ok( "t-online.DE",        undef );

df_ok( "http.de",            "http.de" );
df_ok( "www.http.de",        "http.de" );
df_ok( "http://www.http.de", "http.de" );
df_ok( "http://http.de",     "http.de" );

# now it is here: changed from .de to .gmbh: perhaps there will be a TLD gmbh in future!
df_ok( "autohaus-hutzelhausen-gmbh",             "autohaus-hutzelhausen.gmbh" );
df_ok( "www.autohaus-hutzelhausen-gmbh",         "autohaus-hutzelhausen.gmbh" );
df_ok( "www..autohaus-hutzelhausen-gmbh",        "autohaus-hutzelhausen.gmbh" );
df_ok( "http://www..autohaus-hutzelhausen-gmbh", "autohaus-hutzelhausen.gmbh" );

df_ok( "hutzelhausen-ag",             "hutzelhausen.ag" );
df_ok( "www.hutzelhausen-ag",         "hutzelhausen.ag" );
df_ok( "http://www.hutzelhausen-ag",  "hutzelhausen.ag" );
df_ok( "http://www..hutzelhausen-ag", "hutzelhausen.ag" );
df_ok( "http://hutzelhausen-ag",      "hutzelhausen.ag" );

df_ok( "blablacom",            "blabla.com" );
df_ok( "blablade",             "blabla.de" );
df_ok( "http://blablacom",     "blabla.com" );
df_ok( "http://blablade",      "blabla.de" );
df_ok( "http://www.blablacom", "blabla.com" );
df_ok( "http://www.blablade",  "blabla.de" );

df_ok( "invalid.tld", undef );

df_ok( 'hans@wurst.de',                'wurst.de' );
df_ok( 'www.hans@wurst.de',            'wurst.de' );
df_ok( 'hans@www.wurst.de',            'wurst.de' );
df_ok( 'http://www.hans@www.wurst.de', 'wurst.de' );

df_ok( 'some.long.domain.info',             'some.long.domain.info' );
df_ok( 'www.some.long.domain.info',         'some.long.domain.info' );
df_ok( 'ww.some.long.domain.info',          'some.long.domain.info' );
df_ok( 'http://some.long.domain.info',      'some.long.domain.info' );
df_ok( 'http://www.some.long.domain.info',  'some.long.domain.info' );
df_ok( 'http:\\\\ww.some.long.domain.info', 'some.long.domain.info' );
df_ok( 'http.//some.long.domain.info',      'some.long.domain.info' );

df_ok( 'ätsch.de',            'ätsch.de' );
df_ok( 'www.ätsch.de',        'ätsch.de' );
df_ok( 'http://ätsch.de',     'ätsch.de' );
df_ok( 'http://www.ätsch.de', 'ätsch.de' );

df_ok( 'test.dee', 'test.de' );
df_ok( 'test.deu', 'test.de' );
df_ok( 'test.d',   'test.de' );
df_ok( 'test.e',   'test.de' );

df_ok( 'dee.test.dee', 'dee.test.de' );
df_ok( 'deu.test.deu', 'deu.test.de' );
df_ok( 'd.test.d',     'd.test.de' );
df_ok( 'e.test.e',     'e.test.de' );

df_ok( 'hkttp://www.test.de', 'test.de' );
df_ok( 'htto://www.test.de',  'test.de' );
df_ok( 'htttp://www.test.de', 'test.de' );
df_ok( 'httt://www.test.de',  'test.de' );
df_ok( 'hkttp://test.de',     'test.de' );
df_ok( 'htto://test.de',      'test.de' );
df_ok( 'htttp://test.de',     'test.de' );
df_ok( 'httt://test.de',      'test.de' );

df_ok( "www.ourworld.compuserve.com.homepages/Irgendwer", "ourworld.compuserve.com" );

df_ok( 'http://www.test-domain', 'test-domain.de' );
df_ok( 'www.test-domain',        'test-domain.de' );
df_ok( 'test-domain',            undef );
df_ok( 'test domain',            undef );

df_ok( 'www.domain.info ; www.andere-domain.info', 'domain.info' );
df_ok( 'www.domain.info.',                         'domain.info' );
df_ok( 'www domain.info.',                         'domain.info' );


df_ok( "replace-all", "everything-replaced.tld" );

#
done_testing();
