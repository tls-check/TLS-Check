#!/usr/bin/env perl

# call: time check_lwp_preload.pl


use strict;
use warnings;

use 5.010;

use LWP::Simple;
use Parallel::ForkManager;

#use LWP::UserAgent;
#use HTTP::Status qw(HTTP_OK HTTP_INTERNAL_SERVER_ERROR);
#
## Preload later required libraries (for parallel fork mode)
#use HTTP::Response;
#use HTTP::Request;
#use LWP::Protocol::https;
#use LWP::Protocol::http;
#use Mozilla::CA;
#use IO::Socket::SSL;
#
# getstore( "https://wurzelgnom.a-blast.org/", "dummy.out" );


# Testergebnisse nach lokal
# ohne preload
# 71.671u 10.781s 0:51.90 158.8%	10+166k 996+0io 0pf+0w
# 72.038u 10.904s 0:52.55 157.8%	10+166k 1007+0io 0pf+0w

# mit Preload UND pre-Getstore:
# 16.736u 5.329s 0:44.20 49.8%	9+164k 1005+0io 0pf+0w
# 16.825u 5.226s 0:51.08 43.1%	9+164k 984+0io 0pf+0w


# mit Preload OHNE pre-Getstore:
# 22.280u 6.506s 0:48.39 59.4%	10+166k 952+0io 0pf+0w
# 22.006u 6.808s 0:48.32 59.6%	9+164k 992+0io 0pf+0w





my @links = map { [ "https://wurzelgnom.a-blast.org/", "run-$_" ] } 1 .. 1000;

# Max processes for parallel download
my $pm = Parallel::ForkManager->new(20);

LINKS:
foreach my $linkarray (@links)
   {
   $pm->start and next LINKS;                      # do the fork

   my ( $link, $fn ) = @$linkarray;
   warn "Cannot get $fn from $link"
      if getstore( $link, $fn ) != RC_OK;

   $pm->finish;                                    # do the exit in the child process
   }


$pm->wait_all_children;
