#!/usr/bin/env perl

use strict;
use warnings;
use 5.010;

use FindBin qw($Bin);
use lib "$Bin/../lib";

use Net::SSL::CipherSuites;

use Data::Dumper;


foreach my $name (@ARGV)
   {
   my $ciphers = Net::SSL::CipherSuites->new_by_name($name);
   unless ( $ciphers->count )
      {
      say "===> NO CipherSuite found for $name!";
      next;
      }
   
   say "+++> Found CipherSuites: " . $ciphers->names;
   say Dumper($ciphers);
   say "";
   }


