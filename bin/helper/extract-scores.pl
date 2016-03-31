#!/usr/bin/env perl


use strict;
use warnings;

use 5.010;

my $category;
my $base;

say "Category,Base,cipher_score,version_score,count";

while (<>)
   {
   chomp;
   $category = $1 if m{Category (\S+)};
   $base     = $1 if m{(CipherStrength\w*)};
   
   while ( m{cipher(\d+)-version(\d+) => (\d+)}g )
      {
      say "$category,$base,$1,$2,$3";
      }
   
   }

