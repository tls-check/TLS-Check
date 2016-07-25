package Security::TLSCheck::Checks::FinalScore;

use Moose;
extends 'Security::TLSCheck::Checks';
with 'Security::TLSCheck::Checks::Helper::Timing';

use Log::Log4perl::EasyCatch;


=head1 NAME

Security::TLSCheck::Checks::FinalScore - Creates a summary score out of the other tests

=encoding utf8

=cut

use version; our $VERSION = sprintf "%d", q$Revision: 658 $ =~ /(\d+)/xg;


=head1 SYNOPSIS

...


=head1 DESCRIPTION

This check summarizes all checks and builds a global score.


=cut

#<<<

{
my $key_figures = 
   [
   { name => "Final Web Score",         type => "int",   source => "final_web_score", description => "The Final Web Score", }, 
   { name => "Final Web Score Grouped", type => "group", source => "final_web_score", description => "The Final Web Score, but as group", }, 
   ];

has '+key_figures' => ( default => sub {return $key_figures} );
}

has '+description' => ( default => "Final Scores" );

#>>>



=head1 METHODS

=head2 final_web_score

As the name says, this method calculates the final web score.


 Score wie bisher, zusätzlich:
 DONE! Wenn keine Verschlüsselung: Fix auf 0
 Wenn Heartbleed: fix auf -10
 Wenn kein valides Zertifikat (z.B. selbstsigniert): -10
 Wenn Domain nicht zum Zertifikat passt: -20
 Wenn Strict-Transport-Security: +5 // +10!
 Wenn Strict-Transport-Securoty aktiv abgeschaltet: -5
 Wenn Public-Key-Pinning: +5
 Wenn Umleitung von HTTP auf HTTPS: +5
 Wenn Umleitung von HTTPS auf HTTP: -10
 Wenn IPv6 unterstützt: +3

 Minimum: 0, wenn keine Verschlüsselung


=cut


sub final_web_score
   {
   ## no critic (ValuesAndExpressions::ProhibitMagicNumbers)
   # TODO:
   # use constants for +/- score!

   my $self = shift;

   my $web        = $self->other_check("Security::TLSCheck::Checks::Web");
   my $ciphers    = $self->other_check("Security::TLSCheck::Checks::CipherStrength");
   my $heartbleed = $self->other_check("Security::TLSCheck::Checks::Heartbleed");
   my $dns        = $self->other_check("Security::TLSCheck::Checks::DNS");

   return 0 unless $web->https_active;
   return -10 if $heartbleed->https_vulnerable;

   my $score = $ciphers->score;
   $score -= 10 unless $web->https_cert_verified;
   $score -= 20 unless $web->https_host_verified;
   $score += 10 if $web->hsts_max_age;
   $score -= 5 if $web->disables_hsts;
   $score += 5 if $web->has_hpkp;
   $score += 5 if $web->redirects_to_https;
   $score -= 10 if $web->redirects_to_http;

   $score += 3 if $dns->count_ipv6 or $dns->count_ipv6_www;

   # Not allowed for privacy reasons!
   # TRACE "INTERNALDEBUG: Final Web Score for ${ \$self->domain }: $score";

   return $score;
   } ## end sub final_web_score


1;

