package Security::TLSCheck::Checks::DNS;

use 5.010;
use strict;
use warnings;

use Carp;
use English qw( -no_match_vars );

use Moose;
extends 'Security::TLSCheck::Checks';
with 'Security::TLSCheck::Checks::Helper::Timing';
with 'Security::TLSCheck::Checks::Helper::MX';

use Net::DNS ();

use Log::Log4perl::EasyCatch;

=head1 NAME

Security::TLSCheck::Checks::DNS - Basic DNS Checks

=encoding utf8

=cut

use version; our $VERSION = sprintf "%d", q$Revision: 621 $ =~ /(\d+)/xg;


=head1 SYNOPSIS

...


=head1 DESCRIPTION

Anzahl DNS-Server, Verifizierung DNS-Server (SOA etc), Anzahl MX, IPv6; …

Gets the following values:

...

Gets the following key figures:

 * Number of ns
 * Number of mx
 * Count of all ns/mx via IPv4/IPv6
 * Count of all addresses for domain or www via IPv4/IPv6


=cut

#<<<

{
my $key_figures = 
   [
   { name => "# Nameserver",     type => "count", source => "count_ns",      description => "Number of nameservers for this domain" }, 
   { name => "# Mail Exchanger", type => "count", source => "count_mx",      description => "Number of MX for this domain" }, 
   { name => "Domain IPv4",      type => "flag",  source => "supports_ipv4", description => "Domain (or www) has IPv4 records" }, 
   { name => "Domain IPv6",      type => "flag",  source => "supports_ipv6", description => "Domain (or www) has IPv6 records" }, 
   { name => "NS IPv4",          type => "flag",  source => "count_ipv4_ns", description => "Nameserver has IPv4 records" }, 
   { name => "NS IPv6",          type => "flag",  source => "count_ipv6_ns", description => "Nameserver has IPv6 records" }, 
   { name => "MX IPv4",          type => "flag",  source => "count_ipv4_mx", description => "MX has IPv4 records" }, 
   { name => "MX IPv6",          type => "flag",  source => "count_ipv6_mx", description => "MX has IPv6 records" }, 
   { name => "Domain only IPv4", type => "flag",  source => "only_ipv4",     description => "Domain (or www) has only IPv4 records" }, 
   { name => "Domain only IPv6", type => "flag",  source => "only_ipv6",     description => "Domain (or www) has only IPv6 records" }, 
   { name => "NS only IPv4",     type => "flag",  source => "only_ipv4_ns",  description => "All nameservers have only IPv4 records" }, 
   { name => "NS only IPv6",     type => "flag",  source => "only_ipv6_ns",  description => "All nameservers have only IPv6 records" }, 
   { name => "MX only IPv4",     type => "flag",  source => "only_ipv4_mx",  description => "All MX have only IPv4 records" }, 
   { name => "MX only IPv6",     type => "flag",  source => "only_ipv6_mx",  description => "All MX have only IPv6 records" }, 
   
   { name => "Multi-IP domain IPv4", type => "group", source => "count_ipv4",     description => "Number of IPv4-IPs for the domain, grouped (count roundrobin)" }, 
   { name => "Multi-IP domain IPv6", type => "group", source => "count_ipv6",     description => "Number of IPv6-IPs for the domain, grouped (count roundrobin)" }, 
   { name => "Multi-IP www IPv4",    type => "group", source => "count_ipv4_www", description => "Number of IPv4-IPs for the www.domain, grouped (count roundrobin)" }, 
   { name => "Multi-IP www IPv6",    type => "group", source => "count_ipv6_www", description => "Number of IPv6-IPs for the www.domain, grouped (count roundrobin)" }, 
   
   ];

has '+key_figures' => ( default => sub {return $key_figures} );
}

has '+description' => ( default => "Basic DNS Checks" );

has ns             => ( is => 'rw', isa => 'ArrayRef[Str]', traits  => ['Array'], handles => { count_ns       => 'count', add_ns       => 'push', all_ns       => 'elements', }, default => sub {[]}, );
has mx             => ( is => 'rw', isa => 'ArrayRef[Str]', traits  => ['Array'], handles => { count_mx       => 'count', add_mx       => 'push', all_mx       => 'elements', }, default => sub {[]}, );
has ipv4           => ( is => 'rw', isa => 'ArrayRef[Str]', traits  => ['Array'], handles => { count_ipv4     => 'count', add_ipv4     => 'push', all_ipv4     => 'elements', }, default => sub {[]}, );
has ipv6           => ( is => 'rw', isa => 'ArrayRef[Str]', traits  => ['Array'], handles => { count_ipv6     => 'count', add_ipv6     => 'push', all_ipv6     => 'elements', }, default => sub {[]}, );
has ipv4_www       => ( is => 'rw', isa => 'ArrayRef[Str]', traits  => ['Array'], handles => { count_ipv4_www => 'count', add_ipv4_www => 'push', all_ipv4_www => 'elements', }, default => sub {[]}, );
has ipv6_www       => ( is => 'rw', isa => 'ArrayRef[Str]', traits  => ['Array'], handles => { count_ipv6_www => 'count', add_ipv6_www => 'push', all_ipv6_www => 'elements', }, default => sub {[]}, );
has ipv4_ns        => ( is => 'rw', isa => 'ArrayRef[Str]', traits  => ['Array'], handles => { count_ipv4_ns  => 'count', add_ipv4_ns  => 'push', all_ipv4_ns  => 'elements', }, default => sub {[]}, );
has ipv6_ns        => ( is => 'rw', isa => 'ArrayRef[Str]', traits  => ['Array'], handles => { count_ipv6_ns  => 'count', add_ipv6_ns  => 'push', all_ipv6_ns  => 'elements', }, default => sub {[]}, );
has ipv4_mx        => ( is => 'rw', isa => 'ArrayRef[Str]', traits  => ['Array'], handles => { count_ipv4_mx  => 'count', add_ipv4_mx  => 'push', all_ipv4_mx  => 'elements', }, default => sub {[]}, );
has ipv6_mx        => ( is => 'rw', isa => 'ArrayRef[Str]', traits  => ['Array'], handles => { count_ipv6_mx  => 'count', add_ipv6_mx  => 'push', all_ipv6_mx  => 'elements', }, default => sub {[]}, );

has _already_run   => ( is => "rw", isa => "Bool",   default    => 0, );

#>>>


=head1 METHODS

=head2 ->run_check

=cut


sub run_check
   {
   my $self = shift;

   return $self->result if $self->_already_run;

   $self->add_ns( $self->get_ns );
   $self->add_mx( $self->get_mx );

   # $self->instance->cached_mx( $self->mx );

   $self->add_ipv4( $self->_get_ip( $self->domain, "A" ) );
   $self->add_ipv6( $self->_get_ip( $self->domain, "AAAA" ) );

   $self->add_ipv4_www( $self->_get_ip( $self->www, "A" ) );
   $self->add_ipv6_www( $self->_get_ip( $self->www, "AAAA" ) );

   $self->add_ipv4_ns( $self->_get_ip( $ARG, "A" ) )    foreach $self->all_ns;
   $self->add_ipv6_ns( $self->_get_ip( $ARG, "AAAA" ) ) foreach $self->all_ns;

   $self->add_ipv4_mx( $self->_get_ip( $ARG, "A" ) )    foreach $self->all_mx;
   $self->add_ipv6_mx( $self->_get_ip( $ARG, "AAAA" ) ) foreach $self->all_mx;

   $self->_already_run(1);

   return $self->result;
   } ## end sub run_check


=head2 get_ns

returns the list of NS records for this Domain

=cut

sub get_ns
   {
   my $self   = shift;
   my $domain = $self->domain;

   DEBUG "Start DNS Query for NS records for $domain";
   my $reply = $self->_resolver->query( $domain, "NS" );
   DEBUG "DNS NS Query for $domain finished";

   unless ($reply)
      {
      DEBUG "No NS records for domain $domain Error: " . $self->_resolver->errorstring;
      $self->error( $self->_resolver->errorstring );
      return;
      }

   my @ns = map { $ARG->nsdname } grep { $ARG->type eq 'NS' } $reply->answer;

   DEBUG "found some nameserver for $domain: @ns";

   return @ns;

   } ## end sub get_ns

sub _get_ip
   {
   my $self = shift;
   my $host = shift;
   my $type = shift // "A";

   DEBUG "DNS query $type for $host";
   my $reply = $self->_resolver->search( $host, $type );
   DEBUG "Done DNS query $type for $host";

   unless ($reply)
      {
      DEBUG "No $type record found for $host";
      return;
      }

   my @result = map { $ARG->address } grep { $ARG->type eq $type } $reply->answer;

   DEBUG "Found $type addresses for $host: @result";

   return @result;
   } ## end sub _get_ip

#
# get_mx is in the externaleo
#

=head2 supports_ipv4, supports_ipv6

returns true, when the domain has an ipv4/ipv6 address record for the domain name OR a www subdomain

=cut

sub supports_ipv4
   {
   my $self = shift;
   return $self->count_ipv4 + $self->count_ipv4_www;
   }

sub supports_ipv6
   {
   my $self = shift;
   return $self->count_ipv6 + $self->count_ipv6_www;
   }


=head2 only_ipv4, only_ipv6, only_ipv4_ns, only_ipv6_ns, only_ipv4_mx, only_ipv6_mx 

returns true, when the domain or MX or NS only supports IPv4 respectively IPv6

=cut

sub only_ipv4
   {
   my $self = shift;
   return ( $self->supports_ipv4 and not $self->supports_ipv6 );
   }

sub only_ipv6
   {
   my $self = shift;
   return ( $self->supports_ipv6 and not $self->supports_ipv4 );
   }

sub only_ipv4_ns
   {
   my $self = shift;
   return ( $self->count_ipv4_ns and not $self->count_ipv6_ns );
   }

sub only_ipv6_ns
   {
   my $self = shift;
   return ( $self->count_ipv6_ns and not $self->count_ipv4_ns );
   }

sub only_ipv4_mx
   {
   my $self = shift;
   return ( $self->count_ipv4_mx and not $self->count_ipv6_mx );
   }

sub only_ipv6_mx
   {
   my $self = shift;
   return ( $self->count_ipv6_mx and not $self->count_ipv4_mx );
   }


=head2 has_ipv4_roundrobin, has_ipv6_roundrobin

returns true, when the domain or MX or NS only supports IPv4 respectively IPv6

=cut

sub has_ipv4_roundrobin
   {
   my $self = shift;
   return 1 if $self->x;
   return;
   }

sub has_ipv6_roundrobin
   {
   my $self = shift;
   return;
   }

__PACKAGE__->meta->make_immutable;
1;

