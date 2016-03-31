package Net::SSL::Handshake::Extensions::ServerName;

use Moose;
extends "Net::SSL::Handshake::Extensions";

use Net::IDN::Encode qw(domain_to_ascii);


=encoding utf8

=head1 NAME

Net::SSL::Handshake::Extensions::ServerName - SNI extension for TLS Handshake

=head1 VERSION

Version 0.1.x, $Revision: 629 $

=cut

use version; our $VERSION = qv( "v0.1." . ( sprintf "%d", q$Revision: 629 $ =~ /(\d+)/xg ) );

has "+type" => ( default => 0 );

has hostname => ( is => "ro", isa => "Str", required => 1, );



=head1 SYNOPSIS

=encoding utf8

   use Net::SSL::Handshake::Extensions::ServerName;
   
   my $sni = Net::SSL::Handshake::Extensions::ServerName->new( hostname => $hostname );
   my $data = $sni->data;
   #...

=head1 DESCRIPTION

=cut

sub BUILD
   {
   my $self = shift;

   my $idn_host = domain_to_ascii( $self->hostname );

   my $length = length($idn_host);
   $self->add( "n C n a*", $length+3, 0, $length, $idn_host);

   return;
   }



1;
