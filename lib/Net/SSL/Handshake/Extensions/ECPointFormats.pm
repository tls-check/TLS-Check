package Net::SSL::Handshake::Extensions::ECPointFormats;

use Moose;
extends "Net::SSL::Handshake::Extensions";



=encoding utf8

=head1 NAME

Net::SSL::Handshake::Extensions::ECPointFormats - client extension for TLS Handshake to show supported elliptic courves

=head1 VERSION

Version 0.1.x, $Revision: 658 $

=cut

use version; our $VERSION = qv( "v0.1." . ( sprintf "%d", q$Revision: 658 $ =~ /(\d+)/xg ) );

has "+type" => ( default => 0x000b );



=head1 SYNOPSIS

=encoding utf8

   use Net::SSL::Handshake::Extensions::ECPointFormats;
   
   my $ecp = Net::SSL::Handshake::Extensions::ECPointFormats->new( );
   my $data = $ecp->data;
   #...

=head1 DESCRIPTION

=cut

# List of "supported" EC point formats
# at the moment hardcoded!
# TODO: make this as option (via atrribute)!

my @ec_point_formats = ( 0, 1, 2 );

sub BUILD

   {
   my $self = shift;

   $self->add( "C C*", scalar @ec_point_formats, @ec_point_formats );

   return;
   }



1;
