package Net::SSL::Handshake::Extensions::EllipticCurves;

use Moose;
extends "Net::SSL::Handshake::Extensions";



=encoding utf8

=head1 NAME

Net::SSL::Handshake::Extensions::EllipticCurves - client extension for TLS Handshake to show supported elliptic courves

=head1 VERSION

Version 0.1.x, $Revision: 640 $

=cut

use version; our $VERSION = qv( "v0.1." . ( sprintf "%d", q$Revision: 640 $ =~ /(\d+)/xg ) );

has "+type" => ( default => 0x000a );



=head1 SYNOPSIS

=encoding utf8

   use Net::SSL::Handshake::Extensions::EllipticCurves;
   
   my $ec = Net::SSL::Handshake::Extensions::EllipticCurves->new( );
   my $data = $ec->data;
   #...

=head1 DESCRIPTION

=cut

# List of "supported" elliptic courves
# at the moment hardcoded!
# TODO: make this as option (via attribute)!

my @curves = qw(0017 0019 001c 001b 0018 001a 0016 000e 000d 000b 000c 0009 000a);

sub BUILD
   {
   my $self = shift;

   # $self->add( "n C n a*", $length+3, 0, $length, $idn_host);

   my $curves_bin = pack( "(H4)*", @curves );
   $self->add( "n a*", length($curves_bin), $curves_bin );

   return;
   }



1;
