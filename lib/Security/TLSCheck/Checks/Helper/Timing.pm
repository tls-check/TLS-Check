package Security::TLSCheck::Checks::Helper::Timing;

use Moose::Role;

use Time::HiRes qw(time);


=head1 NAME

Security::TLSCheck::Checks::Helper::Timing - Timing helpers for run_check

=encoding utf8

=cut

use version; our $VERSION = qv( "v0.2." . ( sprintf "%d", q$Revision: 640 $ =~ /(\d+)/xg ) );


=head1 SYNOPSIS

As check subclass:

 package Security::TLSCheck::Checks::MyCheck
 
 use Moose;
 extends 'Security::TLSCheck::Checks';
 with    'Security::TLSCheck::Helper::Timing';


=head1 DESCRIPTION

This role sets method modifiers for timing.

=cut

requires qw(run_check start_time end_time);

before run_check => sub { shift->start_time(time); };
after run_check => sub { my $self = shift; $self->end_time(time); };


1;

