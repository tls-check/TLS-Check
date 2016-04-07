package Security::TLSCheck;

use Moose;
use 5.010;


=head1 NAME

Security::TLSCheck - Application for checking server's TLS capability

=head1 VERSION

Version 1.0.2, $Revision: 651 $

=cut

#<<<
my $BASE_VERSION = "1.0.2"; use version; our $VERSION = qv( sprintf "$BASE_VERSION.%d", q$Revision: 651 $ =~ /(\d+)/xg );
#>>>


=head1 SYNOPSIS

=encoding utf8

TODO!


    use TLS::Check;

    my $foo = Security::TLSCheck->new();
    ...

=head1 DESCRIPTION

TODO: Write Description!

For a project overview, see the README.md of the Distribution.

If you want to write you own checks, look at the checks in C<Security::TLSCheck::Checks>, 
e.g. Dummy for a simple intro.

=cut

use English qw( -no_match_vars );
use FindBin qw($Bin);
use File::HomeDir;
use File::ShareDir;


#
# Configfile search:
#   1. relative to bin: $Bin../conf (for development)
#   2. /usr/local/etc (maybe /etc on linux?)
#   3. ~/
#


#$DATADIR = eval { return File::ShareDir::module_dir(__PACKAGE__) };
#$DATADIR = "$FindBin::Bin/../files/CipherSuites" if not defined $DATADIR;    # or not -d $DATADIR;



# TODO: Configfile via File::ShareDir
# Default: ~/.tls-check.conf; /usr/local/etc/tls-check.conf; /etc/tls-check.conf; File::ShareDir-Location

# Run this at begin, before logging gets initialized
# TODO: maybe write a module for this, which may eliminate the BEGIN hazzle

our $CONFIG_FILE;
our $LOG_CONFIG_FILE;

# our $LOG_DIR;
my $should_die_later;

BEGIN
{
   #  $LOG_DIR         = File::HomeDir->my_dist_data( 'TLS-Check', { create => 1 } ) // "$Bin/../logs";
   $CONFIG_FILE     = _get_configfile("tls-check.conf");
   $LOG_CONFIG_FILE = _get_configfile("tls-check-logging.properties");
   $ENV{LOG_CONFIG} = $LOG_CONFIG_FILE;            ## no critic (Variables::RequireLocalizedPunctuationVars)

   sub _get_configfile
      {
      my $name = shift;

      # 1. Look on development place
      my $file = "$Bin/../conf/$name";
      return $file if -f $file;

      # 2. look in users home dir
      $file = File::HomeDir->my_home() . "/.$name";
      return $file if -f $file;

      # 3. /usr/local/etc
      $file = "/usr/local/etc/$name";
      return $file if -f $file;

      # 4. /etc
      $file = "/etc/$name";
      return $file if -f $file;

      # and othervise look in applications share dir
      my $CONFDIR = eval { return File::ShareDir::module_dir(__PACKAGE__) } // "conf";

      # warn "Share-Dir-Eval-Error: $EVAL_ERROR" if $EVAL_ERROR;
      $file = "$CONFDIR/$name";
      return $file if -f $file;

      $should_die_later = "UUUPS, FATAL: configfile $name not found. Last try was <$file>.";
      return;

      } ## end sub _get_configfile

} ## end BEGIN

die "$should_die_later\n" if not $COMPILING and $should_die_later;



use Log::Log4perl::EasyCatch;



has app => (
             is      => "ro",
             isa     => "Object",
             default => sub { require Security::TLSCheck::App; return Security::TLSCheck::App->new; },
             handles => [qw(checks timeout user_agent_name my_hostname)],
           );

has domain   => ( is => "ro", isa => "Str", required => 1, );
has category => ( is => "ro", isa => "Str", default  => "", );


has results => (
   is      => "rw",
   isa     => "HashRef[Any]",
   default => sub { {} },
   traits  => ['Hash'],
   handles => {
                other_check      => "get",
                set_check_result => "set",
              },
   clearer => "clear_cached_results",

               );


# has cached_mx => ( is => "rw", isa => "ArrayRef[Str]", auto_deref => 1, );


=head1 METHODS

=head2 ->run_all_checks()

=cut

sub run_all_checks
   {
   my $self = shift;

   my @checks;

   DEBUG "run all checks for " . $self->domain;
   foreach my $check_name ( $self->checks )
      {
      $check_name =~ s{ [^\w\d:] }{}gx;            # strip of all not allowed chars

      #      TRACE "Load Module Security::TLSCheck::Checks::$check_name";
      #      eval "require Security::TLSCheck::Checks::$check_name;"    ## no critic (BuiltinFunctions::ProhibitStringyEval)
      #         or die "Can't use check $check_name: $EVAL_ERROR\n";

      eval {
         my $check = "Security::TLSCheck::Checks::$check_name"->new( instance => $self );

         DEBUG "run check " . $check->name . " on " . $self->domain;
         my @results = $check->run_check;
         $check->clear_instance;
         DEBUG sprintf( "Check %s on %s done in %.3f seconds", $check->name, $self->domain, $check->runtime );

         foreach my $result (@results)
            {
            push @checks,
               {
                 name   => $check->name,
                 result => $result,
                 check  => { map { $ARG => $check->$ARG } qw(class description runtime) },
               };
            }

         # caching for other checks
         # TODO: Refactor the logic!
         $self->set_check_result( $check->class             => $check );
         $self->set_check_result( $check->class . "-result" => $results[-1] );    # (temp?) last if more then 1

         return 1;
      } or ERROR "Check $check_name failed for " . $self->domain . " ($EVAL_ERROR)";

      } ## end foreach my $check_name ( $self...)

   $self->clear_cached_results;

   return wantarray ? @checks : \@checks;
   } ## end sub run_all_checks



=head1 AUTHOR

Alvar C.H. Freude, C<< <"alvar at a-blast.org"> >>

http://alvar.a-blast.org/


=head1 ACKNOWLEDGEMENTS


=head1 LICENSE AND COPYRIGHT

Copyright 2014–2016 Alvar C.H. Freude, http://alvar.a-blast.org/

Development contracted by Chamber of Commerce and Industry of the 
Stuttgart (Germany) Region and its committee of information technology, 
information services and telecommunication.

https://www.stuttgart.ihk24.de/


This program is free software; you can redistribute it and/or modify it
under the terms of the the Artistic License (2.0). You may obtain a
copy of the full license at:

L<http://www.perlfoundation.org/artistic_license_2_0>

#Any use, modification, and distribution of the Standard or Modified
#Versions is governed by this Artistic License. By using, modifying or
#distributing the Package, you accept this license. Do not use, modify,
#or distribute the Package, if you do not accept this license.
#
#If your Modified Version has been derived from a Modified Version made
#by someone other than you, you are nevertheless required to ensure that
#your Modified Version complies with the requirements of this license.
#
#This license does not grant you the right to use any trademark, service
#mark, tradename, or logo of the Copyright Holder.
#
#This license includes the non-exclusive, worldwide, free-of-charge
#patent license to make, have made, use, offer to sell, sell, import and
#otherwise transfer the Package with respect to any patent claims
#licensable by the Copyright Holder that are necessarily infringed by the
#Package. If you institute patent litigation (including a cross-claim or
#counterclaim) against any party alleging that the Package constitutes
#direct or contributory patent infringement, then this Artistic License
#to you shall terminate on the date that such litigation is filed.
#
#Disclaimer of Warranty: THE PACKAGE IS PROVIDED BY THE COPYRIGHT HOLDER
#AND CONTRIBUTORS "AS IS' AND WITHOUT ANY EXPRESS OR IMPLIED WARRANTIES.
#THE IMPLIED WARRANTIES OF MERCHANTABILITY, FITNESS FOR A PARTICULAR
#PURPOSE, OR NON-INFRINGEMENT ARE DISCLAIMED TO THE EXTENT PERMITTED BY
#YOUR LOCAL LAW. UNLESS REQUIRED BY LAW, NO COPYRIGHT HOLDER OR
#CONTRIBUTOR WILL BE LIABLE FOR ANY DIRECT, INDIRECT, INCIDENTAL, OR
#CONSEQUENTIAL DAMAGES ARISING IN ANY WAY OUT OF THE USE OF THE PACKAGE,
#EVEN IF ADVISED OF THE POSSIBILITY OF SUCH DAMAGE.


=cut

__PACKAGE__->meta->make_immutable;

1;
