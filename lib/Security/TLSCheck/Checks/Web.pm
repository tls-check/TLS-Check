package Security::TLSCheck::Checks::Web;

use 5.010;

use Carp;
use English qw( -no_match_vars );

use Moose;
extends 'Security::TLSCheck::Checks';
with 'Security::TLSCheck::Checks::Helper::Timing';

use Log::Log4perl::EasyCatch;

use LWP::UserAgent;
use HTTP::Status qw(HTTP_OK HTTP_INTERNAL_SERVER_ERROR);

# Preload later required libraries (for parallel fork mode)
use HTTP::Response;
use HTTP::Request;
use LWP::Protocol::https;
use LWP::Protocol::http;
use Mozilla::CA;
use IO::Socket::SSL;


use Readonly;
Readonly my $NOT_FOUND => -1;


=head1 NAME

Security::TLSCheck::Checks::Web - (Basic) HTTP and HTTPS Checks

=encoding utf8

=cut

use version; our $VERSION = sprintf "%d", q$Revision: 640 $ =~ /(\d+)/xg;


=head1 SYNOPSIS

...


=head1 DESCRIPTION

This module checks some (basic) HTTP key figures:

  * HTTP / HTTPS for domain or www domain active; status OK?
  * HTTP redirects to HTTPS?
  * redirections
  * simple HTTPS Certificate Verification (via LWP with help from Mozilla::CA)
  
  
For simplification of the results, this check first tries to use http://www.domain.tld/ 
and only if this does gives an result only http://domain.tld/

So we don't have to count two results per domain, only one.


=cut

#<<<

{
my $key_figures = 
   [
   { name => "HTTP active",               type => "flag",  source => "http_active",            description => "Is there a HTTP server on Port 80? (all Status OK)", }, 
   { name => "HTTP OK",                   type => "flag",  source => "http_ok",                description => "HTTP-Server returns Status 200 OK", }, 
   { name => "HTTPS active",              type => "flag",  source => "https_active",           description => "Is there a HTTPS server on Port 443? (all states are OK)", }, 
   { name => "HTTPS host verified",       type => "flag",  source => "https_host_verified",    description => "HTTPS is active and host matches", }, 
   { name => "HTTPS cert verified",       type => "flag",  source => "https_cert_verified",    description => "HTTPS is active and certificate is verified against Mozilla::CA", }, 
   { name => "HTTPS wrong host, cert OK", type => "flag",  source => "https_cert_ok_host_not", description => "HTTPS is active but host does not match", }, 
   { name => "HTTPS all verified",        type => "flag",  source => "https_all_verified",     description => "HTTPS is active, host matches and certificate is verified against Mozilla::CA", }, 
   { name => "HTTPS OK",                  type => "flag",  source => "https_ok",               description => "HTTPS returns Status 200 OK (certificate/host not checked)", }, 
   { name => "HTTPS all verified and OK", type => "flag",  source => "https_all_ok",           description => "HTTPS returns Status 200 OK (certificate and host are checked)", }, 
   { name => "Redirect to HTTPS",         type => "flag",  source => "redirects_to_https",     description => "HTTP redirects to HTTPS", }, 
   { name => "Redirect to HTTP",          type => "flag",  source => "redirects_to_http",      description => "HTTPS redirects to HTTP", }, 
   { name => "Supports HSTS",             type => "flag",  source => "hsts_max_age",           description => "Supports HTTP Strict Transport Security", },
   { name => "HSTS max age",              type => "int",   source => "hsts_max_age",           description => "How long browsers should cache HTTP Strict Transport Security", },
   { name => "Disables HSTS",             type => "flag",  source => "disables_hsts",          description => "HTTP Strict Transport Security is disabled by server", },
   { name => "Used cipher suite",         type => "group", source => "cipher_suite",           description => "The cipher suite, selected by the server", },
   { name => "Certificate issuer",        type => "group", source => "cert_issuer",            description => "Issuer of the certificate", },
   { name => "Certificate Let's Encrypt", type => "flag",  source => "cert_letsencrypt",       description => "Issuer of the certificate is Let's Encrypt", },
   { name => "Certificate self-signed",   type => "flag",  source => "cert_selfsigned",        description => "Certificate is self-signed", },
   { name => "Cert self-signed, host OK", type => "flag",  source => "cert_selfsigned_hostok", description => "Certificate is self-signed and host matches", },
   { name => "Server full string",        type => "group", source => "server",                 description => "The full server string (HTTP)", },
   { name => "Server name",               type => "group", source => "server_name",            description => "The server name string", },
   { name => "Server name/major version", type => "group", source => "server_major_version",   description => "The server name and major version", },
   { name => "Supports HPKP",             type => "flag",  source => "has_hpkp",               description => "Server has a public key pinng header", },
   { name => "Supports HPKP report",      type => "flag",  source => "has_hpkp_report",        description => "Server has a report-only public key pinng header", },
   ];


has '+key_figures' => ( default => sub {return $key_figures} );
}

has '+description' => ( default => "(Basic) HTTP and HTTPS Checks" );

has _ua                       => ( is => "ro", isa => "LWP::UserAgent", lazy_build => 1, );
has _http_response            => ( is => "ro", isa => "HTTP::Response", lazy_build => 1, );
has _https_response           => ( is => "ro", isa => "HTTP::Response", lazy_build => 1, );
has _https_response_hostcheck => ( is => "ro", isa => "HTTP::Response", lazy_build => 1, );
has _https_response_certcheck => ( is => "ro", isa => "HTTP::Response", lazy_build => 1, );
has _https_response_nocheck   => ( is => "ro", isa => "HTTP::Response", lazy_build => 1, );


#>>>


sub _build__ua
   {
   my $self = shift;
   return LWP::UserAgent->new( timeout => $self->timeout, agent => $self->user_agent_name, );
   }

sub _build__http_response
   {
   my $self = shift;
   return $self->_do_request("http");
   }

sub _build__https_response
   {
   my $self = shift;
   return $self->_do_request("https");
   }

sub _build__https_response_hostcheck
   {
   my $self = shift;
   return $self->_do_request( "https", { verify_hostname => 1, SSL_verify_mode => IO::Socket::SSL::SSL_VERIFY_NONE } );
   }

sub _build__https_response_certcheck
   {
   my $self = shift;
   return $self->_do_request( "https", { verify_hostname => 0, SSL_verify_mode => IO::Socket::SSL::SSL_VERIFY_PEER } );
   }

sub _build__https_response_nocheck
   {
   my $self = shift;
   return $self->_do_request( "https", { verify_hostname => 0, SSL_verify_mode => IO::Socket::SSL::SSL_VERIFY_NONE } );
   }

sub _do_request
   {
   my $self     = shift;
   my $protocol = shift;
   my $ssl_opts = shift // { verify_hostname => 1, SSL_verify_mode => IO::Socket::SSL::SSL_VERIFY_PEER };

   my $ua = $self->_ua;
   $ua->ssl_opts(%$ssl_opts);

   # If check with www. if not successful, try without www
   # if this is also not successful, use the www result!
   my $response = $ua->get( "$protocol://" . $self->www );
   unless ( $response->is_success )
      {
      my $domain_response = $ua->get( "$protocol://" . $self->domain );
      $response = $domain_response if $domain_response->is_success;
      }

   return $response;
   }



=head1 METHODS

=head2 http_active, https_active, https_all_verified, https_host_verified, https_cert_verified, https_cert_ok_host_not

Checks, if there is something on port 80/443 ...

Fails when Status is 500 and there is a "Client-Warning" header with "Internal response"

   * https_active is true, if there is HTTPS, certificate verify failed, but there is https.
   * https_all_verified is only true, if certificate verification is OK and host matches.
   * https_host_verified is true, if the SSL host matches, but cert is not checked
   * https_cert_verified is true, if there is a valid certificate (Mozilla::CA), hostname not checked
   * https_cert_ok_host_not is true, if there is a valid certificate, but hostname does NOT match

=cut

#sub _has_https
#   {
#   my $self = shift;
#   return 1 if  _valid_response( $self->_https_response_nocheck );
#   return;
#   }

sub _valid_response
   {
   my $response = shift;

   return 1 unless $response->code == HTTP_INTERNAL_SERVER_ERROR;
   return 1 unless defined $response->header("Client-Warning");
   return 1 unless $response->header("Client-Warning") eq "Internal response";
   return 0;
   }

sub http_active
   {
   my $self = shift;
   return _valid_response( $self->_http_response );
   }

sub https_active
   {
   my $self = shift;

   return 1 if _valid_response( $self->_https_response_nocheck );

   # Old method; still active because tests can't check ssl_opts
   #   return 1 if $self->https_all_verified;
   # return 1 if index( $self->_https_response->status_line, "certificate verify failed" ) != $NOT_FOUND;
   return 0;
   }



sub https_all_verified
   {
   my $self = shift;
   return unless $self->https_active;              # when no HTTPS active, don't check more HTTPS
   return _valid_response( $self->_https_response );
   }

sub https_host_verified
   {
   my $self = shift;
   return unless $self->https_active;              # when no HTTPS active, don't check more HTTPS
   return _valid_response( $self->_https_response_hostcheck );
   }

sub https_cert_verified
   {
   my $self = shift;
   return unless $self->https_active;              # when no HTTPS active, don't check more HTTPS
   return _valid_response( $self->_https_response_certcheck );
   }

sub https_cert_ok_host_not
   {
   my $self = shift;
   return unless $self->https_active;              # when no HTTPS active, don't check more HTTPS
   return 1 if $self->https_cert_verified and not $self->https_host_verified;
   return 0;
   }

=head2 http_ok, https_ok, https_all_ok

Returns true if HTTP request was sucessful and no error (status Code 2xx)

=cut

sub http_ok
   {
   my $self = shift;
   return $self->_http_response->is_success;
   }

sub https_ok
   {
   my $self = shift;
   return $self->_https_response_nocheck->is_success;
   }

sub https_all_ok
   {
   my $self = shift;
   return unless $self->https_active;              # when no HTTPS active, don't check more HTTPS
   return $self->_https_response->is_success;
   }

=head2 redirects_to_https

Returns true, all HTTP Requests (on the start page) are redirected to HTTPS

=cut

sub redirects_to_https
   {
   my $self = shift;

   #use Data::Dumper;

   #   DEBUG "Redir to HTTPSSSS? Domain: " . $self->domain;
   #   DEBUG Dumper( $self->_http_response );
   #
   #

   # look at the last request in the HTTP request chain; if there
   # was a redirect to HTTPS, then there is the URI ...
   return 1 if $self->_http_response->request->uri =~ m{^https}x;
   return 0;
   }

=head2 redirects_to_http

Returns true, if HTTPS Requests (on the startpage) are redirected to HTTP

Checked for all HTTPS conections, including invalid Certs.


=cut

sub redirects_to_http
   {
   my $self = shift;

   return unless $self->https_active;              # when no HTTPS active, don't check more HTTPS


   # use Data::Dumper;

   #   DEBUG "Redir to HTTP? Domain: " . $self->domain;
   #   DEBUG Dumper( $self->_https_response );
   #


   # look at the last request in the HTTPS request chain; if there
   # was a redirect to HTTP, then there is the URI ...
   return 1 if $self->_https_response_nocheck->request->uri =~ m{^http:}x;
   return 0;
   }



=head2 hsts_max_age

Returns the max-age value of the Strict-Transport-Security header.

Checked for all certs (also when invalid).

Returns undef, if there is none.


RFC says: The max-age directive value can optionally be quoted: 

  Strict-Transport-Security: max-age="31536000"

=cut

sub hsts_max_age
   {
   my $self = shift;

   my @hsts = $self->_https_response_nocheck->header("Strict-Transport-Security");
   return unless @hsts;

   my %hsts = map { _split_hsts($ARG) } map { split( m{\s*;\s*}x, $ARG ) } @hsts;

   DEBUG "Probably parsing error: found a HSTS header, but no max_age for @hsts at " . $self->www unless defined $hsts{"max-age"};

   # remove all non-numbers, because some hsts headers are broken.
   ( my $filtered_hsts = $hsts{"max-age"} ) =~ s{\D}{}g;

   return $filtered_hsts;

   }

sub _split_hsts
   {
   my $param = shift;

   my ( $key, $value ) = $param =~ m{ ^ ([-\w]+) \s* (?: = \s* (.*) )? }x;
   $value //= "";

   # strip sourrounding " and '
   $value =~ s{ ^ (["']) (.*) \1 $}{$2}gx;

   return ( lc($key), $value );

   }



=head2 disables_hsts

Does the site resets HTTP Strict Transport Security?

This is the case, when the max_age is set to 0.

=cut

sub disables_hsts
   {
   my $self = shift;
   my $max_age = $self->hsts_max_age // return 0;

   return 1 if $max_age == 0;
   return 0;
   }


=head2 cipher_suite

Extracts the used cipher_suite from the HTTP-Headers (Client-SSL-Cipher)

Checked for all HTTPS connections, also checked when invalid certificate

=cut

sub cipher_suite
   {
   my $self = shift;
   return $self->_https_response_nocheck->header("Client-SSL-Cipher");
   }

=head2 cert_issuer

Extracts certifivate issuer from the HTTP-Headers (Client-SSL-Cert-Issuer)

ONLY FOR VALID CERTS!

=cut

sub cert_issuer
   {
   my $self = shift;
   return unless $self->https_cert_verified;       # only remember issuer, when it's a valid CA
   return $self->_https_response->header("Client-SSL-Cert-Issuer");
   }

=head2 ->cert_letsencrypt

Checks, if the cert is signed by Let's Encrypt

=cut

sub cert_letsencrypt
   {
   my $self = shift;
   my $cert_issuer = $self->cert_issuer // return;
   return index( $cert_issuer, "Let's Encrypt" ) >= 0;
   }


=head2 ->cert_selfsigned

Checks, if the cert is selfsigned

=cut

sub cert_selfsigned
   {
   my $self         = shift;
   my $cert_issuer  = $self->_https_response->header("Client-SSL-Cert-Issuer") // return;
   my $cert_subject = $self->_https_response->header("Client-SSL-Cert-Subject") // return;
   return $cert_subject eq $cert_issuer;
   }

=head2 ->cert_selfsigned_hostok

Checks, if the cert is selfsigned AND the hostname matches

=cut

sub cert_selfsigned_hostok
   {
   my $self = shift;
   return ( $self->https_host_verified and $self->cert_selfsigned );
   }


=head2 server

Extracts server string from Server header. 

=cut

sub server
   {
   my $self = shift;
   return $self->_http_response->header("Server");
   }

=head2 server_name

Server name, without other informations (Version, modules, ...)

=cut

sub server_name
   {
   my $self = shift;
   return _get_server_name( $self->server );
   }

sub _get_server_name
   {
   my $server = shift // return;

   my ($name) = $server =~ m{ ^ ([^/]*) }x;
   return $name if length($name) < 20;             ## no critic (ValuesAndExpressions::ProhibitMagicNumbers)

   $name =~ s{ ( [^\w\s].* ) }{}xg;

   return $name;

   }


=head2 server_major_version

Server name and major version, without other informations (patchlevel, modules, ...)

=cut

sub server_major_version
   {
   my $self = shift;

   return _get_server_major_version( $self->server );

   }

sub _get_server_major_version
   {
   my $server = shift // return;

   my ($name_version) = $server =~ m{ ( [-\w\s]+ (?: / \d+ (?:[.]\d+) )? ) }x;

   return $name_version // _get_server_name($server);

   }


=head2 has_hpkp

Supports HTTP Public Key pinning (Public-Key-Pins Header).

Checked for all HTTPS conections, including invalid Certs.

=cut

sub has_hpkp
   {
   my $self = shift;
   return 1 if $self->_https_response_nocheck->header("Public-Key-Pins");
   return 0;
   }


=head2 has_hpkp_report

Supports HTTP Public Key pinning, report only (Public-Key-Pins-Report-Only Header).

Checked for all HTTPS conections, including invalid Certs.


=cut

sub has_hpkp_report
   {
   my $self = shift;
   return 1 if $self->_https_response_nocheck->header("Public-Key-Pins-Report-Only");
   return 0;
   }



__PACKAGE__->meta->make_immutable;

1;

