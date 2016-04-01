# TLS-Check – Collect information about domains and their servers

TLS-Check is 

1. a modular framework for collecting and summarizing arbitrary key figures for a lot of domains and their running servers (usually Web- and Mailserver) 
2. a software for analyzing and summarizing the security and encryption of given domains, e.g. supported SSL/TLS-Versions and cipher suites.

Its primary goal is to get key figures about SSL/TLS connections. It can count how many servers support encryption or not, good or weak SSL/TLS-Versions, good or weak cipher suites, how many websites or mailservers are vulnerable to security problems like Heartbleed, how many support IPv6, how many support all recommendations of the BSI or Bettercrypto project and much much more.

TLS-Check comes with a lot of checks. But it is very easy to add more tests. It is highly modular and each part of the code can be replaced (e.g. input or output).

Development contracted by Chamber of Commerce and Industry of the Stuttgart (Germany) Region and its committee of information technology, information services and telecommunication.


## Why writing another SSL/TLS testing tool? What are the primary goals?

There are a lot of tools, which check servers for their SSL/TLS capabilities (e.g. SSLyze, OWASP O-Saft, ssl-cipher-suite-enum, testssl.sh and much more). But none meets all our requirements at starting with TLS-Check in 2014:

* We need a flexible and extensible tool to check every possible key figure for a given domain – e.g. from counting how many servers support IPv6 or the different top level domains to counting how many supports the really old SSLv2 protocol.
* The most important subtests in TLS-Check are SSL/TLS checks. TLS-Check uses it's own SSL/TLS handshake implementation, because we found no acceptable other solution. Some of the tools for checking SSL/TLS cipher suites are really ugly hacks, violating all best practice rules, have no or very few automated tests, have ugly spaghetti code, are unmaintainable or buggy. TLS-Check is not free of errors, but tries to have testable, extendable, maintainable code.
* It should allow to check every known or unknown cipher suite, not limited to e.g. the cipher suites supported by OpenSSL. Because TLS-Check uses it's own code for SSL/TLS Handshake, it supports every possible ciphersuite. It knows about 362 different cipher suites, 455 with duplicates.
* It should be easy to add new checks: *It makes easy things easy and hard things possible – reliable, testable.*
* Tests must run in parallel to reduce the runtime.
* We have some limitations because of privacy reasons.
* The output should be parseable. The output of TLS-Check is CSV by default, for import in Excel, Numbers, LibreOffice or similar. But it is easy to write a module which outputs the result as JSON, XML or whatever.


## Checks

TLS-Check comes with the following check modules; they are enabled by default. If a check is dependant on another, then the order is important. The default order is fine.

For more Documentation see the doc in Security::TLSCheck::Checks::xxx

* **DNS** – Does some DNS Checks, tests for IPv4 and IPv6 IPs, counts MX (Mail eXchanger).
* **Web** – Basic web tests: check if there is a website and if HTTPS is supported; redirect checks and some more.
* **Mail** - Checks if the MX are reachable an support STARTTLS; DNS must run before, some results are used here.
* **Dummy** – A small and simple example module; counts the top level domains.
* **CipherStrength** – Checks for supported SSL/TLS versions and cipher suites of websites, checks if BSI and Bettercrypto recommendations are met and much more. Web must run first, its output is used.
* **MailCipherStrength** – the same, but for mailserver. Mail must run before.
* **CipherStrengthOnlyValidCerts** – exactly the same as CipherStrength, but counts only web cipher strengths when the certificate is valid. CipherStrength must run first, its result is used.
* **AgeDE** – checks, if a server supports the german age declaration for youth protection and which default/minimum age are given. Web must run first.
* **Heartbleed** – Heartbleed check, web and mail; Web and DNS must run before.
* **FinalScore** – calculates a final score for websites (only websites). Web and CipherStrength must run before.

As example here a summary of the most important tests of a real life check, generated with TLS-Check and converted with the summary script: 
* [TLS-Check summary IHK Region Stuttgart, Q1 2016](https://www.stuttgart.ihk24.de/blob/sihk24/Fuer-Unternehmen/innovation/downloads/3300084/5a1ce6ed286e7385afb6e878a95dcc65/TLS-Check---Zusammenfassung-data.pdf) (in german)

Full output has much more details.


## Installation

TLS-Check was developed on FreeBSD and OS X, but also works with Linux. It's not tested on Windows. TLS-Check is written in Perl with Moose and uses a lot of CPAN modules.

### Install as packages

The most easy way to install TLS-Check is using FreeBSD and install it as port or package.

    # TODO: port coming soon!
    cd /usr/ports/security/tls-check && make install clean
    # Or as package (the same TODO)
    pkg install security/tls-check

### Manual installation on Linux/Unix/…: 

Download and unpack it. Run 

    perl Build.PL

It may complain about missing dependencies. Install them manually with your favorite package manager or use the buildin CPAN installer:

    ./Build installdeps

Because this runs a lot of tests, this takes a long time. If you want to do DNS checks on IDN-Domains, the installation of the `Net::LibIDN` module is necessary. But this needs the LibIDN library, so you should install this before.

Then you may install TLS-Check:

    ./Build install

As alternative you can start everything without installing directly from `bin`, e.g. as `bin/tls-check-parallel.pl`.


## Example Usage

### Short summary

    tls-check-parallel.pl --files=path/to/domain-file.txt --outfile=result/my-result.csv
    csv-result-to-summary.pl result/my-result.csv > result/summary.csv

You may also run it without parameter, then it gets input from STDIN and writes the result to STDOUT.

csv-result-to-summary.pl is a hack to extract the most important results and create an easy to read CSV, which can be used with LibreOffice, Excel, Numbers, … But at the moment the descriptions of the summary are in german.

You can also use the full result, but it's hard to read.

### More detailed usage

After installation there are some new executables:

    tls-check.pl
    tls-check-parallel.pl
  
They are the same, but, tls-check-parallel can query domains in parallel.

Usage:

    > tls-check-parallel.pl --help
    usage: tls-check-parallel.pl [-?h] [long options...]
      --configfile STR          Configuration file
      --jobs INT                Number of max. parallel worker jobs
      --log_config STR          Alternative logging config
      --checks STR...           List of checks to run
      --user_agent_name STR     UserAgent string for web checks
      --my_hostname STR         Hostname for SMTP EHLO etc.
      --timeout INT             Timeout for networking
      --separator STR           CSV Separator char(s)
      --files STR...            List of files with domain names to check
      --verbose                 Verbose Output/Logging
      --temp_out_interval INT   Produce temporary output every # Domains
      -h -? --usage --help      Prints this usage information.
      --undef_string STR        String for undef with show_options
      --show_options            List all Options
      --results KEY=STR...       
      --outfile STR             Output file name; - for STDOUT (default)

Each config parameter can be set in the configuration file. This is searched in the following places:

    ~/.tls-check.conf
    /usr/local/etc/tls-check.conf
    /etc/tls-check.conf
    <perl installation dir>/tls-check.conf

You can view the default and used values by adding `--show_options`:

    tls-check-parallel.pl --show_options
    tls-check-parallel.pl --configfile=~/my-config.conf --show_options

The domain file is a CSV and has one or more colums: first column is a domain name, the second a category; so it looks usually like:

    domain.tld;Category
    other-domain.tld;Other Category

It's OK to have no category, so the file simply contains one domain per line.

If you have enough memory it's OK to set --jobs to a high value. But at the moment the parallel mode is not optimal.


### Logfiles

You find log files (trace, info and error) usually in ~/.perl/dist/TLS-Check by default, or in your data-directory if your OS supports this. When running without installation, the logfiles will stored in the logs folder in die main diretory.


## Bugs

It's sure, that there are bugs. Please report them, patches and fixes are welcome.

### Known other issues

* Some documentation (POD) for code and internal API should be (re)written
* Parallel fork mode does not scale well, should be rewritten with a fork pool and queue handling
* Some tests are written for execution in my local development environment, should be rewritten
* write more and better tests, e.g. with different SSL implementations
* Single standalone program for getting SSL/TLS properties should be rewritten (Net::SSL::GetServerProperties module should provide list of all checks)
* Split some modules into extra Distributions
* publish everything on CPAN (after splitting in distributions)
* There are some other TODOs … ;-)
* MX handling works as expected, but should be rewritten, e.g. to better handle categories


## Author

TLS-Check is written by [Alvar C.H. Freude](http://alvar.a-blast.org/), 2014–2016.

Development contracted by Chamber of Commerce and Industry of the Stuttgart (Germany) Region and its committee of information technology, information services and telecommunication.

https://www.stuttgart.ihk24.de

## Links

* [TLS-Check page, IHK Region Stuttgart](https://www.stuttgart.ihk24.de/Fuer-Unternehmen/innovation/E-Businessberatung/IT-Sicherheits-Check/664320)  (in german)
* [TLS-Check summary IHK Region Stuttgart, Q1 2016](https://www.stuttgart.ihk24.de/blob/sihk24/Fuer-Unternehmen/innovation/downloads/3300084/5a1ce6ed286e7385afb6e878a95dcc65/TLS-Check---Zusammenfassung-data.pdf); output from the TLS-Check summary script (in german)
* [Description TLS Check and results](https://www.stuttgart.ihk24.de/blob/sihk24/Fuer-Unternehmen/innovation/downloads/3300070/801b0ef29405c1710223f9a76bc24c06/TLS-Check-Ergebnisse-data.pdf) (in german)
* [Bettercrypto project](https://bettercrypto.org), [Bettercrypto guide](https://bettercrypto.org/static/applied-crypto-hardening.pdf) with copy&paste configuration examples for hardening your servers (in english)
* [BSI Guideline TR-01102-2](https://www.bsi.bund.de/SharedDocs/Downloads/DE/BSI/Publikationen/TechnischeRichtlinien/TR02102/BSI-TR-02102-2.html) (in german)
* [Press Release IHK Region Stuttgart](https://www.stuttgart.ihk24.de/presse/Pressemitteilungen/IHK-Pressemitteilungen_2016/Januar-bis-Maerz_2016/PM-Nr--17-Sicherheitscheck/3302518) to the first public launch (in german)

## License 

TLS-Check is licensed under the [Artistic License 2.0](https://opensource.org/licenses/Artistic-2.0) or the [European Public Licence 1.1 (EUPL)](https://joinup.ec.europa.eu/community/eupl/og_page/european-union-public-licence-eupl-v11).


