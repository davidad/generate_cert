create or replace function public.generate_p12(token varchar(32), device varchar(32)) returns text as $PERL$

my $token = $_[0];
my $device = $_[1];

use Crypt::OpenSSL::CA;
use File::Slurp;
use MIME::Base64;

my $rowset = spi_exec_query('select auth.certificate_tokens.cert_serial is not null as has_serial, auth.certificate_tokens.entry_id as entry_id, auth.uid_email.email as email, auth.uid_email.uid as uid, (main.people.name).given, (main.people.name).particle, (main.people.name).family, (auth.certificate_tokens.token_expires < now()) as expired from auth.uid_email, main.people, auth.certificate_tokens where auth.uid_email.uid = main.people.uid and auth.uid_email.email = auth.certificate_tokens.email and auth.certificate_tokens.token_digest = digest('.quote_literal($token).",'sha512');",1);

if($rowset->{processed}<1) {
    die "Invalid token"
}
my $r = $rowset->{rows}[0];
if($r->{expired}!='f') {
    die "Expired token"
}
if($r->{has_serial}!='f') {
    die "Token already has cert"
}

my $s = spi_exec_query('update auth.certificate_tokens set cert_created = now(), cert_expires = (now() + interval \'1 year\'), device_name = '.quote_literal($device).', cert_serial = nextval(\'auth.cert_serial_seq\') where entry_id = '.quote_literal($r->{entry_id}).' returning to_char((cert_created - interval \'1 day\'),\'YYYYMMDDHH24MISSZ\') as not_before, to_char(cert_expires,\'YYYYMMDDHH24MISSZ\') as not_after, cert_serial',1)->{rows}[0];

my $client_file_base = sprintf("/etc/pg_certs/clients/client_%s_%s_%0.8x",($r->{email} =~ s/[^\w]+/_/rg),($device =~ s/[^\w]+/_/rg),$s->{cert_serial});
my $client_pem_file = "$client_file_base.pem";
my $client_p12_file = "$client_file_base.p12";

system("openssl genrsa -out $client_pem_file 1024");

my $keyfile = read_file("/etc/pg_certs/ca/davidad.org.ca.key");
my $certfile = read_file("/etc/pg_certs/ca/davidad.org.ca.crt");
my $server_private_key = Crypt::OpenSSL::CA::PrivateKey->parse($keyfile, -password => "SEKRIT");
my $server_cert = Crypt::OpenSSL::CA::X509->parse($certfile);
my $server_pubkey = $server_cert->get_public_key();
my $server_dn = $server_cert->get_subject_DN();

my $client_pem = read_file($client_pem_file);
my $client_pubkey = Crypt::OpenSSL::CA::PrivateKey->parse($client_pem)->get_public_key();
my $client_cert = Crypt::OpenSSL::CA::X509->new($client_pubkey);
$client_cert->set_serial(sprintf("%#0.8x",$s->{cert_serial}));
my $client_dn = Crypt::OpenSSL::CA::X509_NAME->new(
    countryName => 'US',
    stateOrProvinceName => 'CA',
    localityName => 'San Francisco',
    organizationName => 'davidad.org',
    OU => 'davidad.org client certificate',
    SN => ((length($r->{particle})>0)?"$r->{particle} $r->{family}":$r->{family}),
    GN => $r->{given},
    CN => $r->{uid},
    emailAddress => $r->{email});
$client_cert->set_subject_DN($client_dn);
$client_cert->set_issuer_DN($server_dn);
$client_cert->set_notAfter($s->{not_after});
$client_cert->set_notBefore($s->{not_before});
$client_cert->set_extension("subjectKeyIdentifier",$client_pubkey->get_openssl_keyid);
$client_cert->set_extension("authorityKeyIdentifier",{keyid=>$server_pubkey->get_openssl_keyid});
my $pem = $client_cert->sign($server_private_key,'sha1');

my $outfile = "$client_file_base.crt";
open FILE, ">$outfile";
print FILE $pem;
close FILE;

system("openssl pkcs12 -export -nodes -out $client_p12_file -in $outfile -inkey $client_pem_file -passout 'pass:SEKRIT2'");
my $p12 = read_file($client_p12_file);
#unlink $client_pem_file;
#unlink $client_p12_file;

return encode_base64($p12,'');

$PERL$ LANGUAGE 'plperlu' security definer volatile;