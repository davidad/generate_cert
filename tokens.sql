create or replace function public.generate_token() returns text
    as $$ select trim(trailing '=' from translate(encode(gen_random_bytes(8),'base64'),'ABGIMNOPQSUVZaceilmnosuwz01248+/','CDEFHJKLRTWXYbdfghjkpqrtvxy35679')); $$ language sql;

create or replace function send_token_pl() returns trigger as $PERL$

use Email::Simple;
use Email::Simple::Creator;
use Email::Sender::Simple qw(sendmail);
use Email::Sender::Transport::Sendmail;
use Try::Tiny;
my $transport = Email::Sender::Transport::Sendmail->new();

my $sslport = "";

my $u = spi_exec_query('select generate_token() as token, (main.people.name).nick, (main.people.name).prefix_abb, (main.people.name).given_abb, (main.people.name).particle, (main.people.name).family, (main.people.name).suffix_abb, auth.uid_email.email from main.people, auth.uid_email where main.people.uid=auth.uid_email.uid and auth.uid_email.email='.quote_literal($_TD->{new}{email}).';',1)->{rows}[0];
my $token = $u->{token};
spi_exec_query('update auth.certificate_tokens set token_expires=now() where email='.quote_literal($_TD->{new}{email})."and token_expires>now() and entry_id != ".quote_literal($_TD->{new}{entry_id}).";");

my $email = Email::Simple->create(
    header => [
        To => "$u->{prefix_abb} $u->{given_abb} $u->{family}".$u->{suffix_abbr}." <$u->{email}>",
        From => 'Nemaload Authentication <auth@nemaload.davidad.org>',
        Subject => "Authentication Token (requested)",
        'Content-Type' => 'text/plain; charset="utf-8"'
    ],
    body => <<"EOF"
Hi $u->{nick},

To proceed to the next phase, open this link: https://nemaload.davidad.org$sslport/login?token=$token

Or copy the token:
        $token

Please note that this token expires in 10 minutes, but don't worry - you can always request another:
        https://nemaload.davidad.org$sslport/login?email=$u->{email}

Cheers,
- The Nemaload Website
EOF
);

try {
    sendmail($email,{transport=>$transport});
    spi_exec_query('update auth.certificate_tokens set token_digest = digest('.quote_literal($token).",'sha512'), token_sent=clock_timestamp() where entry_id=".quote_literal($_TD->{new}{entry_id}).";");
    return undef;
} catch {
    elog ERROR, "sending failed: $_";
    return "SKIP";
}

$PERL$ LANGUAGE 'plperlu' volatile;

create trigger send_token_trigger
    after insert on auth.certificate_tokens
    for each row execute procedure send_token_pl();

create or replace function public.send_token(varchar(256)) returns table (email varchar(256), expires timestamptz, nick varchar(32), formal_address text)
    as $$
    declare
        entry integer;
        expires timestamptz;
    begin
        begin
            insert into certificate_tokens (email) values ($1) returning entry_id, token_expires into entry, expires;
            return query select $1 as email, expires, (main.people.name).nick, formal_address(main.people.name) as formal_address from people, uid_email where people.uid=uid_email.uid and uid_email.email=$1;
        exception when foreign_key_violation or check_violation then
            insert into unknown_emails (email) values ($1);
            return;
        end;
    end;
    $$ language plpgsql security definer set search_path = auth, main, public, pg_temp;

create or replace function public.pre_send_token(varchar(256)) returns table (email varchar(256), nick varchar(32), formal_address text) as $$
    begin
        return query select $1 as email, (main.people.name).nick, formal_address(main.people.name) as formal_address from people, uid_email where people.uid=uid_email.uid and uid_email.email=$1;
        if not found then
            begin
                insert into unknown_emails (email) values ($1);
            exception when not_null_violation then
                null;
            end;
        end if;
        return;
    end
    $$ language plpgsql security definer set search_path = auth, main, public, pg_temp;