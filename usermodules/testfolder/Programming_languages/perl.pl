#!/usr/bin/env perl
# example.pl — długi plik testowy dla highlightera Perl
use strict;
use warnings;
use feature 'say';
use Encode qw(encode decode);
use Fcntl qw(:flock);
use IO::Handle;
use Time::HiRes qw(time sleep);
use Data::Dumper;

# POD example at top of file
=pod

=head1 NAME

example.pl - comprehensive Perl syntax test file

=head1 DESCRIPTION

This file contains many Perl constructs to stress-test syntax highlighting.

=cut

BEGIN {
    # BEGIN block: executed at compile time
    $| = 1;    # autoflush STDOUT
    print "BEGIN initialisation\n" if $ENV{EXAMPLE_DEBUG};
}

# package / module-like section
package My::Example::Class;
use Carp qw(croak carp);
our $VERSION = '0.01';
our @EXPORT_OK = qw(make_point);

# A constant with subroutine prototype style
sub PI () { 3.141592653589793 }

# constructor, bless, methods
sub new {
    my ($class, %args) = @_;
    my $self = {
        x => $args{x} // 0,
        y => $args{y} // 0,
        name => $args{name} // 'anon',
    };
    return bless $self, $class;
}

sub norm {
    my ($self) = @_;
    return sqrt($self->{x} ** 2 + $self->{y} ** 2);
}

sub set {
    my ($self, %args) = @_;
    $self->{$_} = $args{$_} for keys %args;
    return $self;
}

sub make_point {
    my ($x, $y) = @_;
    return { x => $x, y => $y };
}

# sub with prototype and default values, and :lvalue (edge-case)
sub counter(\@;$) {
    my ($arr_ref, $start) = @_;
    $start ||= 0;
    return sub { ++$start };
}

# demonstrate sub declaration styles
sub fancy {
    my ($a, $b) = @_;
    return sprintf("fancy:%s/%s", $a, $b);
}

# a multi-line anonymous sub assigned to a variable
my $anon = sub {
    my ($msg) = @_;
    return uc($msg);
};

# lexical variables, arrays and hashes
my $scalar = "Hello, 世界";    # unicode text
my @array = (1, 2, 3, 4, 5);
my %hash = ( apple => 'red', banana => 'yellow', cherry => 'red' );

# complex data structures: array of hashes, hash of arrayrefs
my @people = (
    { name => 'Anna', age => 30, nick => 'annie' },
    { name => 'Bob', age => 45, nick => 'bobby'  },
);

my %groups = (
    admins => [ 'Anna', 'Root' ],
    users  => [ 'Bob', 'Carol', 'Dave' ],
);

# references and dereferencing
my $aref = \@array;
my $href = \%hash;
my $first = $aref->[0];
my $color_of_apple = $href->{apple};

# file I/O with locking and binmode UTF-8
open my $fh, ">:encoding(UTF-8)", "example_output.txt" or die "Can't open output: $!";
flock($fh, LOCK_EX);
print $fh "Output starts at " . scalar(localtime) . "\n";
print $fh "Scalar: $scalar\n";
flock($fh, LOCK_UN);
close $fh;

# here-docs examples
my $here1 = <<"EOF";
This is a simple heredoc.
It supports "quotes" and 'single quotes' without escaping.
EOF

my $here2 = <<'NOINT';
No interpolation here: $scalar will NOT expand.
NOINT

my $here3 = <<`CMD`;
uname -a
CMD

# qq, q, qx usage:
my $double_q = qq{He said "Hello"};
my $single_q = q{A single-quoted string (no interpolation)};
my $exec_back = qx{echo "ping"};   # backticks equivalent

# regex examples: match, qr, substitution, transliteration, modifiers
my $text = "The quick brown fox jumps over 13 lazy dogs.";
if ($text =~ /quick\s+(brown)\s+(\w+)/i) {
    my $color = $1;
    my $animal = $2;
}

my $regex = qr{fox.*?(\d+)}msx;

# substitution with different delimiters and modifiers
$text =~ s/13/thirteen/;
$text =~ s{quick\s+brown}{slow white}i;
$text =~ s!lazy!energetic!g;

# transliteration
(my $t = "héllo") =~ tr/éèê/eee/;

# capture variables $1, $2 usage, and named capture (Perl 5.10+)
if ($text =~ /(?<who>fox)\s+(\w+)/) {
    my $who = $+{who};
}

# qr// compiled regex used later
my $q = qr{(\w+)\s+dogs}i;
if ($text =~ $q) {
    my $m = $1;
}

# complex substitution with evaluation
my %repl = ( 'thirteen' => 13 );
$text =~ s/(\w+)/ exists $repl{lc $1} ? $repl{lc $1} : $1 /ge;

# split/join examples
my @tokens = split /[\s,]+/, $text;
my $joined = join "-", @tokens;

# map/grep with blocks
my @upper = map { uc($_) } @tokens;
my @reds  = grep { $hash{$_} && $hash{$_} eq 'red' } keys %hash;

# sort with custom comparator
my @sorted_by_age = sort { $a->{age} <=> $b->{age} } @people;

# eval/die/warn and exception handling
eval {
    die "Something bad happened";
};
if ($@) {
    warn "Caught error: $@";
}

# system, backticks, IPC
my $ls = `ls -1 2>/dev/null` // '';
my $status = system("echo", "hello");

# object-oriented: simple package and bless usage
package My::Counter;
sub new {
    my ($class, $start) = @_;
    $start ||= 0;
    bless \$start, $class;
}
sub inc {
    my ($self) = @_;
    $$self++;
    return $$self;
}
package main;

my $c = My::Counter->new(10);
$c->inc();
$c->inc();

# Demonstrate $/ and input record separator, and <> diamond operator
{
    local $/ = undef;    # slurp mode
    # but don't actually read files here
}

# POD block example within code
=pod

=head2 Example Function

Below is a sample function that demonstrates many constructs.

=cut

sub example_complex {
    my ($arg) = @_;
    # conditional / loops
    for my $i (0..3) {
        next if $i == 2;
        print "i = $i\n";
    }

    my $sum = 0;
    foreach my $v (@array) {
        $sum += $v;
    }

    # nested anonymous subs and closures
    my $adder = sub {
        my $base = shift;
        return sub { $base + shift };
    };
    my $add5 = $adder->(5);
    my $res = $add5->(3);

    return ($sum, $res);
}

# Heredoc with interpolation and special quoting
my $data = <<'RAW';
This is raw: $scalar will not expand here.
RAW

my $data2 = <<"INT";
This will expand: $scalar and @{[join(',', @array)]}
INT

# File test: read filehandle with different layers
open my $in, "<:encoding(UTF-8)", "example_output.txt" or warn "Can't open: $!";
if ($in) {
    while (my $line = <$in>) {
        chomp $line;
        # regex with code block
        $line =~ s{(\d+)}{ sprintf("[%03d]", $1) }eg;
    }
    close $in;
}

# Formats (old-school)
format STDOUT_TOP =
********** REPORT **********
.
format STDOUT =
@<<<<<< @<<<<<<<<<<<<<<<<<<<<
$scalar, $text
.

# tie / untie example (very simple)
{
    package TiedScalar;
    sub TIESCALAR { bless \do{my $x}, shift }
    sub FETCH { ${$_[0]} }
    sub STORE { ${$_[0]} = $_[1] }
}
my $obj = tie my $ts, 'TiedScalar';
$ts = "tied value";
untie $ts;

# Special regex cases: m{...}, m!...!, m!...!i
my $s = "abc123";
if ($s =~ m{[a-z]+(\d+)}i) {
    my $num = $1;
}

# substitution with eval and /e modifier
my $code = '2+3';
$code =~ s/(\d+)/$1+0/eg;   # transforms digits

# POD inline =item usage
=pod

=item * Bullet point example

=cut

# more regex edge cases, including nested groups and lookarounds (PCRE-like constructs are not all in core),
# but Perl supports a lot, so test some:
my $phone = "Tel: +48 (22) 123-45-67";
if ($phone =~ /(\+\d{1,3})\s*\((\d{1,4})\)\s*([\d-]+)/) {
    my ($cc, $area, $rest) = ($1, $2, $3);
}

# complex quoting operators: qx, qq, q, qw
my @words = qw(one two three);
my $joined_words = join ",", @words;
my $exec = qx(echo "hello world");

# Interpolation and variable forms inside strings
my $complex = "User: $ENV{USER} PID: $$ Time: @{[time]}";

# Unicode examples
use utf8;
my $u = "Zażółć gęślą jaźń — 漢字 and emoji 🎉";

# Demonstrate prototypes and special sub names
sub add ($$) { $_[0] + $_[1] }
my $sum = add(2, 3);

# Using map/grep with complex blocks
my @mapped = map { my $x = $_ * 2; $x > 5 ? $x : () } (1..10);

# System calls and backticks with error checking
my $out = `date`;
my $rc = $? >> 8;

# Signal handling example
$SIG{INT} = sub { warn "Caught INT\n"; };

# Last END block
END {
    print "END cleanup\n" if $ENV{EXAMPLE_DEBUG};
}

# A final run-through: build a sample output demonstrating many values
sub run_demo {
    my ($self) = @_;
    say "Scalar: $scalar";
    say "Array first: $array[0]";
    say "Hash apple: $hash{apple}";
    say "Here-doc1 length: " . length($here1);
    say "Upper tokens: @upper[0..4]";
    my ($sum, $res) = example_complex();
    say "Sum: $sum Res: $res";
    return 1;
}

# call demo
run_demo();

# trailing POD for end-of-file documentation
=pod

=head1 AUTHOR

Generated for syntax-highlighting tests.

=cut
