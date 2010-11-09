use strict;
use warnings;
use Test::More tests => 11;
use Digest::ECHO;

new_ok('Digest::ECHO' => [$_], "algorithm $_") for qw(224 256 384 512);

is(eval { Digest::ECHO->new },     undef, 'no algorithm specified');
is(eval { Digest::ECHO->new(10) }, undef, 'invalid algorithm specified');

can_ok('Digest::ECHO',
    qw(clone algorithm hashsize add digest hexdigest b64digest)
);

for my $alg (qw(224 256 384 512)) {
    my $d1 = Digest::ECHO->new($alg);
    is(
        $d1->add('foobar')->hexdigest, $d1->clone->hexdigest,
        "clone of $alg"
    );
}
