package Digest::ECHO;

use strict;
use warnings;
use parent qw(Exporter Digest::base);

use MIME::Base64 ();

our $VERSION = '0.02';
$VERSION = eval $VERSION;

eval {
    require XSLoader;
    XSLoader::load(__PACKAGE__, $VERSION);
    1;
} or do {
    require DynaLoader;
    DynaLoader::bootstrap(__PACKAGE__, $VERSION);
};

our @EXPORT_OK = qw(
    echo_224 echo_224_hex echo_224_base64
    echo_256 echo_256_hex echo_256_base64
    echo_384 echo_384_hex echo_384_base64
    echo_512 echo_512_hex echo_512_base64
);

# TODO: convert to C.
sub echo_224_hex  { unpack 'H*', echo_224(@_) }
sub echo_256_hex  { unpack 'H*', echo_256(@_) }
sub echo_384_hex  { unpack 'H*', echo_384(@_) }
sub echo_512_hex  { unpack 'H*', echo_512(@_) }

sub echo_224_base64 {
    my $b64 = MIME::Base64::encode(echo_224(@_), '');
    $b64 =~ s/=+$//g;
    return $b64;
}
sub echo_256_base64 {
    my $b64 = MIME::Base64::encode(echo_256(@_), '');
    $b64 =~ s/=+$//g;
    return $b64;
}
sub echo_384_base64 {
    my $b64 = MIME::Base64::encode(echo_384(@_), '');
    $b64 =~ s/=+$//g;
    return $b64;
}
sub echo_512_base64 {
    my $b64 = MIME::Base64::encode(echo_512(@_), '');
    $b64 =~ s/=+$//g;
    return $b64;
}

sub add_bits {
    my ($self, $data, $bits) = @_;
    if (2 == @_) {
        return $self->_add_bits(pack('B*', $data), length $data);
    }
    return $self->_add_bits($data, $bits);
}


1;

__END__

=head1 NAME

Digest::ECHO - Perl interface to the ECHO digest algorithm

=head1 SYNOPSIS

    # Functional interface
    use Digest::ECHO qw(echo_256 echo_256_hex echo_256_base64);

    $digest = echo_256($data);
    $digest = echo_hex_256($data);
    $digest = echo_base64_256($data);

    # Object-oriented interface
    use Digest::ECHO;

    $ctx = Digest::ECHO->new(256);

    $ctx->add($data);
    $ctx->addfile(*FILE);

    $digest = $ctx->digest;
    $digest = $ctx->hexdigest;
    $digest = $ctx->b64digest;

=head1 DESCRIPTION

The C<Digest::ECHO> module provides an interface to the ECHO message
digest algorithm. ECHO is a candidate in the NIST SHA-3 competition.

This interface follows the conventions set forth by the C<Digest> module.

=head1 FUNCTIONS

The following functions are provided by the C<Digest::ECHO> module. None
of these functions are exported by default.

=head2 echo_224($data, ...)

=head2 echo_256($data, ...)

=head2 echo_384($data, ...)

=head2 echo_512($data, ...)

Logically joins the arguments into a single string, and returns its ECHO
digest encoded as a binary string.

=head2 echo_224_hex($data, ...)

=head2 echo_256_hex($data, ...)

=head2 echo_384_hex($data, ...)

=head2 echo_512_hex($data, ...)

Logically joins the arguments into a single string, and returns its ECHO
digest encoded as a hexadecimal string.

=head2 echo_224_base64($data, ...)

=head2 echo_256_base64($data, ...)

=head2 echo_384_base64($data, ...)

=head2 echo_512_base64($data, ...)

Logically joins the arguments into a single string, and returns its ECHO
digest encoded as a Base64 string, without any trailing padding.

=head1 METHODS

The object-oriented interface to C<Digest::ECHO> is identical to that
described by C<Digest>, except for the following:

=head2 new

    $echo = Digest::ECHO->new(256)

The constructor requires the algorithm to be specified. It must be one of:
224, 256, 384, 512.

=head2 algorithm

=head2 hashsize

Returns the algorithm used by the object.

=head1 SEE ALSO

L<Digest>

L<http://crypto.rd.francetelecom.com/echo/>

L<http://en.wikipedia.org/wiki/NIST_hash_function_competition>

L<http://www.saphir2.com/sphlib/>

=head1 REQUESTS AND BUGS

Please report any bugs or feature requests to
L<http://rt.cpan.org/Public/Bug/Report.html?Digest-ECHO>. I will be
notified, and then you'll automatically be notified of progress on your bug
as I make changes.

=head1 SUPPORT

You can find documentation for this module with the perldoc command.

    perldoc Digest::ECHO

You can also look for information at:

=over

=item * GitHub Source Repository

L<http://github.com/gray/digest-echo>

=item * AnnoCPAN: Annotated CPAN documentation

L<http://annocpan.org/dist/Digest-ECHO>

=item * CPAN Ratings

L<http://cpanratings.perl.org/d/Digest-ECHO>

=item * RT: CPAN's request tracker

L<http://rt.cpan.org/Public/Dist/Display.html?Name=Digest-ECHO>

=item * Search CPAN

L<http://search.cpan.org/dist/Digest-ECHO/>

=back

=head1 COPYRIGHT AND LICENSE

Copyright (C) 2010 gray <gray at cpan.org>, all rights reserved.

This library is free software; you can redistribute it and/or modify it
under the same terms as Perl itself.

=head1 AUTHOR

gray, <gray at cpan.org>

=cut
