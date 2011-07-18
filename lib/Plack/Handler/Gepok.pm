package Plack::Handler::Gepok;
use strict;
use Gepok;

sub new {
    my $class = shift;
    my $self = bless { @_ }, $class;

    # translate different option names
    if ($self->{port}) {
        $self->{http_ports} //= [($self->{host} // "") . ":" . $self->{port}];
        delete $self->{port};
        delete $self->{host};
    }
    $self;
}

sub run {
    my($self, $app) = @_;
    Gepok->new(%$self)->run($app);
}

1;

__END__

=head1 NAME

Plack::Handler::Gepok - Plack adapter for Gepok

=head1 SYNOPSIS

  plackup -s Gepok

=head1 SEE ALSO

L<Gepok>

=cut


