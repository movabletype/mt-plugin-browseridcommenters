package BrowserIDCommenters::Auth;
use strict;
use warnings;

sub password_exists {0}

sub return_true { 1 }

sub handle_sign_in {
    my $class = shift;
    my ( $app, $auth_type ) = @_;
    my $q = $app->param;
    my $assertion = $q->param("browserid_assertion");
    $assertion =~ s/[^\w\-\.]//g;
    my $blog = $app->blog;
    my ($blog_domain) = ( $blog ? $blog->archive_url : $app->base ) =~ m|^.+://([^/]+)|;
    my $ua = MT->new_ua( { paranoid => 1 } );

    require HTTP::Request;
    my $request = HTTP::Request->new(POST => "https://browserid.org/verify");
    $request->content_type('application/x-www-form-urlencoded');
    $request->content("assertion=".$assertion."&audience=$blog_domain");
    my $response = $ua->request($request);

    return $app->error("Can not connect to authonticating server, Error Code:".$response->code())
        unless $response->is_success;
    require JSON;
    # responses seen until now:
    # {"status":"failure","reason":"Payload has expired."}
    # {"status":"okay","email":"shmuelfomberg@gmail.com","audience":"localhost","valid-until":1313467972012,"issuer":"browserid.org:443"}
    my $answer = JSON::from_json($response->decoded_content());
    return $app->error("Authonticating end in ".$answer->{status}.", reason:".$answer->{reason})
        unless $answer->{status} eq 'okay';

    my $name = $answer->{email};
    my $author_class = $app->model('author');
    my $cmntr = $author_class->load(
        {   name      => $name,
            type      => $author_class->COMMENTER(),
            auth_type => $auth_type,
        }
    );
    if (not $cmntr) {
        my $nickname = $name;
        $nickname =~ s/\@.*//;
        $cmntr = $app->make_commenter(
            name        => $name,
            email       => $name,
            nickname    => $nickname,
            auth_type   => $auth_type,
        );
    }
    return $app->error("Failed to created commenter")
        unless $cmntr;

    $app->make_commenter_session($cmntr) 
        or return $app->error("Failed to create a session");
    
    return $cmntr;
}

sub commenter_auth_params {
    my ($key, $blog_id, $entry_id, $static) = @_;
    require MT::Util;
    if ($static =~ m/^http%3A%2F%2F/) {
        # the URL was encoded before, but we want the normal version
        $static = MT::Util::decode_url($static);
    }
    my $params = {
        blog_id => $blog_id,
        static  => $static,
    };
    $params->{entry_id} = $entry_id if defined $entry_id;
    return $params;
}

1;