use Data::Dumper;
use Test::More;
require_ok(OAuthSimple);

my $apiKey = 'abcdefghijk';
my $secret = 'sikkret012i)))3';
my $halfSignatures = {
    'oauth_token'=>'TOKEN_value',
    'oauth_secret'=>'0987sikkret'
};
my $fullSignatures = {
    'oauth_consumer_key'=>$apiKey,'shared_secret'=>$secret,
    'oauth_token'=>'zyxw','oauth_secret'=>'0987'
};

my $path = 'http://example.com/oauth/';
my $argsAsString = 'term=mac%20and+me&expand=formats,synopsis&max_results=1&v=2.0&output=json';
my $argsAsHash = {
        term=>'mac and me',
        expand=>'formats,synopsis',
        max_results=>1,
        v=>'2.0',
        output=>'json',
        # The following are only for testing purposes and should NOT be included
        # for production.
        oauth_nonce=>'aaaa',
        oauth_timestamp=>1234567890,
    };

my $oauth = new OAuthSimple($apiKey,$secret);
ok(defined $oauth, 'new');
ok($oauth->isa('OAuthSimple'), 'class');

my $ret = $oauth->sign({path=>$path,
                        parameters=>$argsAsHash,
                    });

is($ret->{header},
    'OAuth oauth_consumer_key="abcdefghijk", oauth_nonce="aaaa", oauth_signature="xCSxnlogab8zqJy2acNu6wElIRk%3D", oauth_signature_method="HMAC-SHA1", oauth_timestamp="1234567890", oauth_version="1.0"',
   'has header');
ok(defined $ret->{parameters}, 'has parameters');
is($ret->{signature}, 'xCSxnlogab8zqJy2acNu6wElIRk%3D', 'signature matched expected');
is($ret->{sbs}, 'GET&http%3A%2F%2Fexample.com%2Foauth%2F&expand%3Dformats%252Csynopsis%26max_results%3D1%26oauth_consumer_key%3Dabcdefghijk%26oauth_nonce%3Daaaa%26oauth_signature_method%3DHMAC-SHA1%26oauth_timestamp%3D1234567890%26oauth_version%3D1.0%26output%3Djson%26term%3Dmac%2520and%2520me%26v%3D2.0',
    'sbs matches expected');
is($ret->{signed_url},
    'http://example.com/oauth/?expand=formats%2Csynopsis&max_results=1&oauth_consumer_key=abcdefghijk&oauth_nonce=aaaa&oauth_signature_method=HMAC-SHA1&oauth_timestamp=1234567890&oauth_version=1.0&output=json&term=mac%20and%20me&v=2.0',
    'signed_url matches expected');

$oauth->reset();
my $ret = $oauth->sign({'path'=>$path});
ok (defined $ret, 'returned elemens for simple path');
done_testing()
