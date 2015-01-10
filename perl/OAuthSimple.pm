use strict;
use Data::Dumper;
# OAuthSimple
# A simpler version of OAuth
#
# author:     jr conlin
# mail:       src@jrconlin.com
# copyright:  unitedHeroes.net
# version:    1.2
# url:        http://unitedHeroes.net/OAuthSimple
#
# Copyright (c) 2011, unitedHeroes.net
#
# Redistribution and use in source and binary forms, with or without
# modification, are permitted provided that the following conditions are met:
#     * Redistributions of source code must retain the above copyright
#       notice, this list of conditions and the following disclaimer.
#     * Redistributions in binary form must reproduce the above copyright
#       notice, this list of conditions and the following disclaimer in the
#       documentation and/or other materials provided with the distribution.
#     * Neither the name of the unitedHeroes.net nor the
#       names of its contributors may be used to endorse or promote products
#       derived from this software without specific prior written permission.
#
# THIS SOFTWARE IS PROVIDED BY UNITEDHEROES.NET ''AS IS'' AND ANY
# EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE IMPLIED
# WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE ARE
# DISCLAIMED. IN NO EVENT SHALL UNITEDHEROES.NET BE LIABLE FOR ANY
# DIRECT, INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY, OR CONSEQUENTIAL DAMAGES
# (INCLUDING, BUT NOT LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS OR SERVICES;
# LOSS OF USE, DATA, OR PROFITS; OR BUSINESS INTERRUPTION) HOWEVER CAUSED AND
# ON ANY THEORY OF LIABILITY, WHETHER IN CONTRACT, STRICT LIABILITY, OR TORT
# (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY OUT OF THE USE OF THIS
# SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF SUCH DAMAGE.
#

# Define a custom Exception for easy trap and detection
#
package OAuthSimpleException;
    use Data::Dumper;
    use base qw(Error);
    use overload ('""' => 'stringify');

    sub stringify {
        my $this = shift;
        my $class = ref($this) || $this;

        return "$class Exception: ". Dumper($this);
        ## TODO: Prettify this
    };
1;


package OAuthSimple;
=pod

=head1 NAME

OAuthSimple

=head1 SYNOPSIS

    use OAuthSimple;

    $oauth = new OAuthSimple();
    $ret = $oauth->sign({path=>"http://jrconlin.com",
                  signatures=>{oauth_consumer_key=>'abcd', shared_secret=>'1234',
                               oauth_token=>'zyxw', oauth_secret=>'0987'},
                  parameters=>{term=>'Mac and Me','v'=>'2.0',foo=>[1,2,3]});
    `curl -v $ret->{signed_url}`;

=head1 DESCRIPTION

OAuthSimple was built to provide a simple, intuitive way to do OAuth signatures.


This class only builds the OAuth elements, it does not do the actual
transmission or reception of the tokens. It does not validate elements
of the token. It is for client use only.

oauth_consumer_key is the API key, shared_secret is the shared secret (duh).

Both the oauth_consumer_key and shared_secret are generally provided by the site
offering OAuth services. You need to specify them at object creation
because nobody <explative>ing uses OAuth without that minimal set of
signatures.

If you want to use the higher order security that comes from the
OAuth token (sorry, I don't provide the functions to fetch that because
sites aren't horribly consistent about how they offer that), you need to
pass those in either with .signatures() or as an argument to the
.sign() or .getHeaderString() functions.

that will sign as a "GET" using "SHA1-MAC" the url. If you need more than
that, read on, McDuff.

=cut

    use Error qw(:try); # required for exception handling
    use MIME::Base64;   # required for OAuth
    use Digest::SHA;
    use URI::Escape;

=pod

=head2 B<new OAuthSimple>([I<oauth_consumer_key>, I<shared_secret>]);

Create a new instance of OAuthSimple, optionally initializing the low security signature elements.

=over

=item api_key {string}

 The API Key (sometimes referred to as the consumer key) This value is usually supplied by the site you wish to use.

=item shared_secret (string) 

The shared secret. This value is also usually provided by the site you wish to use.

=back

=cut
    sub new {
        my $this = {_secrets=>{},
                    _parameters=>{},
                    _default_signature_method=>'HMAC-SHA1',
                    _action=>"GET",
                    _nonce_chars=>"0123456789ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz"};
        my $class = shift;
        $class = ref($class) || $class;
        bless $this,$class;

        my ($apikey,$sharedSecret) = @_;

        if (!empty($apikey)) {
            $this->{_secrets}->{oauth_consumer_key} = $apikey;
        }
        if (!empty($sharedSecret)) {
            $this->{_secrets}->{shared_secret}=$sharedSecret;
        }
        return $this;
    }

=pod 

=head2 B<reset>();

Reinitialize the current OAuthSimple object, purging parameters and paths, but keeping signature values. Useful for subsequent calls.

=cut
    sub reset {
        my $this = shift;

        $this->{_parameters}=undef;
        $this->{path}=undef;
        $this->{sbs}=undef;
        return $this;    
    }

=pod

=head2 B<setParameters>(I<parameters>)

set the parameters either from a hash or a string

=over

=item {string or HASH} 

List of parameters for the call, this can either be a URI string (e.g. "foo=bar&gorp=banana" or an hash)

=back

=cut
    sub setParameters {
        my $this = shift;
        my $parameters = shift;
        
        if (defined($parameters)) {
            if (ref($parameters) eq '') {
                $parameters = $this->_parseParameterString($parameters);
            }
            if (empty($this->{_parameters})) {
                $this->{_parameters} = $parameters;
            }
            elsif (!empty($parameters)) {
                $this->{_parameters} = array_merge($this->{_parameters},$parameters);
            }
        }
        if (empty($this->{_parameters}->{oauth_nonce})) {
            $this->_getNonce();
        }
        if (empty($this->{_parameters}->{oauth_timestamp})) {
            $this->_getTimeStamp();
        }
        if (empty($this->{_parameters}->{oauth_consumer_key})) {
            $this->_getApiKey();
        }
        if (empty($this->{_parameters}->{oauth_token})) {
            $this->_getAccessToken();
        }
        if (empty($this->{_parameters}->{oauth_signature_method})) {
            $this->setSignatureMethod();
        }
        if (empty($this->{_parameters}->{oauth_version})) {
            $this->{_parameters}->{oauth_version}="1.0";
        }
        return $this;
    }

=pod

=head2 B<setQueryString>(I<parameters>)

Convenience method for setParameters();

=cut
    sub setQueryString {
        my $this=shift;
        my $parameters = @_;

        return $this->setParameters($parameters);
    }


=pod

=head2 B<setURL>(I<URL>);

 Set the target URL (does not include the parameters)

=over

=item path {string} 

the fully qualified URI (excluding query arguments) (e.g "http://example.org/foo")

=back

=cut
    sub setPath {
        my $this=shift;
        my $path=shift;

        if (empty($path)) {
            Error::throw OAuthSimpleException('No path specified');
        }
        $this->{_path}=$path;
        return $this;
    }

=pod

=head2 setURL(I<URL>)

convienence method for setPath

=cut
    sub setURL {
        my $this=shift;

        return $this->setPath(shift);
    }

=pod

=head2 B<setAction>(I<action>);

set the "action" for the url, (e.g. GET,POST, DELETE, etc.)

=over

=item action {string} 

HTTP Action word.

=back

=cut
    sub setAction {
        my $this=shift;
        my $action=uc(shift || 'GET');

        if ($action =~ /[^A-Z]/) {
            Error::throw OAuthSimpleException('Invalid action specified for OAuthSimple.setAction');
        }
        $this->{_action} = $action;
        return $this;
    }

=pod

=head2 B<signatures>(I<signatureHash>)

set the signatures (as well as validate the ones you have)

=over 

=item signatures {object} 

object/hash of the token/signature pairs {oauth_consumer_key:, shared_secret:, oauth_token: oauth_secret:}

=back

=cut
    sub signatures {
        my $this=shift;
        my $signatures=shift;

        if (!empty($signatures) && ref($signatures) ne 'HASH') {
            Error::throw OAuthSimpleException('Must pass HASH to OAuthSimple.signatures');
        }
        if (!empty($signatures)) {
            $this->{_secrets} = array_merge($signatures,$this->{_secrets});
        }
# Aliases
        if (defined($this->{_secrets}->{api_key})) {
            $this->{_secrets}->{oauth_consumer_key} = $this->{_secrets}->{api_key};
        }
        if (defined($this->{_secrets}->{consumer_key})) {
            $this->{_secrets}->{oauth_consumer_key} = $this->{_secrets}->{consumer_key};
        }
        if (defined($this->{_secrets}->{access_token})) {
            $this->{_secrets}->{oauth_token} = $this->{_secrets}->{access_token};
        }
        if (defined($this->{_secrets}->{access_secret})) {
            $this->{_secrets}->{oauth_secret} = $this->{_secrets}->{access_secret};
        }
        if (defined($this->{_secrets}->{access_token_secret})) {
            $this->{_secrets}->{oauth_secret} = $this->{_secrets}->{access_token_secret};
        }
# Gauntlet
        if (empty($this->{_secrets}->{oauth_consumer_key})) {
            Error::throw OAuthSimpleException('Missing required oauth_consumer_key in OAuthSimple.signatures');
        }
        if (empty($this->{_secrets}->{shared_secret})) {
            Error::throw OAuthSimpleException('Missing requires shared_secret in OAuthSimple.signatures');
        }
        if (!empty($this->{_secrets}->{oauth_token}) && empty($this->{_secrets}->{oauth_secret})) {
            Error::throw OAuthSimpleException('Missing oauth_secret for supplied oauth_token in OAuthSimple.signatures');
        }
        return $this;
    }


=pod

=head2 setTokensAndSecrets(I<signatureHash>)

Convenience method for signatures

=cut
    sub setTokensAndSecrets {
        my $this = shift;

        return $this->signatures(shift);
    }

=pod 

=head2 setSignatureMethod(I<method>)

set the signature method (currently only Plaintext or SHA-MAC1) Currently defaults to Plaintext

=over

=item method {string} 

Method of signing the transaction (only PLAINTEXT and SHA-MAC1 allowed for now)

=back

=cut
    sub setSignatureMethod {
        my $this = shift;
        my $method = shift || $this->{_default_signature_method};

        $method = uc($method);
        if($method eq 'PLAINTEXT' || $method eq 'HMAC-SHA1') {
            $this->{_parameters}->{oauth_signature_method}=$method;
        } else {
            Error::throw OAuthSimpleException ("Unknown signing method $method specified for OAuthSimple.setSignatureMethod");
        }
        return $this;
    }

=pod

=head2 B<sign>(I<arguments>)

sign the request

note: all arguments are optional, provided you've set them using the other helper functions.

=over 

=item args {object} 

hash of arguments for the call. Allowed elements are:

=over

=item action

=item path

=item parameters (hash)

=item method

=item signatures (hash)

=back

=back

=cut
    sub sign {
        my $this=shift;
        my $args=shift;

        if (!empty($args->{action})) {
            $this->setAction($args->{action});
        }
        if (!empty($args->{path})) {
            $this->setPath($args->{path});
        }
        if (!empty($args->{method})) {
            $this->setSignatureMethod($args->{method});
        } 
        if (!empty($args->{signatures})) {
            $this->signatures($args->{signatures});
        }
        $this->setParameters($args->{parameters});
        my $normParams = $this->_normalizedParameters();
        $this->{_parameters}->{oauth_signature} = $this->_generateSignature($normParams);
        return {
            'parameters' => $this->{_parameters},
            'signature' => $this->_oauthEscape($this->{_parameters}->{oauth_signature}),
            'signed_url' => $this->{_path} . '?' . $normParams,
            'header' => $this->getHeaderString(),
            'sbs'=> $this->{sbs}
            };
    }

=pod

=head2 B<getHeaderString>(I<args>)

Return a formatted "header" string

NOTE: This doesn't set the "Authorization: " prefix, which is required.
I don't set it because various set header functions prefer different
ways to do that.

=over

=item args {object} 

see .sign()

=back
=cut;
    sub getHeaderString { 
        my $this=shift;
        my $args=shift;
        my $result = 'OAuth ';

        if (empty($this->{_parameters}->{oauth_signature})) {
            $this->sign($args);
        }

        my ($pName,$pValue);
        while (($pName,$pValue) = each %{$this->{_parameters}}) {
            my $pValue = $this->{_parameters}->{$pName};
            if ($pName !~ /^oauth_/) {
                next;
            }
            if (ref($pValue) eq 'ARRAY')
            {
                foreach my $val (@$pValue)
                {
                    $result .= $pName .'="' . $this->_oauthEscape($val) . '", ';
                }
            }
            else
            {
                $result .= $pName . '="' . $this->_oauthEscape($pValue) . '", ';
            }
        }
        $result =~ s/, +$//;
        return $result;
    }

# Start private methods. Here be Dragons.
# No promises are kept that any of these functions will continue to exist
# in future versions.
    sub _parseParameterString {
        my $this=shift;
        my $paramString=shift;

        my @elements = split('&',$paramString);
        my $result = {};

        foreach my $element (@elements) {
            my ($key,$token) = split('=',$element);
            if ($token) {
                $token = URI::Escape::uri_unescape($token);
            }
            if (!empty($result->{$key})) {
                if (ref($result->{$key} ne 'ARRAY')) {
                    $result->{$key} = [$result->{$key},$token];
                } else {
                    push(@{$result->{$key}},$token);
                }
            } else {
                $result->{$key}=$token;
            }
        }
        return $result;
    }

    sub _oauthEscape {
        my $this=shift;
        my $string=shift;

        if (empty($string)) {
            return '';
        }
        if (ref($string) eq 'ARRAY' || ref($string) eq 'HASH') {
            Error::throw OAuthSimpleException('Array passed to _oauthEscape');
        }
        $string = URI::Escape::uri_escape($string);
        $string =~ s/\+/%20/gm;
        $string =~ s/\!/%21/gm;
        $string =~ s/\*/%2A/gm;
        $string =~ s/\\/%27/gm;
        $string =~ s/\(/%28/gm;
        $string =~ s/\)/%29/gm;
        return $string;
    }

    sub _getNonce {
        my $this=shift;
        my $length=shift || 5;
        my $result = '';    
        my $cLength = length($this->{_nonce_chars});

        for (my $i=0; $i < $length; $i++)
        {
            $result .= substr($this->{_nonce_chars},rand($cLength),1);
        }
        $this->{_parameters}->{oauth_nonce} = $result;
        return $result;
    }

    sub _getApiKey {
        my $this=shift;

        if (empty($this->{_secrets}->{oauth_consumer_key}))
        {
            Error::throw OAuthSimpleException('No oauth_consumer_key set for OAuthSimple');
        }
        $this->{_parameters}->{oauth_consumer_key}=$this->{_secrets}->{oauth_consumer_key};
        return $this->{_parameters}->{oauth_consumer_key};
    }

    sub _getAccessToken {
        my $this=shift;

        if (!defined($this->{_secrets}->{oauth_secret})) {
            return '';
        }
        if (!defined($this->{_secrets}->{oauth_token})) {
            Error::throw OAuthSimpleException('No access token (oauth_token) set for OAuthSimple.');
        }
        $this->{_parameters}->{oauth_token} = $this->{_secrets}->{oauth_token};
        return $this->{_parameters}->{oauth_token};
    }

    sub _getTimeStamp {
        my $this=shift;

        return $this->{_parameters}->{oauth_timestamp} = time();
    }

    sub _normalizedParameters() {
        my $this=shift;

        my @elements;
        my @sortedKeys = sort(keys(%{$this->{_parameters}}));
        foreach my $paramName (@sortedKeys) {
            next if ($paramName =~ /_secret/);
            my $paramValue = $this->{_parameters}->{$paramName};
            if (ref($paramValue) eq 'ARRAY')
            {
                $paramValue = \{sort(@$paramValue)};
                foreach my $element (@$paramValue) {
                    push(@elements,$this->_oauthEscape($paramName).'='.$this->_oauthEscape($element));
                }
                next;
            }
            push(@elements,$this->_oauthEscape($paramName).'='.$this->_oauthEscape($paramValue));
        }
        return join('&',@elements);
    }

    sub _generateSignature {
        my $this=shift;
        my $normalizedParameters = shift;
        my $secretKey = '';
    
    	if(defined($this->{_secrets}->{shared_secret})) {
	        $secretKey = $this->_oauthEscape($this->{_secrets}->{shared_secret});
        }
    	$secretKey .= '&';
	    if(defined($this->{_secrets}->{oauth_secret})) {
            $secretKey .= $this->_oauthEscape($this->{_secrets}->{oauth_secret});
        }
        if (!empty($normalizedParameters)) {
            $normalizedParameters = $this->_oauthEscape($normalizedParameters);
        }
        if ($this->{_parameters}->{oauth_signature_method} eq 'PLAINTEXT') {
            return $secretKey;
        } elsif ($this->{_parameters}->{oauth_signature_method} eq 'HMAC-SHA1') {
            $this->{sbs} = $this->_oauthEscape($this->{_action}).'&'.$this->_oauthEscape($this->{_path}).'&'.$normalizedParameters;
            # For what it's worth, I prefer long form method calls like this since it identifies the source package.
            return MIME::Base64::encode_base64(Digest::SHA::hmac_sha1($this->{sbs},$secretKey),'');
        } else {
            Error::throw OAuthSimpleException('Unknown signature method for OAuthSimple');
        }
    }

# Utilities
    sub array_merge {
     #   my $this=shift;
        my $source=shift;
        my $target=shift;

        @$target{keys %$source} = values %$source;

        return $target;
    }

    sub empty {
    #    my $this=shift;
        #TODO: Check if the first elem is a ref to this && skip
        my $testable = shift;

        if (!defined($testable)) {
            return 1;
        }
        my $ref = ref ($testable);
        if ($ref eq 'HASH') {
                return scalar(keys %$testable) == 0;
        } elsif ($ref eq 'ARRAY') {
                return scalar(@$testable) == 0;
        } else {
                return $testable eq '';
        }
    }
1;

=pod

=head1 AUTHORS

JR Conlin, jrconlin.com

=head1 LICENSE

This class is licensed under BSD, see source for details.

=head1 AVAILABILITY 

see L<http://jrconlin.com/oauthsimple> for current repository

=cut
