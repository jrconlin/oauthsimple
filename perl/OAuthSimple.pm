use strict;
use Data::Dumper;
# OAuthSimple
# A simpler version of OAuth
#
# author:     jr conlin
# mail:       src@anticipatr.com
# copyright:  unitedHeroes.net
# version:    1.0
# url:        http://unitedHeroes.net/OAuthSimple
#
# Copyright (c) 2009, unitedHeroes.net
# All rights reserved.
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
# Simple OAuth
#
# This class only builds the OAuth elements, it does not do the actual
# transmission or reception of the tokens. It does not validate elements
# of the token. It is for client use only.
#
# api_key is the API key, also known as the OAuth consumer key
# shared_secret is the shared secret (duh).
#
# Both the api_key and shared_secret are generally provided by the site
# offering OAuth services. You need to specify them at object creation
# because nobody <explative>ing uses OAuth without that minimal set of
# signatures.
#
# If you want to use the higher order security that comes from the
# OAuth token (sorry, I don't provide the functions to fetch that because
# sites aren't horribly consistent about how they offer that), you need to
# pass those in either with .setTokensAndSecrets() or as an argument to the
# .sign() or .getHeaderString() functions.
#
# Example:

    ##TODO: code samples

#
# that will sign as a "GET" using "SHA1-MAC" the url. If you need more than
# that, read on, McDuff.
#/

    use Error qw(:try); # required for exception handling
    use MIME::Base64;   # required for OAuth
    use Digest::SHA;
    use URI::Escape;


# OAuthSimple creator
#
# Create an instance of OAuthSimple
#
# @param api_key {string}       The API Key (sometimes referred to as the consumer key) This value is usually supplied by the site you wish to use.
# @param shared_secret (string) The shared secret. This value is also usually provided by the site you wish to use.
#/
    sub new {
        my $this = {_secrets=>{},
                    _parameters=>{},
                    _default_signature_method=>'HMAC-SHA1',
                    _action=>"GET",
                    _nonce_chars=>"0123456789ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz"};
        my $class = shift;
        $class = ref($class) || $class;
        bless $this,$class;
        $DB::single=1;

        my ($apikey,$sharedSecret) = @_;

        if (!empty($apikey)) {
            $this->{_secrets}->{oauth_consumer_key} = $apikey;
        }
        if (!empty($sharedSecret)) {
            $this->{_secrets}->{shared_secret}=$sharedSecret;
        }
        return $this;
    }

# reset the parameters and url 
#
#/
    sub reset {
        my $this = shift;

        $this->{_parameters}=undef;
        $this->{path}=undef;
        return $this;    
    }

# set the parameters either from a hash or a string
#
# @param {string,object} List of parameters for the call, this can either be a URI string (e.g. "foo=bar&gorp=banana" or an object/hash)
#/
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
                $this->_parameters = array_merge($this->_parameters,$parameters);
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
#error_log('parameters: '.print_r($this,1));
        return $this;
    }

# convienence method for setParameters
    sub setQueryString {
        my $this=shift;
        my $parameters = @_;

        return $this->setParameters($parameters);
    }

# Set the target URL (does not include the parameters)
#
# @param path {string} the fully qualified URI (excluding query arguments) (e.g "http://example.org/foo")
#/
    sub setURL {
        my $this=shift;
        my $path=shift;

        if (empty($path)) {
            Error::throw OAuthSimpleException('No path specified');
        }
        $this->{_path}=$path;
        return $this;
    }

# convienence method for setURL
#
# @param path {string} see .setURL
#/
    sub setPath {
        my $this=shift;

        return $this->setURL(shift);
    }

# set the "action" for the url, (e.g. GET,POST, DELETE, etc.)
#
# @param action {string} HTTP Action word.
#/
    sub setAction {
        my $this=shift;
        my $action=uc(shift || 'GET');

        if ($action =~ /[^A-Z]/) {
            Error::throw OAuthSimpleException('Invalid action specified for OAuthSimple.setAction');
        }
        $this->{_action} = $action;
        return $this;
    }

# set the signatures (as well as validate the ones you have)
#
# @param signatures {object} object/hash of the token/signature pairs {api_key:, shared_secret:, oauth_token: oauth_secret:}
#/
    sub setTokensAndSecrets {
        my $this=shift;
        my $signatures=shift;

        if (!empty($signatures) && ref($signatures) ne 'HASH') {
            Error::throw OAuthSimpleException('Must pass HASH to OAuthSimple.setTokensAndSecrets');
        }
        if (!empty($signatures)) {
            while (my ($sig,$value) = each %$signatures) {
                $this->{_secrets}->{$sig} = $value;
            }
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
            Error::throw OAuthSimpleException('Missing required oauth_consumer_key in OAuthSimple.setTokensAndSecrets');
        }
        if (empty($this->{_secrets}->{shared_secret})) {
            Error::throw OAuthSimpleException('Missing requires shared_secret in OAuthSimple.setTokensAndSecrets');
        }
        if (!empty($this->{_secrets}->{oauth_token}) && empty($this->{_secrets}->{oauth_secret})) {
            Error::throw OAuthSimpleException('Missing oauth_secret for supplied oauth_token in OAuthSimple.setTokensAndSecrets');
        }
        return $this;
    }

# set the signature method (currently only Plaintext or SHA-MAC1)
#
# @param method {string} Method of signing the transaction (only PLAINTEXT and SHA-MAC1 allowed for now)
#/
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

# sign the request
#
# note: all arguments are optional, provided you've set them using the
# other helper functions.
#
# @param args {object} hash of arguments for the call
#                   {action, path, parameters (array), method, signatures (array)}
#                   all arguments are optional.
#/
    sub sign {
        my $this=shift;
        my $args=shift;

        if (!empty($args->{action})) {
            $this->setAction($args->{action});
        }
        if (!empty($args->{path})) {
            $this->setURL($args->{path});
        }
        if (!empty($args->{method})) {
            $this->setSignatureMethod($args->{method});
        }
        if (!empty($args->{signatures})) {
            $this->setTokensAndSecrets($args->{signatures});
        }
        $this->setParameters($args->{parameters});
        my $normParams = $this->_normalizedParameters();
        $this->{_parameters}->{oauth_signature} = $this->_generateSignature($normParams);
        return {
            'parameters' => $this->{_parameters},
            'signature' => $this->_oauthEscape($this->{_parameters}->{oauth_signature}),
            'signed_url' => $this->{_path} . '?' . $this->_normalizedParameters(),
            'header' => $this->getHeaderString(),
            'sbs'=> $this->{sbs}
            };
    }

# Return a formatted "header" string
#
# NOTE: This doesn't set the "Authorization: " prefix, which is required.
# I don't set it because various set header functions prefer different
# ways to do that.
#
# @param args {object} see .sign
#/
    sub getHeaderString { 
        my $this=shift;
        my $args=shift;
        my $result = 'OAuth ';

        if (empty($this->{_parameters}->{oauth_signature})) {
            $this->sign($args);
        }

        while (my ($pName,$pValue) = each %{$this->{_parameters}}) {
        {
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
        return $result =~ s/, +$//;
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
                $token = urldecode($token);
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
        $string = uri_escape($string);
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
        my $secretKey = '';
    
    	if(defined($this->{_secrets}->{shared_secret})) {
	        $secretKey = $this->_oauthEscape($this->{_secrets}->{shared_secret});
        }
    	$secretKey .= '&';
	    if(defined($this->{_secrets}->{oauth_secret})) {
            $secretKey .= $this->_oauthEscape($this->{_secrets}->{oauth_secret});
        }
        if ($this->{_parameters}->{oauth_signature_method} eq 'PLAINTEXT') {
            return $secretKey;
        } elsif ($this->{_parameters}->{oauth_signature_method} eq 'HMAC-SHA1') {
            $this->{sbs} = $this->_oauthEscape($this->{_action}).'&'.$this->_oauthEscape($this->{_path}).'&'.$this->_oauthEscape($this->_normalizedParameters());
            # For what it's worth, I prefer long form method calls like this since it identifies the source package.
            return MIME::Base64::encode_base64(Digest::SHA::hmac_sha1($this->{sbs},$secretKey));
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
}
1;
