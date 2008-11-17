<?php

class OAuthSimpleException extends Exception {}

class OAuthSimple {
    var $_secrets;
    var $_default_signature_method;
    var $_access;
    var $_nonce_chars;

    function OAuthSimple ($APIKey = "",$sharedSecret=""){
        if (!empty($APIKey))
            $this->_secrets{'api_key'}=$APIKey;
        if (!empty($sharedSecret))
            $this->_secrets{'shared_secret'}=$sharedSecret;
        $this->_default_signature_method="HMAC-SHA1";
        $this->_access="GET";
        $this->_nonce_chars="0123456789ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz";
        return $this;
    }

    function setParameters ($parameters) {
        if (empty($parameters))
            throw new OAuthSimpleException('No parameters specified for OAuthSimple.setParameters');
        if (is_string($parameters))
            $parameters = $this->_parseParameterString($parameters);
        $this->_parameters = $parameters;
        if (empty($this->_parameters{oauth_nonce}))
            $this->_getNonce();
        if (empty($this->_parameters{oauth_timestamp}))
            $this->_getTimestamp();
        if (empty($this->_parameters{oauth_consumer_key}))
            $this->_getApiKey();
        if (empty($this->_parameters{oauth_token}))
            $this->_getAccessToken();

        return $this;
    }

    function setQueryString ($parameters) {
        return $this->setParameters($parameters);
    }

    function setURL ($path) {
        if (empty($path))
            throw OAuthSimpleException('No path specified for OAuthSimple.setURL');
        $this->_path=$path;
        return $this;
    }

    function setPath ($path) {
        return $this->setPath($path);
    }

    function setAction ($action) {
        if (empty($action))
            $action = 'GET';
        $action = strtoupper($action);
        if (preg_match('/[^A-Z]/',$action))
            throw OAuthSimpleException('Invalid action specified for OAuthSimple.setAction');
        $this->action = $action;
        return $this;
    }

    function setTokensAndSecrets ($signatures) {
        if (!empty($signatures) && !is_array($signatures))
            throw OAuthSimpleException('Must pass dictionary array to OAuthSimple.setTokensAndSecrets');
        if (!empty($signatures))
            foreach ($signatures as $sig=>$value)
                $this->_secrets{$sig} = $value;
        if (!empty($this->_secrets{'consumer_key'}) && emtpy($this->_secrets{'api_key'}))
            $this->_secrets{'api_key'} = $this->_secrets{'consumer_key'};
        if (empty($this->_secrets{'api_key'}))
            throw OAuthSimpleException('Missing required api_key or consumer_key in OAuthSimple.setTokensAndSecrets');
        if (empty($this->_secrets{'shared_secret'}))
            throw OAuthSimpleException('Missing requires shared_secret in OAuthSimple.setTokensAndSecrets');
        if (!empty($this->_secrets{'access_token'}) && empty($this->_secrets{access_secret}))
            throw OAuthSimpleException('Missing access_secret for supplied access_token in OAuthSimple.setTokensAndSecrets');
        return this;
    }

    function setSignatureMethod ($method) {
        if (empty($method))
            $method = $this->_default_signature_method;
        $method = strtoupper($method);
        switch($method)
        {
            case 'PLAINTEXT':
            case 'HMAC-SHA1':
                $this->_parameters{'oauth_signature_method'}=$method;
                break;
            default:
                throw OAuthSimpleException ('Unknown signing method specified for OAuthSimple.setSignatureMethod');
        }
        return $this;
    }

    function sign($args) {
        if (!empty($args{action}))
            $this->setAction($args{action});
        if (!empty($args{path}))
            $this->setPath($args{path});
        if (!empty($args{method}))
            $this->setSignatureMethod($args{method});
        $this->setTokensAndSecrets($args{signatures});
        $this->setParameters($args{parameters});
    }
}
?>
