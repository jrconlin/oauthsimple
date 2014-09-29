#!/usr/bin/env python -tt

import base64
import hashlib
import hmac
import random
import re
import time
import urllib2
import urlparse
import string

import OAuthSimpleException


class OAuthSimple:
    _secrets = {}
    _parameters = {}
    _default_signature_method = "HMAC-SHA1"
    _action = "GET"
    _nonce_characters = string.digits + string.letters
    sbs = ""
    _path = ""

    def __init__(self, apiKey=None, sharedSecret=None):
        if apiKey:
            self._secrets['oauth_consumer_key'] = apiKey
        if sharedSecret:
            self._secrets['shared_secret'] = sharedSecret
        return

    def reset(self):
        self._parameters = {}
        self.path = {}
        self.sbs = {}
        return self

    def setParameters(self, parameters={}):
        if parameters:
            if type(parameters) == type(""):
                parameters = self._parseParameterString(parameters)
            if not self._parameters:
                self._parameters = parameters
            elif parameters:
                self._parameters = self._arrayMerge(self._parameters,
                        parameters)
        if not self._parameters.get('oauth_nonce'):
            self._getNonce()
        if not self._parameters.get('oauth_timestamp'):
            self._getTimeStamp()
        if not self._parameters.get('oauth_consumer_key'):
            self._getApiKey()
        if not self._parameters.get('oauth_token'):
            self._getAccessToken()
        if not self._parameters.get('oauth_signature_method'):
            self.setSignatureMethod()
        if not self._parameters.get('oauth_version'):
            self._parameters['oauth_version'] = '1.0'
        return self

    def setPath(self, path):
        if not path:
            raise OAuthSimpleException('No path specified')
        self._path = path
        return self

    def setAction(self, action):
        action = action.upper()
        if re.match('[^A-Z]', action):
            raise OAuthSimpleException(
                    'Invalid action specified for OAuthSimple.setAction')
        self._action = action
        return self

    def signatures(self, signatures):
        if signatures and (type(signatures) != type({})):
            raise OAuthSimpleException(
                    'Must pass Dict to OAuthSimple.signatures')

        if signatures:
            self._secrets = self._arrayMerge(signatures, self._secrets)

        # swap keys
        swap = (('api_key', 'oauth_consumer_key'),
                 ('consumer_key', 'oauth_consumer_key'),
                 ('access_token', 'oauth_token'),
                 ('access_token_secret', 'oauth_secret'))
        for swapable in swap:
            if (self._secrets.get(swapable[0])):
                self._secrets[swapable[1]] = self._secrets[swapable[0]]
                del self._secrets[swapable[0]]
        if not self._secrets.get('oauth_consumer_key'):
            raise OAuthSimpleException('Missing required oauth_consumer_key')
        if not self._secrets.get('shared_secret'):
            raise OAuthSimpleException('Missing required shared_secret')
        if (self._secrets.get('oauth_token') and
                not self._secrets.get('oauth_secret')):
            raise OAuthSimpleException(
                    'Missing oauth_secret for supplied oauth_token')
        return self

    def setSignatureMethod(self, method=None):
        if not method:
            method = self._default_signature_method
        method = method.upper()
        if method not in ('PLAINTEXT', 'HMAC-SHA1'):
            raise OAuthSimpleException('Invalid Signature method specified ')
        self._parameters['oauth_signature_method'] = method
        return self

    def sign(self, args={}):
        if args.get('action'):
            self.setAction(args['action'])
        if args.get('path'):
            self.setPath(args['path'])
        if args.get('method'):
            self.setSignatureMethod(args['method'])
        if args.get('signatures'):
            self.signatures(args.get('signatures'))
        self.setParameters(args.get('parameters'))
        normParamString = self._normalizeParameters()
        self._parameters['oauth_signature'] = \
            self._generateSignature(normParamString)
        return {'parameters': self._parameters,
                'signature': self._oauthEscape(
                    self._parameters['oauth_signature']),
                'signed_url': '%s?%s' % (self._path,
                    normParamString),
                'header': self.getHeaderString(),
                'sbs': self.sbs}

    def getHeaderString(self, args={}):
        result = []

        if not self._parameters.get('oauth_signature'):
            self.sign(args)

        for pName in self._parameters:
            if not pName.startswith('oauth_'):
                continue
            pValue = self._parameters.get(pName)
            if type(pValue) == type([]):
                for val in pValue:
                    result.append('%s="%s"' % (pName,
                        self._oauthEscape(val)))
            else:
                result.append('%s="%s"' % (pName,
                    self._oauthEscape(str(pValue))))
        return 'OAuth %s' % (', '.join(result))

    def _arrayMerge(self, target, source):
        for skey in source.keys():
            target[skey] = source.get(skey)
        return target

    def _parseParameterString(self, paramString):
        return urlparse.parse_qs(paramString, True)

    def _oauthEscape(self, string):
        if not string:
            return ''

        string = urllib2.quote(string)
        return string.replace('/', '%2F').replace('+', '%20')\
                .replace('!', '%21').replace('*', '%2A')\
                .replace('\\', '%27').replace('(', '%28').\
                replace(')', '%29')

    def _getApiKey(self):
        if 'oauth_consumer_key' not in self._parameters:
            if not self._secrets.get('oauth_consumer_key'):
                raise OAuthSimpleException('No oauth_consumer_key set')
            self._parameters['oauth_consumer_key'] = \
                    self._secrets.get('oauth_consumer_key')
        return self._parameters.get('oauth_consumer_key')

    def _getAccessToken(self):
        if 'oauth_secret' not in self._secrets:
            return ''
        if 'oauth_access_token' not in self._parameters:
            if not self._secrets.get('oauth_access_token'):
                raise OAuthSimpleException('No oauth_access_token set')
            self._parameters['oauth_access_token'] = \
                    self._secrets.get('oauth_access_token')
        return self._parameters.get('oauth_access_token')

    def _getNonce(self, length=5):
        result = []
        cLength = len(self._nonce_characters)

        for i in range(0, length):
            rnd = random.randint(0, cLength - 1)
            result.append(self._nonce_characters[rnd])
        self._parameters['oauth_nonce'] = ''.join(result)
        return self._parameters['oauth_nonce']

    def _getTimeStamp(self):
        """ return the top UTC time integer as a string """
        self._parameters['oauth_timestamp'] = int(time.time())
        return self._parameters['oauth_timestamp']

    def _normalizeParameters(self):
        elements = []
        if not self._parameters:
            return ''
        pKeys = self._parameters.keys()
        pKeys.sort()
        for paramName in pKeys:
            if paramName.find('_secret') > 0:
                continue
            paramValue = self._parameters.get(paramName)
            if type(paramValue) == type([]):
                paramValue.sort()
                for value in paramValue:
                    elements.append('%s=%s' % (self._oauthEscape(paramName),
                        self._oauthEscape(value)))
                next
            else:
                elements.append('%s=%s' % (self._oauthEscape(paramName),
                    self._oauthEscape(str(paramValue))))
        return '&'.join(elements)

    def _generateSignature(self, normParamString):
        secretKey = ''

        if self._secrets.get('shared_secret'):
            secretKey = self._oauthEscape(self._secrets['shared_secret'])

        secretKey += '&'

        if self._secrets.get('oauth_secret'):
            secretKey += self._oauthEscape(self._secrets['oauth_secret'])

        if (self._parameters['oauth_signature_method'] == 'PLAINTEXT'):
            return secretKey
        elif (self._parameters['oauth_signature_method'] == 'HMAC-SHA1'):
            self.sbs = '&'.join([self._oauthEscape(self._action),
                                self._oauthEscape(self._path),
                                normParamString])
        return base64.b64encode(hmac.new(secretKey,
                                self.sbs,
                                hashlib.sha1).digest())
