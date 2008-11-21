/* OAuthSimple
  * A simpler version of OAuth
  *
  * author:     jr conlin
  * mail:       jconlin@netflix.com
  * copyright:  Netflix, Inc.
  * version:    0.1 (Not Ready For Prime Time)
  * url:        http://developer.netflix.com
  *
  * Copyright (c) 2008, Netflix, Inc.
  * All rights reserved.
  *
  * Redistribution and use in source and binary forms, with or without
  * modification, are permitted provided that the following conditions are met:
  *     * Redistributions of source code must retain the above copyright
  *       notice, this list of conditions and the following disclaimer.
  *     * Redistributions in binary form must reproduce the above copyright
  *       notice, this list of conditions and the following disclaimer in the
  *       documentation and/or other materials provided with the distribution.
  *     * Neither the name of the Netflix,Inc. nor the
  *       names of its contributors may be used to endorse or promote products
  *       derived from this software without specific prior written permission.
  *
  * THIS SOFTWARE IS PROVIDED BY NETFLIX,INC ''AS IS'' AND ANY
  * EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE IMPLIED
  * WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE ARE
  * DISCLAIMED. IN NO EVENT SHALL NETFLIX,INC BE LIABLE FOR ANY
  * DIRECT, INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY, OR CONSEQUENTIAL DAMAGES
  * (INCLUDING, BUT NOT LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS OR SERVICES;
  * LOSS OF USE, DATA, OR PROFITS; OR BUSINESS INTERRUPTION) HOWEVER CAUSED AND
  * ON ANY THEORY OF LIABILITY, WHETHER IN CONTRACT, STRICT LIABILITY, OR TORT
  * (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY OUT OF THE USE OF THIS
  * SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF SUCH DAMAGE.
 */
// Requires:
// sha1.js -- included here for simplicity
//  TODO: other include requirements here.
var OAuthSimple;

if (OAuthSimple == null)
{
    /* Simple OAuth
     *
     * This class only builds the OAuth elements, it does not do the actual
     * transmission or reception of the tokens. It does not validate elements
     * of the token. It is for client use only.
     *
     * api_key is the API key, also known as the OAuth consumer key
     * shared_secret is the shared secret (duh).
     *
     * Both the api_key and shared_secret are generally provided by the site
     * offering OAuth services. You need to specify them at object creation
     * because nobody <explative>ing uses OAuth without that minimal set of
     * signatures.
     *
     * If you want to use the higher order security that comes from the
     * OAuth token (sorry, I don't provide the functions to fetch that because
     * sites aren't horribly consistent about how they offer that), you need to
     * pass those in either with .setTokensAndSecrets() or as an argument to the
     * .sign() or .getHeaderString() functions.
     *
     * Example:
       <code>
        var oauthObject = OAuthSimple().sign({path:'http://example.com/rest/',
                                              parameters: 'foo=bar&gorp=banana',
                                              signatures:{
                                                api_key:'12345abcd',
                                                shared_secret:'xyz-5309'
                                             }});
        document.getElementById('someLink').href=oauthObject.signed_url;
       </code>
     *
     * that will sign as a "GET" using "SHA1-MAC" the url. If you need more than
     * that, read on, McDuff.
     */

    /** OAuthSimple creator
     *
     * Create an instance of OAuthSimple
     *
     * @param api_key {string}       The API Key (sometimes referred to as the consumer key) This value is usually supplied by the site you wish to use.
     * @param shared_secret (string) The shared secret. This value is also usually provided by the site you wish to use.
     */
    OAuthSimple = function (api_key,shared_secret)
    {
/*        if (api_key == null)
            throw("Missing argument: api_key (oauth_consumer_key) for OAuthSimple. This is usually provided by the hosting site.");
        if (shared_secret == null)
            throw("Missing argument: shared_secret (shared secret) for OAuthSimple. This is usually provided by the hosting site.");
*/      this._secrets={};


        // General configuration options.
        if (api_key != null)
            this._secrets['api_key'] = api_key;
        if (shared_secret != null)
            this._secrets['shared_secret'] = shared_secret;
        this._default_signature_method= "HMAC-SHA1";
        this._access = "GET";
        this._nonce_chars = "0123456789ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz";

        /** set the parameters either from a hash or a string
         *
         * @param {string,object} List of parameters for the call, this can either be a URI string (e.g. "foo=bar&gorp=banana" or an object/hash)
         */
        this.setParameters = function (parameters) {
            if (parameters == null)
                throw ('No parameters specified for OAuthSimple.setParameters');
            if (typeof(parameters) == 'string')
                parameters=this._parseParameterString(parameters);
            this._parameters = parameters;
            if (this._parameters['oauth_nonce'] == null)
                this._getNonce();
            if (this._parameters['oauth_timestamp'] == null)
                this._getTimestamp();
            if (this._parameters['oauth_method'] == null)
                this.setSignatureMethod();
            if (this._parameters['oauth_consumer_key'] == null)
                this._getApiKey();
            if(this._parameters['oauth_token'] == null)
                this._getAccessToken();

            return this;
        };

        /** convienence method for setParameters
         *
         * @param parameters {string,object} See .setParameters
         */
        this.setQueryString = function (parameters) {
            return this.setParameters(parameters);
        };

        /** Set the target URL (does not include the parameters)
         *
         * @param path {string} the fully qualified URI (excluding query arguments) (e.g "http://example.org/foo")
         */
        this.setURL = function (path) {
            if (path == '')
                throw ('No path specified for OAuthSimple.setURL');
            this._path = path;
            return this;
        };

        /** convienence method for setURL
         *
         * @param path {string} see .setURL
         */
        this.setPath = function(path){
            return this.setURL(path);
        };

        /** set the "action" for the url, (e.g. GET,POST, DELETE, etc.)
         *
         * @param action {string} HTTP Action word.
         */
        this.setAction = function(action) {
            if (action == null)
                action="GET";
            action = action.toUpperCase();
            if (action.match('[^A-Z]'))
                throw ('Invalid action specified for OAuthSimple.setAction');
            this._action = action;
            return this;
        };

        /** set the signatures (as well as validate the ones you have)
         *
         * @param signatures {object} object/hash of the token/signature pairs {api_key:, shared_secret:, access_token: access_secret:}
         */
        this.setTokensAndSecrets = function(signatures) {
            if (signatures)
                for (var i in signatures)
                    this._secrets[i] = signatures[i];
            if (this._secrets['consumer_key'] != null && this._secrets['api_key'] == null)
                this._secrets.api_key = this._secrets['consumer_key'];
            if (this._secrets.api_key == null)
                throw('Missing required api_key or consumer_key in OAuthSimple.setTokensAndSecrets');
            if (this._secrets.shared_secret == null)
                throw('Missing required shared_secret in OAuthSimple.setTokensAndSecrets');
            if ((this._secrets.access_token!=null) && (this._secrets.access_secret == null))
                throw('Missing access_secret for supplied access_token in OAuthSimple.setTokensAndSecrets');
            return this;
        };

        /** set the signature method (currently only Plaintext or SHA-MAC1)
         *
         * @param method {string} Method of signing the transaction (only PLAINTEXT and SHA-MAC1 allowed for now)
         */
        this.setSignatureMethod = function(method) {
            if (method == null)
                method = this._default_signature_method;
            //TODO: accept things other than PlainText or SHA-MAC1
            if (method.toUpperCase().match(/(PLAINTEXT|HMAC-SHA1)/) == null)
                throw ('Unknown signing method specified for OAuthSimple.setSignatureMethod');
            this._parameters['oauth_signature_method']= method.toUpperCase();
            return this;
        };

        /** sign the request
         *
         * note: all arguments are optional, provided you've set them using the
         * other helper functions.
         *
         * @param args {object} hash of arguments for the call
         *                   {action:, path:, parameters:, method:, signatures:}
         *                   all arguments are optional.
         */
        this.sign = function (args) {
            if (args == null)
                args = {};
            // Set any given parameters
            if(args['action'] != null)
                this.setAction(args['action']);
            if (args['path'] != null)
                this.setPath(args['path']);
            if (args['method'] != null)
                this.setSignatureMethod(args['method']);
            this.setTokensAndSecrets(args['signatures']);
            if (args['parameters'] != null)
            this.setParameters(args['parameters']);
            // check the parameters
            var normParams = this._normalizedParameters();
            this._parameters['oauth_signature']=this._generateSignature(normParams);
            return {
                parameters: this._parameters,
                signature: this._oauthEscape(this._parameters['oauth_signature']),
                signed_url: this._path + '?' + this._normalizedParameters(),
                header: this.getHeaderString()
            };
        };

        /** Return a formatted "header" string
         *
         * NOTE: This doesn't set the "Authorization: " prefix, which is required.
         * I don't set it because various set header functions prefer different
         * ways to do that.
         *
         * @param args {object} see .sign
         */
        this.getHeaderString = function(args) {
            if (this._parameters['oauth_signature'] == null)
                this.sign(args);

            var result = 'OAuth ';
            for (var pName in this._parameters)
            {
                if (pName.match(/^oauth/) == null)
                    continue;
                if ((this._parameters[pName]) instanceof Array)
                {
                    var pLength = this._parameters[pName].length;
                    for (var j=0;j<pLength;j++)
                    {
                        result += pName +'="'+this._oauthEscape(this._parameters[pName][j])+'" ';
                    }
                }
                else
                {
                    result += pName + '="'+this._oauthEscape(this._parameters[pName])+'" ';
                }
            }
            return result;
        };

        // Start Private Methods.

        /** convert the parameter string into a hash of objects.
         *
         */
        this._parseParameterString = function(paramString){
            var elements = paramString.split('&');
            var result={};
            for(var element=elements.shift();element;element=elements.shift())
            {
                var keyToken=element.split('=');
                if(result[keyToken[0]]){
                    if (!(result[keyToken[0]] instanceof Array))
                    {
                        result[keyToken[0]] = Array(result[keyToken[0]],keyToken[1]);
                    }
                    else
                    {
                        result[keyToken[0]].push(keyToken[1]);
                    }
                }
                else
                {
                    result[keyToken[0]]=keyToken[1];
                }
            }
            return result;
        };

        this._oauthEscape = function(string) {
            if (string == null)
                return "";
            if (string instanceof Array)
            {
                throw('Array passed to _oauthEscape');
            }
            return encodeURIComponent(string).replace("!", "%21", "g").
            replace("*", "%2A", "g").
            replace("'", "%27", "g").
            replace("(", "%28", "g").
            replace(")", "%29", "g");
        };

        this._getNonce = function (length) {
            if (length == null)
                length=5;
            var result = "";
            var cLength = this._nonce_chars.length;
            for (var i = 0; i < length;i++) {
                var rnum = Math.floor(Math.random() *cLength);
                result += this._nonce_chars.substring(rnum,rnum+1);
            }
            this._parameters['oauth_nonce']=result;
            return result;
        };

        this._getApiKey = function() {
            if (this._secrets.api_key == null)
                throw('No api_key (oauth_consumer_key) set for OAuthSimple.');
            this._parameters['oauth_consumer_key']=this._secrets.api_key;
            return this._parameters.oauth_consumer_key;
        };

        this._getAccessToken = function() {
            if (this._secrets['access_secret'] == null)
                return '';
            if (this._secrets['access_token'] == null)
                throw('No access_token (oauth_access_token) set for OAuthSimple.');
            this._parameters['oauth_access_token'] = this._secrets.access_token;
            return this._parameters.oauth_access_token;
        };

        this._getTimestamp = function() {
            var d = new Date();
            var ts = Math.floor(d.getTime()/1000);
            this._parameters['oauth_timestamp'] = ts;
            return ts;
        };

        this._normalizedParameters = function() {
            var elements = new Array();
            var paramNames = [];
            var ra =0;
            for (var paramName in this._parameters)
            {
                if (ra++ > 1000)
                    throw('runaway 1');
                paramNames.unshift(paramName);
            }
            paramNames = paramNames.sort();
            pLen = paramNames.length;
            for (var i=0;i<pLen; i++)
            {
                paramName=paramNames[i];
                //skip secrets.
                if (paramName.match(/\w+_secret/))
                    continue;
                if (this._parameters[paramName] instanceof Array)
                {
                    var sorted = this._parameters[paramName].sort();
                    var spLen = sorted.length;
                    for (var j = 0;j<spLen;j++){
                        if (ra++ > 1000)
                            throw('runaway 1');
                        elements.push(this._oauthEscape(paramName) + '=' +
                                  this._oauthEscape(sorted[j]));
                    }
                    continue;
                }
                elements.push(this._oauthEscape(paramName) + '=' +
                              this._oauthEscape(this._parameters[paramName]));
            }
            return elements.join('&');
        };

        this._generateSignature = function() {

            var secretKey = this._oauthEscape(this._secrets.shared_secret)+'&'+
                this._oauthEscape(this._secrets.access_secret);
            if (this._parameters['oauth_signature_method'] == 'PLAINTEXT')
            {
                return secretKey;
            }
            if (this._parameters['oauth_signature_method'] == 'HMAC-SHA1')
            {
                var sigString = this._access+'&'+this._path+'&'+this._normalizedParameters();
                b64pad = "=";
                return b64_hmac_sha1(secretKey,sigString);
            }
            return null;
        };

    return this;
    }
}
// Including Paul Johnson's SHA-1 for completeness.

/*
 * A JavaScript implementation of the Secure Hash Algorithm, SHA-1, as defined
 * in FIPS PUB 180-1
 * Version 2.1a Copyright Paul Johnston 2000 - 2002.
 * Other contributors: Greg Holt, Andrew Kepert, Ydnar, Lostinet
 * Distributed under the BSD License
 * See http://pajhome.org.uk/crypt/md5 for details.
 */

/*
 * Configurable variables. You may need to tweak these to be compatible with
 * the server-side, but the defaults work in most cases.
 */
var hexcase = 0;  /* hex output format. 0 - lowercase; 1 - uppercase        */
var b64pad  = ""; /* base-64 pad character. "=" for strict RFC compliance   */
var chrsz   = 8;  /* bits per input character. 8 - ASCII; 16 - Unicode      */

/*
 * These are the functions you'll usually want to call
 * They take string arguments and return either hex or base-64 encoded strings
 */
function hex_sha1(s){return binb2hex(core_sha1(str2binb(s),s.length * chrsz));}
function b64_sha1(s){return binb2b64(core_sha1(str2binb(s),s.length * chrsz));}
function str_sha1(s){return binb2str(core_sha1(str2binb(s),s.length * chrsz));}
function hex_hmac_sha1(key, data){ return binb2hex(core_hmac_sha1(key, data));}
function b64_hmac_sha1(key, data){ return binb2b64(core_hmac_sha1(key, data));}
function str_hmac_sha1(key, data){ return binb2str(core_hmac_sha1(key, data));}

/*
 * Perform a simple self-test to see if the VM is working
 */
function sha1_vm_test()
{
  return hex_sha1("abc") == "a9993e364706816aba3e25717850c26c9cd0d89d";
}

/*
 * Calculate the SHA-1 of an array of big-endian words, and a bit length
 */
function core_sha1(x, len)
{
  /* append padding */
  x[len >> 5] |= 0x80 << (24 - len % 32);
  x[((len + 64 >> 9) << 4) + 15] = len;

  var w = Array(80);
  var a =  1732584193;
  var b = -271733879;
  var c = -1732584194;
  var d =  271733878;
  var e = -1009589776;

  for(var i = 0; i < x.length; i += 16)
  {
    var olda = a;
    var oldb = b;
    var oldc = c;
    var oldd = d;
    var olde = e;

    for(var j = 0; j < 80; j++)
    {
      if(j < 16) w[j] = x[i + j];
      else w[j] = rol(w[j-3] ^ w[j-8] ^ w[j-14] ^ w[j-16], 1);
      var t = safe_add(safe_add(rol(a, 5), sha1_ft(j, b, c, d)),
                       safe_add(safe_add(e, w[j]), sha1_kt(j)));
      e = d;
      d = c;
      c = rol(b, 30);
      b = a;
      a = t;
    }

    a = safe_add(a, olda);
    b = safe_add(b, oldb);
    c = safe_add(c, oldc);
    d = safe_add(d, oldd);
    e = safe_add(e, olde);
  }
  return Array(a, b, c, d, e);

}

/*
 * Perform the appropriate triplet combination function for the current
 * iteration
 */
function sha1_ft(t, b, c, d)
{
  if(t < 20) return (b & c) | ((~b) & d);
  if(t < 40) return b ^ c ^ d;
  if(t < 60) return (b & c) | (b & d) | (c & d);
  return b ^ c ^ d;
}

/*
 * Determine the appropriate additive constant for the current iteration
 */
function sha1_kt(t)
{
  return (t < 20) ?  1518500249 : (t < 40) ?  1859775393 :
         (t < 60) ? -1894007588 : -899497514;
}

/*
 * Calculate the HMAC-SHA1 of a key and some data
 */
function core_hmac_sha1(key, data)
{
  var bkey = str2binb(key);
  if(bkey.length > 16) bkey = core_sha1(bkey, key.length * chrsz);

  var ipad = Array(16), opad = Array(16);
  for(var i = 0; i < 16; i++)
  {
    ipad[i] = bkey[i] ^ 0x36363636;
    opad[i] = bkey[i] ^ 0x5C5C5C5C;
  }

  var hash = core_sha1(ipad.concat(str2binb(data)), 512 + data.length * chrsz);
  return core_sha1(opad.concat(hash), 512 + 160);
}

/*
 * Add integers, wrapping at 2^32. This uses 16-bit operations internally
 * to work around bugs in some JS interpreters.
 */
function safe_add(x, y)
{
  var lsw = (x & 0xFFFF) + (y & 0xFFFF);
  var msw = (x >> 16) + (y >> 16) + (lsw >> 16);
  return (msw << 16) | (lsw & 0xFFFF);
}

/*
 * Bitwise rotate a 32-bit number to the left.
 */
function rol(num, cnt)
{
  return (num << cnt) | (num >>> (32 - cnt));
}

/*
 * Convert an 8-bit or 16-bit string to an array of big-endian words
 * In 8-bit function, characters >255 have their hi-byte silently ignored.
 */
function str2binb(str)
{
  var bin = Array();
  var mask = (1 << chrsz) - 1;
  for(var i = 0; i < str.length * chrsz; i += chrsz)
    bin[i>>5] |= (str.charCodeAt(i / chrsz) & mask) << (32 - chrsz - i%32);
  return bin;
}

/*
 * Convert an array of big-endian words to a string
 */
function binb2str(bin)
{
  var str = "";
  var mask = (1 << chrsz) - 1;
  for(var i = 0; i < bin.length * 32; i += chrsz)
    str += String.fromCharCode((bin[i>>5] >>> (32 - chrsz - i%32)) & mask);
  return str;
}

/*
 * Convert an array of big-endian words to a hex string.
 */
function binb2hex(binarray)
{
  var hex_tab = hexcase ? "0123456789ABCDEF" : "0123456789abcdef";
  var str = "";
  for(var i = 0; i < binarray.length * 4; i++)
  {
    str += hex_tab.charAt((binarray[i>>2] >> ((3 - i%4)*8+4)) & 0xF) +
           hex_tab.charAt((binarray[i>>2] >> ((3 - i%4)*8  )) & 0xF);
  }
  return str;
}

/*
 * Convert an array of big-endian words to a base-64 string
 */
function binb2b64(binarray)
{
  var tab = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/";
  var str = "";
  for(var i = 0; i < binarray.length * 4; i += 3)
  {
    var triplet = (((binarray[i   >> 2] >> 8 * (3 -  i   %4)) & 0xFF) << 16)
                | (((binarray[i+1 >> 2] >> 8 * (3 - (i+1)%4)) & 0xFF) << 8 )
                |  ((binarray[i+2 >> 2] >> 8 * (3 - (i+2)%4)) & 0xFF);
    for(var j = 0; j < 4; j++)
    {
      if(i * 8 + j * 6 > binarray.length * 32) str += b64pad;
      else str += tab.charAt((triplet >> 6*(3-j)) & 0x3F);
    }
  }
  return str;
}
