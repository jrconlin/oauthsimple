<?php

// Craptastic UNIT test for PHP OAuthSimple

require 'OAuthSimple.php';

$path  = 'http://example.com/test';
$static_nonce = 'abcd123';
$static_time = 1234567890;
$signatures  = array('consumer_key' => 'test_key',
    'shared_secret' => 'test_secret',
    'oauth_token' => 'access_key',
    'oauth_secret' => 'access_secret');
$parameters = array(
    'fruit'=>'bananas are <Awe+some!>',
    'number'=>42,
    // defining these here overrides the auto-generator.
    'oauth_nonce'=>$static_nonce,
    'oauth_timestamp'=>$static_time);
$oauth = new OAuthSimple();
$results = $oauth->sign(array('path'=>$path,
    'parameters'=>$parameters,
    'signatures'=>$signatures));

// ====
$expected = array(
    'fruit'=>'bananas are <Awe+some!>',
    'number'=>42,
    'oauth_nonce'=>$static_nonce,
    'oauth_timestamp'=>$static_time,
    'oauth_consumer_key'=>$signatures['consumer_key'],
    'oauth_token'=>$signatures['oauth_token'],
    'oauth_signature_method'=>'HMAC-SHA1',
    'oauth_version'=>1.0,
    'oauth_signature'=>'IkTXsl3d/FV7uOY0p9CFFCxpdyQ=');
if ($results['parameters'] != $expected) {
    print_r($results['parameters']);
        throw new OAuthSimpleException("Failure: incorrect parameters returned");
}


// ====
$expected="IkTXsl3d%2FFV7uOY0p9CFFCxpdyQ%3D";
if ($results['signature'] != $expected) {
    print $results['signature']."\n$expected\n";
    throw new OAuthSimpleException("Failure: incorrect signature returned");
}


// ====
$expected="http://example.com/test?fruit=bananas%20are%20%3CAwe%2Bsome%21%3E&number=42&oauth_consumer_key=test_key&oauth_nonce=abcd123&oauth_signature_method=HMAC-SHA1&oauth_timestamp=1234567890&oauth_token=access_key&oauth_version=1.0&oauth_signature=IkTXsl3d/FV7uOY0p9CFFCxpdyQ=";
if ($results['signed_url'] != $expected){
    print $results['signed_url']."\n$expected\n";
    throw new OAuthSimpleException("Failure: Invalid signed URL returned");
}

// ====
$expected='OAuth oauth_nonce="abcd123", oauth_timestamp="1234567890", oauth_consumer_key="test_key", oauth_token="access_key", oauth_signature_method="HMAC-SHA1", oauth_version="1.0", oauth_signature="IkTXsl3d%2FFV7uOY0p9CFFCxpdyQ%3D"';
if ($results['header'] != $expected) {
    print $results['header']."\n$expected\n";
    throw new OAuthSimpleException("Failure: Invalid Header returned");
}

// ====
$expected='GET&http%3A%2F%2Fexample.com%2Ftest&fruit%3Dbananas%2520are%2520%253CAwe%252Bsome%2521%253E%26number%3D42%26oauth_consumer_key%3Dtest_key%26oauth_nonce%3Dabcd123%26oauth_signature_method%3DHMAC-SHA1%26oauth_timestamp%3D1234567890%26oauth_token%3Daccess_key%26oauth_version%3D1.0';
if ($results['sbs'] != $expected) {
    print $results['sbs']."\n$expected\n";
    throw new OAuthSimpleException("Failure: Invalid Base String returned");
}

print("ok\n");
