<?php
    include ('./OAuthSimple.php');
    include ('./config.inc'); // Private configuration values
    /* 
        Defined in config.inc
        
        $apiKey
        $sharedSecret
        $accessToken
        $tokenSecret
     */

    // Some sample argument values

    // You can pass in arguments either as a string of URL characters:
    $argumentsAsString = "term=rat&expand=formats,synopsis&max_results=1&boo=foo&boo=fie";
    //   or a hash:
    $argumentsAsObject = Array(
        term=>'rat',
        expand=>'formats,synopsis',
        max_results=> '1',
    );

    $path = "http://api.netflix.com/catalog/titles";

    # Test 1 ====
    $oauth = new OAuthSimple($apiKey,$sharedSecret);
    $oauth->setParameters($argumentsAsString);
    $oauth->setPath($path);

    $sample1Results = $oauth->sign();

    # Test 2 =====

    $oauth=null;
    $oauth = new OAuthSimple($apiKey,$sharedSecret);
    $sample2Results = $oauth->sign(Array(action=>'GET',
                                         path=>$path,
                                         method=>'HMAC-SHA1',
                                         parameters=>$argumentsAsObject));

    # Test 3 ======

    $oauth = new OAuthSimple();
    $sample3Results = $oauth->sign(Array(path=>$path,
                    parameters=>$argumentsAsObject,
                    signatures=> Array('consumer_key'=>$apiKey,
                                        'shared_secret'=>$sharedSecret,
                                        'access_token'=>$accessToken,
                                        'access_secret'=>$tokenSecret)));
?>
<html>
    <head>
        <title>Test Document</title>
    </head>
    <body>
        <h1>Test Document</h1>
        <ol>
            <li><a href="<?php print $sample1Results['signed_url'] ?>">First Link</a><br />
            <?php print $sample1Results['signed_url'] ?></li>
            <li><a href="<?php print $sample2Results['signed_url'] ?>">Second Link</a></li>
            <li><a href="<?php print $sample3Results['signed_url'] ?>">Third Link</a></li>
        </ol>
        <a href="index.phps">Source for index</a><br />
        <a href="OAuthSimple.phps">Source for OAuthSimple.php</a>
    </body>
</html>
