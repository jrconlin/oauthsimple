#OAuthSimple for Javascript

## A Word of Caution:
It might be useful to understand what OAuth is. OAuth is a way for two
(or more) parties to confirm the fact that they are who they say they
are. This is done by a set of secret handshakes that only both sides
know.

In short, the very first thing that happens is that both sides
exchange some secret value. This exchange happens outside of OAuth and
the secret is NEVER displayed to anyone other than the two parties.

This... gets a bit tricky when you're talking about javascript.

The example code in index.html doesn't even try to hide the secret,
and frankly, it's considerably difficult to do that even in the best
of situations because users can stop and examine code with most recent
browsers.

So, while your secret may be disclosed, in a properly functioning
system, the user's data is only disclosed after the user concents to
it.

If you're building this for your own use on a device you control where
your code can't be inspected by malicious parties. Go for it.
Otherwise, you probably want to do the OAuth exchange on the server
and pass back the final access token to the javascript app. (See the
OAuth documentation for whatever site you're working with for details
about that.)

## Webcalls without a Web

There are lots of environments that let you run javascript outside of
a browser. I'm not going to detail all of them (because there are a
lot of them), but I'll note that OAuth was designed around using HTTP
as the transport mechanism.

Fortunately, that doesn't mean that you have to fire up your browser
of choice in order to make these calls. You do need to have something
that talks HTTP, however. Again, there are lots of choices, for
instance libcURL is available for darn near everything out there.
There are also plenty of systems that provide native calls.

For the most part, these calls will either want the arguments in-line
with the call (use ```OAuthSimple().sign(...).signed_url;```), as a
request header ( ```OAuthSimple().sign(...).header```), or as the POST
request body (you may want to use _normalizedParameters() for that,
but understand that it's not a public function and is subject to
change.) Again, see the documentation for the service you wish to
connect to for how best to provide this info.

## How to use it.

Honestly? Read the source. I commented the heck out of it and there's
example code inside there. Plus, unlike this, it is more likely to be
documented and included with the distribution.
