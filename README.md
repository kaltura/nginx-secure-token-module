# Secure token module for Nginx

Generates CDN tokens, either as a cookie or as a query string parameter (m3u8,mpd,f4m only).
Currently supports Akamai v2 tokens, and Amazon CloudFront tokens.

## Installation

Add `--add-module` when configuring nginx:

    ./configure --add-module=$PATH_TO_SECURE_TOKEN

Requires OpenSSL.

## Configuration

#### secure_token
* **syntax**: `secure_token type`
* **default**: `none`
* **context**: `http`, `server`, `location`

Enables token generation of the requested type, supported types are: akamai, cloudfront

#### secure_token_akamai_key
* **syntax**: `secure_token_key key_hex`
* **default**: `empty`
* **context**: `http`, `server`, `location`

Sets the secret key

#### secure_token_akamai_param_name
* **syntax**: `secure_token_param_name name`
* **default**: `__hdnea__`
* **context**: `http`, `server`, `location`

Sets the token parameter name (either the name of the cookie or the query string parameter)

#### secure_token_cloudfront_private_key_file
* **syntax**: `secure_token_cloudfront_private_key_file filename`
* **default**: `none`
* **context**: `http`, `server`, `location`

Sets the file name of the private key (PEM file)

#### secure_token_cloudfront_key_pair_id
* **syntax**: `secure_token_cloudfront_key_pair_id id`
* **default**: `none`
* **context**: `http`, `server`, `location`

Sets the key pair id

#### secure_token_window
* **syntax**: `secure_token_window window`
* **default**: `86400`
* **context**: `http`, `server`, `location`

Sets the validity time of the token in seconds

#### secure_token_avoid_cookies
* **syntax**: `secure_token_avoid_cookies on/off`
* **default**: `on`
* **context**: `http`, `server`, `location`

When enabled the module prefers to use a query string token instead of a cookie token.
A query string token is currently supported only for the following mime types:
* application/vnd.apple.mpegurl
* application/dash+xml
Other mime types will return a cookie token.

#### secure_token_types
* **syntax**: `secure_token_types mime_type ...`
* **default**: `none`
* **context**: `http`, `server`, `location`

Defines a set of mime types that should return a token

#### secure_token_uri_filename_prefix
* **syntax**: `secure_token_uri_filename_prefix prefix`
* **default**: `none`
* **context**: `http`, `server`, `location`

Defines a set of prefixes that will be matched against the URI file name, only URIs whose file name
starts with one of the defined prefixes will return a token

#### secure_token_expires_time
* **syntax**: `secure_token_expires_time time`
* **default**: `none`
* **context**: `http`, `server`, `location`

Sets the expiration time of responses that are not tokenized 
(determines the values of the Cache-Control and Expires HTTP headers)

#### secure_token_cookie_token_expires_time
* **syntax**: `secure_token_cookie_token_expires_time time`
* **default**: `none`
* **context**: `http`, `server`, `location`

Sets the expiration time of responses that are tokenized with a cookie token 
(determines the values of the Cache-Control and Expires HTTP headers)

#### secure_token_query_token_expires_time
* **syntax**: `secure_token_query_token_expires_time time`
* **default**: `none`
* **context**: `http`, `server`, `location`

Sets the expiration time of responses that are tokenized with a query string token 
(determines the values of the Cache-Control and Expires HTTP headers)

#### secure_token_cache_scope
* **syntax**: `secure_token_cache_scope scope`
* **default**: `public`
* **context**: `http`, `server`, `location`

Sets the cache scope (public/private) of responses that are not tokenized

#### secure_token_token_cache_scope
* **syntax**: `secure_token_token_cache_scope scope`
* **default**: `private`
* **context**: `http`, `server`, `location`

Sets the cache scope (public/private) of responses that are tokenized (query / cookie)

#### secure_token_last_modified
* **syntax**: `secure_token_last_modified time`
* **default**: `Sun, 19 Nov 2000 08:52:00 GMT`
* **context**: `http`, `server`, `location`

Sets the value of the last-modified header of responses that are not tokenized.
An empty string leaves the value of last-modified unaltered, while the string "now" sets the header to the server current time.

#### secure_token_token_last_modified
* **syntax**: `secure_token_token_last_modified time`
* **default**: `now`
* **context**: `http`, `server`, `location`

Sets the value of the last-modified header of responses that are tokenized (query / cookie)
An empty string leaves the value of last-modified unaltered, while the string "now" sets the header to the server current time.

## Copyright & License

All code in this project is released under the [AGPLv3 license](http://www.gnu.org/licenses/agpl-3.0.html) unless a different license for a particular library is specified in the applicable library path. 

Copyright © Kaltura Inc. All rights reserved.
