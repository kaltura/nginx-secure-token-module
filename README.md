# Akamai token module for Nginx

Generates an Akamai v2 token, either as a cookie or as a query string parameter (m3u8/mpd only).

## Installation

Add `--add-module` when configuring nginx:

    ./configure --add-module=$PATH_TO_AKAMAI_TOKEN

Requires OpenSSL.

## Configuration

#### akamai_token
* **syntax**: `akamai_token on/off`
* **default**: `off`
* **context**: `http`, `server`, `location`

Enables / disables the module

#### akamai_token_key
* **syntax**: `akamai_token_key key_hex`
* **default**: `empty`
* **context**: `http`, `server`, `location`

Sets the secret key

#### akamai_token_window
* **syntax**: `akamai_token_window window`
* **default**: `86400`
* **context**: `http`, `server`, `location`

Sets the validity time of the token in seconds

#### akamai_token_param_name
* **syntax**: `akamai_token_param_name name`
* **default**: `__hdnea__`
* **context**: `http`, `server`, `location`

Sets the token parameter name (either the name of the cookie or the query string parameter)

#### akamai_token_avoid_cookies
* **syntax**: `akamai_token_avoid_cookies on/off`
* **default**: `on`
* **context**: `http`, `server`, `location`

When enabled the module prefers to use a query string token instead of a cookie token.
A query string token is currently supported only for the following mime types:
* application/vnd.apple.mpegurl
* application/dash+xml
Other mime types will return a cookie token.

#### akamai_token_types
* **syntax**: `akamai_token_types mime_type ...`
* **default**: `none`
* **context**: `http`, `server`, `location`

Defines a set of mime types that should return a token

#### akamai_token_uri_filename_prefix
* **syntax**: `akamai_token_uri_filename_prefix prefix`
* **default**: `none`
* **context**: `http`, `server`, `location`

Defines a set of prefixes that will be matched against the URI file name, only URIs whose file name
starts with one of the defined prefixes will return a token

#### akamai_token_expires_time
* **syntax**: `akamai_token_expires_time time`
* **default**: `none`
* **context**: `http`, `server`, `location`

Sets the expiration time of requests that are not tokenized 
(determines the values of the Cache-Control and Expires HTTP headers)

#### akamai_token_cookie_token_expires_time
* **syntax**: `akamai_token_cookie_token_expires_time time`
* **default**: `none`
* **context**: `http`, `server`, `location`

Sets the expiration time of requests that are tokenized with a cookie token 
(determines the values of the Cache-Control and Expires HTTP headers)

#### akamai_token_query_token_expires_time
* **syntax**: `akamai_token_query_token_expires_time time`
* **default**: `none`
* **context**: `http`, `server`, `location`

Sets the expiration time of requests that are tokenized with a query string token 
(determines the values of the Cache-Control and Expires HTTP headers)

#### akamai_token_cache_scope
* **syntax**: `akamai_token_cache_scope scope`
* **default**: `public`
* **context**: `http`, `server`, `location`

Sets the cache scope (public/private) of requests that are not tokenized

#### akamai_token_token_cache_scope
* **syntax**: `akamai_token_token_cache_scope scope`
* **default**: `private`
* **context**: `http`, `server`, `location`

Sets the cache scope (public/private) of requests that are tokenized (query / cookie)

#### akamai_token_last_modified
* **syntax**: `akamai_token_last_modified time`
* **default**: `Sun, 19 Nov 2000 08:52:00 GMT`
* **context**: `http`, `server`, `location`

Sets the value of the last-modified header of requests that are not tokenized.
An empty string leaves the value of last-modified unaltered, while the string "now" sets the header to the server current time.

#### akamai_token_token_last_modified
* **syntax**: `akamai_token_token_last_modified time`
* **default**: `now`
* **context**: `http`, `server`, `location`

Sets the value of the last-modified header of requests that are tokenized (query / cookie)
An empty string leaves the value of last-modified unaltered, while the string "now" sets the header to the server current time.

## Copyright & License

All code in this project is released under the [AGPLv3 license](http://www.gnu.org/licenses/agpl-3.0.html) unless a different license for a particular library is specified in the applicable library path. 

Copyright © Kaltura Inc. All rights reserved.
