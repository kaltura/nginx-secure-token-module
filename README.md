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

## Copyright & License

Copyright (C) 2006-2014  Kaltura Inc.

This program is free software: you can redistribute it and/or modify
it under the terms of the GNU Affero General Public License as
published by the Free Software Foundation, either version 3 of the
License, or (at your option) any later version.

This program is distributed in the hope that it will be useful,
but WITHOUT ANY WARRANTY; without even the implied warranty of
MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
GNU Affero General Public License for more details.

You should have received a copy of the GNU Affero General Public License
along with this program.  If not, see <http://www.gnu.org/licenses/>.
