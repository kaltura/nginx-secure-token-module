# Akamai token module for Nginx

Generates an Akamai cookie v2 token.

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

Sets the name of cookie

#### akamai_token_types
* **syntax**: `akamai_token_types mime_type ...`
* **default**: `none`
* **context**: `http`, `server`, `location`

Defines a set of mime types that should return a token cookie

#### akamai_token_uri_filename_prefix
* **syntax**: `akamai_token_uri_filename_prefix prefix`
* **default**: `none`
* **context**: `http`, `server`, `location`

Defines a set of prefixes that will be matched against the URI file name, only URIs whose file name
starts with one of the defined prefixes will return a cookie

#### akamai_token_expires_time
* **syntax**: `akamai_token_expires_time time`
* **default**: `none`
* **context**: `http`, `server`, `location`

Sets the expiration time of requests that are not tokenized (determines the values of the Cache-Control
and Expires HTTP headers)

#### akamai_token_tokenized_expires_time
* **syntax**: `akamai_token_tokenized_expires_time time`
* **default**: `none`
* **context**: `http`, `server`, `location`

Sets the expiration time of requests that are tokenized (determines the values of the Cache-Control
and Expires HTTP headers)
