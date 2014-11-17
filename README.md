# Akamai token module for Nginx

Generates an Akamai cookie v2 token.

## Installation

Add `--add-module` when configuring nginx:

    ./configure --add-module=$PATH_TO_AKAMAI_TOKEN

Requires OpenSSL.

## Configuration

#### akamai_token_key
* **syntax**: `akamai_token_key key_hex`
* **default**: `empty`
* **context**: `http`, `server`, `location`

Sets the secret key, when empty, the module is disabled

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

#### akamai_token_uri_extens
* **syntax**: `akamai_token_uri_extens ext1,ext2`
* **default**: `none`
* **context**: `http`, `server`, `location`

Sets the file extensions of URIs that should return a cookie
