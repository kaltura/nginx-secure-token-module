# Change log

Note: the list of changes below may not include all changes, it will include mostly "breaking" changes.
	Usually, these are changes that require some update to nginx.conf in order to retain the existing behavior.

## 2016/12/08 - refactor conf structure

The following configuration settings were removed:
* secure_token - this parameter no longer gets the token type (akamai/cloudfront) it now gets an expression that evaluates to the token.
	use a secure_token_akamai / secure_token_cloudfront block to define a token variable, and use the token variable as the secure_token expression.
* secure_token_window - use the end param inside a secure_token_akamai / secure_token_cloudfront block
* secure_token_end_time - use the end param inside a secure_token_akamai / secure_token_cloudfront block
* secure_token_ip_address - use the ip_address param inside a secure_token_akamai / secure_token_cloudfront block
* secure_token_akamai_key - use the key param inside a secure_token_akamai block
* secure_token_akamai_param_name - use the param_name param inside a secure_token_akamai block
* secure_token_akamai_acl - use the acl param inside a secure_token_akamai block
* secure_token_cloudfront_private_key_file - use the private_key_file param inside a secure_token_cloudfront block
* secure_token_cloudfront_key_pair_id - use the key_pair_id param inside a secure_token_cloudfront block
* secure_token_cloudfront_acl - use the acl param inside a secure_token_cloudfront block
