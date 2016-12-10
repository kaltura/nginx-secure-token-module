#ifndef _NGX_HTTP_SECURE_TOKEN_CLOUDFRONT_H_INCLUDED_
#define _NGX_HTTP_SECURE_TOKEN_CLOUDFRONT_H_INCLUDED_

#include "../ngx_http_secure_token_conf.h"

// functions
char* ngx_secure_token_cloudfront_block(
	ngx_conf_t *cf, 
	ngx_command_t *cmd, 
	void *conf);

#endif // _NGX_HTTP_SECURE_TOKEN_CLOUDFRONT_H_INCLUDED_
