#ifndef _NGX_HTTP_SECURE_TOKEN_UTILS_H_INCLUDED_
#define _NGX_HTTP_SECURE_TOKEN_UTILS_H_INCLUDED_

// includes
#include <ngx_core.h>

// functions
ngx_int_t ngx_http_secure_token_decode_hex(
	ngx_pool_t* pool, 
	ngx_str_t* src, 
	ngx_str_t* dest);

#endif // _NGX_HTTP_SECURE_TOKEN_UTILS_H_INCLUDED_
