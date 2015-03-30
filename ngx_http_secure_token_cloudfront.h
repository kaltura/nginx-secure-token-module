#ifndef _NGX_HTTP_SECURE_TOKEN_CLOUDFRONT_H_INCLUDED_
#define _NGX_HTTP_SECURE_TOKEN_CLOUDFRONT_H_INCLUDED_

#include "ngx_http_secure_token_conf.h"

void ngx_http_secure_token_cloudfront_create_conf(
	ngx_conf_t *cf,
	ngx_http_secure_token_cloudfront_conf_t *conf);

char *ngx_http_secure_token_cloudfront_merge_conf(
	ngx_conf_t *cf,
	ngx_http_secure_token_loc_conf_t *base,
	ngx_http_secure_token_cloudfront_conf_t *conf,
	ngx_http_secure_token_cloudfront_conf_t *prev);

ngx_int_t ngx_http_secure_token_cloudfront_build(
	ngx_http_request_t* r, 
	ngx_http_secure_token_loc_conf_t *conf, 
	ngx_str_t* result);

#endif // _NGX_HTTP_SECURE_TOKEN_CLOUDFRONT_H_INCLUDED_
