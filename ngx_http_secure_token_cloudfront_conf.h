#ifndef _NGX_HTTP_SECURE_TOKEN_CLOUDFRONT_CONF_H_INCLUDED_
#define _NGX_HTTP_SECURE_TOKEN_CLOUDFRONT_CONF_H_INCLUDED_

#include <ngx_core.h>
#include <openssl/evp.h>

typedef struct {
	ngx_http_complex_value_t *acl;
	ngx_str_t key_pair_id;
	ngx_str_t private_key_file;
	EVP_PKEY *private_key;
} ngx_http_secure_token_cloudfront_conf_t;

#endif // _NGX_HTTP_SECURE_TOKEN_CLOUDFRONT_CONF_H_INCLUDED_
