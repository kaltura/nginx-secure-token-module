#ifndef _NGX_HTTP_SECURE_TOKEN_CLOUD_FRONT_CONF_H_INCLUDED_
#define _NGX_HTTP_SECURE_TOKEN_CLOUD_FRONT_CONF_H_INCLUDED_

#include <ngx_core.h>
#include <openssl/evp.h>

typedef struct {
	ngx_str_t key_pair_id;
	ngx_str_t private_key_file;
	EVP_PKEY *private_key;
} ngx_http_secure_token_cloud_front_conf_t;

#endif // _NGX_HTTP_SECURE_TOKEN_CLOUD_FRONT_CONF_H_INCLUDED_
