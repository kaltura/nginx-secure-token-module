#include "ngx_http_secure_token_akamai.h"

#include <openssl/hmac.h>
#include <openssl/evp.h>

#define TOKEN_FORMAT "st=%uD~exp=%uD~acl=%V*"
#define HMAC_PARAM "~hmac="

void
ngx_http_secure_token_akamai_create_conf(
	ngx_conf_t *cf,
	ngx_http_secure_token_akamai_conf_t *conf)
{
}

char *
ngx_http_secure_token_akamai_merge_conf(
	ngx_conf_t *cf,
	ngx_http_secure_token_loc_conf_t *base,
	ngx_http_secure_token_akamai_conf_t *conf,
	ngx_http_secure_token_akamai_conf_t *prev)
{
	ngx_conf_merge_str_value(conf->key, prev->key, "");
	ngx_conf_merge_str_value(conf->param_name, prev->param_name, "__hdnea__");

	return NGX_CONF_OK;
}

ngx_int_t
ngx_http_secure_token_akamai_build(
	ngx_http_request_t* r, 
	ngx_http_secure_token_loc_conf_t *conf, 
	ngx_str_t* acl, 
	ngx_str_t* result)
{
	time_t current_time = ngx_time();
    u_char hash[EVP_MAX_MD_SIZE];
	unsigned hash_len;
    HMAC_CTX hmac;
	ngx_str_t signed_part;
	size_t result_size;
	u_char* p;
	
	result_size = conf->akamai.param_name.len + 1 + sizeof(TOKEN_FORMAT) + 2 * NGX_INT32_LEN + acl->len + sizeof(HMAC_PARAM) - 1 + EVP_MAX_MD_SIZE * 2 + 1;
	
	result->data = ngx_palloc(r->pool, result_size);
	if (result->data == NULL)
	{
		return NGX_ERROR;
	}
	
	p = ngx_copy(result->data, conf->akamai.param_name.data, conf->akamai.param_name.len);
	*p++ = '=';
	
	signed_part.data = p;
	p = ngx_sprintf(p, TOKEN_FORMAT, current_time, current_time + conf->window, acl);
	signed_part.len = p - signed_part.data;
	
	HMAC_Init(&hmac, conf->akamai.key.data, conf->akamai.key.len, EVP_sha256());
    HMAC_Update(&hmac, signed_part.data, signed_part.len);
    HMAC_Final(&hmac, hash, &hash_len);

	p = ngx_copy(p, HMAC_PARAM, sizeof(HMAC_PARAM) - 1);
	p = ngx_hex_dump(p, hash, hash_len);
	*p = '\0';
	
	result->len = p - result->data;
	return NGX_OK;
}
