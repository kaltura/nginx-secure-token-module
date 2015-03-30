#include "ngx_http_secure_token_akamai.h"

#include <openssl/hmac.h>
#include <openssl/evp.h>

#define TOKEN_FORMAT "st=%uD~exp=%uD~acl=%V"
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
	if (conf->acl == NULL)
	{
		conf->acl = prev->acl;
	}
	ngx_conf_merge_str_value(conf->key, prev->key, "");
	ngx_conf_merge_str_value(conf->param_name, prev->param_name, "__hdnea__");

	if (base->build_token == ngx_http_secure_token_akamai_build)
	{
		if (conf->key.len == 0)
		{
			ngx_conf_log_error(NGX_LOG_EMERG, cf, 0,
				"\"secure_token_akamai_key\" is mandatory for akamai tokens");
			return NGX_CONF_ERROR;
		}
	}

	return NGX_CONF_OK;
}

ngx_int_t
ngx_http_secure_token_akamai_build(
	ngx_http_request_t* r, 
	ngx_http_secure_token_loc_conf_t *conf, 
	ngx_str_t* result)
{
	time_t current_time = ngx_time();
	u_char hash[EVP_MAX_MD_SIZE];
	unsigned hash_len;
	HMAC_CTX hmac;
	ngx_str_t signed_part;
	ngx_str_t acl;
	size_t result_size;
	u_char* p;
	ngx_int_t rc;

	rc = ngx_http_secure_token_get_acl(r, conf->akamai.acl, &acl);
	if (rc != NGX_OK)
	{
		return rc;
	}

	result_size = conf->akamai.param_name.len + 1 + sizeof(TOKEN_FORMAT) + 2 * NGX_INT32_LEN + acl.len + sizeof(HMAC_PARAM) - 1 + EVP_MAX_MD_SIZE * 2 + 1;
	
	result->data = ngx_palloc(r->pool, result_size);
	if (result->data == NULL)
	{
		return NGX_ERROR;
	}
	
	p = ngx_copy(result->data, conf->akamai.param_name.data, conf->akamai.param_name.len);
	*p++ = '=';
	
	signed_part.data = p;
	p = ngx_sprintf(p, TOKEN_FORMAT, current_time, current_time + conf->window, &acl);
	signed_part.len = p - signed_part.data;
	
	HMAC_CTX_init(&hmac);

	if (!HMAC_Init(&hmac, conf->akamai.key.data, conf->akamai.key.len, EVP_sha256()))
	{
		goto error;
	}
	if (!HMAC_Update(&hmac, signed_part.data, signed_part.len))
	{
		goto error;
	}
	if (!HMAC_Final(&hmac, hash, &hash_len))
	{
		goto error;
	}

	HMAC_CTX_cleanup(&hmac);

	p = ngx_copy(p, HMAC_PARAM, sizeof(HMAC_PARAM) - 1);
	p = ngx_hex_dump(p, hash, hash_len);
	*p = '\0';
	
	result->len = p - result->data;
	return NGX_OK;

error:

	HMAC_CTX_cleanup(&hmac);
	return NGX_ERROR;
}
