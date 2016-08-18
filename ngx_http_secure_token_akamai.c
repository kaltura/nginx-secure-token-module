#include "ngx_http_secure_token_akamai.h"
#include "ngx_http_secure_token_filter_module.h"
#include "ngx_http_secure_token_utils.h"

#include <openssl/hmac.h>
#include <openssl/evp.h>

#define TOKEN_FORMAT "st=%uD~exp=%uD~acl=%V"
#define IP_TOKEN_PARAM "ip=%V~"
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
	if (conf->key == NULL)
	{
		conf->key = prev->key;
	}
	ngx_conf_merge_str_value(conf->param_name, prev->param_name, "__hdnea__");

	if (base->build_token == ngx_http_secure_token_akamai_build)
	{
		if (conf->key == NULL)
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
	time_t start_time;
	time_t end_time;
	u_char hash[EVP_MAX_MD_SIZE];
	unsigned hash_len;
	HMAC_CTX hmac;
	ngx_str_t signed_part;
	ngx_str_t ip_address;
	ngx_str_t key_hex;
	ngx_str_t key;
	ngx_str_t acl;
	size_t result_size;
	u_char* p;
	ngx_int_t rc;

	// get the acl
	rc = ngx_http_secure_token_get_acl(r, conf->akamai.acl, &acl);
	if (rc != NGX_OK)
	{
		return rc;
	}

	// get the key
	if (ngx_http_complex_value(
		r,
		conf->akamai.key,
		&key_hex) != NGX_OK)
	{
		return NGX_ERROR;
	}

	rc = ngx_http_secure_token_decode_hex(
		r->pool,
		&key_hex,
		&key);
	if (rc != NGX_OK)
	{
		ngx_log_error(NGX_LOG_ERR, r->connection->log, 0,
			"ngx_http_secure_token_akamai_build: failed to decode hex key \"%V\"", &key_hex);
		return NGX_ERROR;
	}

	// get the ip address
	result_size = conf->akamai.param_name.len + 1 + sizeof(TOKEN_FORMAT) + 2 * NGX_INT32_LEN + acl.len + sizeof(HMAC_PARAM) - 1 + EVP_MAX_MD_SIZE * 2 + 1;

	if (conf->ip_address != NULL)
	{
		if (ngx_http_complex_value(
			r,
			conf->ip_address,
			&ip_address) != NGX_OK)
		{
			return NGX_ERROR;
		}

		result_size += sizeof(IP_TOKEN_PARAM) + ip_address.len;
	}

	// allocate the result
	result->data = ngx_pnalloc(r->pool, result_size);
	if (result->data == NULL)
	{
		return NGX_ERROR;
	}

	// get the start / end time (mandatory fields)
	if (conf->end_time > 0)
	{
		start_time = 0;
		end_time = conf->end_time;
	}
	else
	{
		start_time = ngx_time();
		end_time = start_time + conf->window;
	}
	
	// build the result
	p = ngx_copy(result->data, conf->akamai.param_name.data, conf->akamai.param_name.len);
	*p++ = '=';
	
	signed_part.data = p;
	if (conf->ip_address != NULL)
	{
		p = ngx_sprintf(p, IP_TOKEN_PARAM, &ip_address);
	}
	p = ngx_sprintf(p, TOKEN_FORMAT, start_time, end_time, &acl);
	signed_part.len = p - signed_part.data;
	
	HMAC_CTX_init(&hmac);
	HMAC_Init(&hmac, key.data, key.len, EVP_sha256());
	HMAC_Update(&hmac, signed_part.data, signed_part.len);
	HMAC_Final(&hmac, hash, &hash_len);
	HMAC_CTX_cleanup(&hmac);

	p = ngx_copy(p, HMAC_PARAM, sizeof(HMAC_PARAM) - 1);
	p = ngx_hex_dump(p, hash, hash_len);
	*p = '\0';
	
	result->len = p - result->data;
	return NGX_OK;
}
