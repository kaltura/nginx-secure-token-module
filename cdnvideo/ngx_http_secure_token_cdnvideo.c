#include "ngx_http_secure_token_cdnvideo.h"
#include "../ngx_http_secure_token_filter_module.h"
#include "../ngx_http_secure_token_utils.h"

#include <ngx_md5.h>

// typedefs
typedef struct {
	ngx_http_complex_value_t *acl;
	ngx_str_t key;
	ngx_str_t md5_param_name;
	ngx_str_t exp_param_name;
	ngx_http_complex_value_t *ip_address;
	ngx_secure_token_time_t end;
} ngx_secure_token_cdnvideo_token_t;

// globals
static ngx_command_t ngx_http_secure_token_cdnvideo_cmds[] = {
	{ ngx_string("acl"),
	NGX_CONF_TAKE1,
	ngx_http_set_complex_value_slot,
	0,
	offsetof(ngx_secure_token_cdnvideo_token_t, acl),
	NULL },

	{ ngx_string("key"),
	NGX_CONF_TAKE1,
	ngx_conf_set_str_slot,
	0,
	offsetof(ngx_secure_token_cdnvideo_token_t, key),
	NULL },

	{ ngx_string("md5_param_name"),
	NGX_CONF_TAKE1,
	ngx_conf_set_str_slot,
	0,
	offsetof(ngx_secure_token_cdnvideo_token_t, md5_param_name),
	NULL },

	{ ngx_string("exp_param_name"),
	NGX_CONF_TAKE1,
	ngx_conf_set_str_slot,
	0,
	offsetof(ngx_secure_token_cdnvideo_token_t, exp_param_name),
	NULL },

	{ ngx_string("ip_address"),
	NGX_CONF_TAKE1,
	ngx_http_set_complex_value_slot,
	0,
	offsetof(ngx_secure_token_cdnvideo_token_t, ip_address),
	NULL },

	{ ngx_string("end"),
	NGX_CONF_TAKE1,
	ngx_http_secure_token_conf_set_time_slot,
	0,
	offsetof(ngx_secure_token_cdnvideo_token_t, end),
	NULL },
};

static ngx_int_t
ngx_secure_token_cdnvideo_get_var(
	ngx_http_request_t *r,
	ngx_http_variable_value_t *v,
	uintptr_t data)
{
	ngx_secure_token_cdnvideo_token_t* token = (void*)data;
	ngx_str_t end_time_str;
	ngx_str_t ip_address;
	ngx_str_t md5hash;
	ngx_str_t base64;
	ngx_str_t acl;
	ngx_md5_t md5;
	ngx_int_t rc;
	size_t result_size;
	time_t end_time;
	u_char* p;
	u_char end_time_str_buf[NGX_INT32_LEN];
	u_char md5hash_buf[MD5_DIGEST_LENGTH];

	ngx_md5_init(&md5);

	// key
	ngx_md5_update(&md5, token->key.data, token->key.len);
	ngx_md5_update(&md5, ":", 1);

	// end time
	end_time = token->end.val;
	if (token->end.type == NGX_HTTP_SECURE_TOKEN_TIME_RELATIVE)
	{
		end_time += ngx_time();
	}

	end_time_str.data = end_time_str_buf;
	end_time_str.len = ngx_sprintf(end_time_str_buf, "%uD", end_time) - end_time_str_buf;

	ngx_md5_update(&md5, end_time_str.data, end_time_str.len);
	ngx_md5_update(&md5, ":", 1);

	// ip address
	if (token->ip_address != NULL)
	{
		if (ngx_http_complex_value(
			r,
			token->ip_address,
			&ip_address) != NGX_OK)
		{
			return NGX_ERROR;
		}

		ngx_md5_update(&md5, ip_address.data, ip_address.len);
		ngx_md5_update(&md5, ":", 1);
	}

	// acl
	rc = ngx_http_secure_token_get_acl(r, token->acl, &acl);
	if (rc != NGX_OK)
	{
		return rc;
	}
	ngx_md5_update(&md5, acl.data, acl.len);

	ngx_md5_final(md5hash_buf, &md5);
	md5hash.data = md5hash_buf;
	md5hash.len = sizeof(md5hash_buf);

	// allocate the result
	result_size = token->md5_param_name.len + ngx_base64_encoded_length(MD5_DIGEST_LENGTH) +
		token->exp_param_name.len + end_time_str.len + sizeof("=&=");

	p = ngx_pnalloc(r->pool, result_size);
	if (p == NULL)
	{
		return NGX_ERROR;
	}

	v->data = p;

	// build the result
	p = ngx_copy(p, token->md5_param_name.data, token->md5_param_name.len);
	*p++ = '=';

	base64.data = p;
	ngx_encode_base64url(&base64, &md5hash);
	p += base64.len;

	*p++ = '&';
	p = ngx_copy(p, token->exp_param_name.data, token->exp_param_name.len);
	*p++ = '=';
	p = ngx_copy(p, end_time_str.data, end_time_str.len);

	*p = '\0';

	v->len = p - v->data;
	v->valid = 1;
	v->no_cacheable = 0;
	v->not_found = 0;

	return NGX_OK;
}

char *
ngx_secure_token_cdnvideo_block(ngx_conf_t *cf, ngx_command_t *cmd, void *conf)
{
	ngx_secure_token_cdnvideo_token_t* token;
	char* rv;

	// init config
	token = ngx_pcalloc(cf->pool, sizeof(*token));
	if (token == NULL)
	{
		return NGX_CONF_ERROR;
	}

	token->end.type = NGX_HTTP_SECURE_TOKEN_TIME_UNSET;

	// parse the block
	rv = ngx_http_secure_token_conf_block(
		cf,
		ngx_http_secure_token_cdnvideo_cmds,
		token,
		ngx_secure_token_cdnvideo_get_var);
	if (rv != NGX_CONF_OK)
	{
		return rv;
	}

	// validate required params
	if (token->key.data == NULL)
	{
		ngx_conf_log_error(NGX_LOG_EMERG, cf, 0,
			"\"key\" is mandatory for cdnvideo tokens");
		return NGX_CONF_ERROR;
	}

	// populate unset optional params
	if (token->md5_param_name.data == NULL)
	{
		ngx_str_set(&token->md5_param_name, "md5");
	}

	if (token->exp_param_name.data == NULL)
	{
		ngx_str_set(&token->exp_param_name, "e");
	}

	if (token->end.type == NGX_HTTP_SECURE_TOKEN_TIME_UNSET)
	{
		token->end.type = NGX_HTTP_SECURE_TOKEN_TIME_RELATIVE;
		token->end.val = 86400;
	}

	return NGX_CONF_OK;
}
