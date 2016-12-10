#include "ngx_http_secure_token_cht.h"
#include "../ngx_http_secure_token_filter_module.h"
#include "../ngx_http_secure_token_utils.h"

#include <ngx_md5.h>

// constants
#define TOKEN_PART1 "token="
#define TOKEN_PART2 "&expires="

// typedefs
typedef struct {
	ngx_http_complex_value_t *acl;
	ngx_str_t key;
	ngx_secure_token_time_t end;
} ngx_secure_token_cht_token_t;

// globals
static ngx_command_t ngx_http_secure_token_cht_cmds[] = {
	{ ngx_string("acl"),
	NGX_CONF_TAKE1,
	ngx_http_set_complex_value_slot,
	0,
	offsetof(ngx_secure_token_cht_token_t, acl),
	NULL },

	{ ngx_string("key"),
	NGX_CONF_TAKE1,
	ngx_conf_set_str_slot,
	0,
	offsetof(ngx_secure_token_cht_token_t, key),
	NULL },

	{ ngx_string("end"),
	NGX_CONF_TAKE1,
	ngx_http_secure_token_conf_set_time_slot,
	0,
	offsetof(ngx_secure_token_cht_token_t, end),
	NULL },
};

static ngx_int_t
ngx_secure_token_cht_get_var(
	ngx_http_request_t *r,
	ngx_http_variable_value_t *v,
	uintptr_t data)
{
	ngx_secure_token_cht_token_t* token = (void*)data;
	ngx_str_t expires_str;
	ngx_str_t md5hash_str;
	ngx_str_t token_str;
	ngx_str_t acl;
	ngx_md5_t md5;
	u_char end_time_buf[NGX_INT32_LEN];
	u_char md5hash_buf[MD5_DIGEST_LENGTH];
	u_char token_buf[ngx_base64_encoded_length(MD5_DIGEST_LENGTH)];
	time_t end_time;
	size_t result_size;
	u_char* p;
	ngx_int_t rc;

	// get the acl
	rc = ngx_http_secure_token_get_acl(r, token->acl, &acl);
	if (rc != NGX_OK)
	{
		return rc;
	}

	// get the end time
	end_time = token->end.val;
	if (token->end.type == NGX_HTTP_SECURE_TOKEN_TIME_RELATIVE)
	{
		end_time += ngx_time();
	}
	expires_str.data = end_time_buf;
	expires_str.len = ngx_sprintf(end_time_buf, "%uD", (uint32_t)end_time) - end_time_buf;
	
	// calculate the signature
	ngx_md5_init(&md5);
	ngx_md5_update(&md5, acl.data, acl.len);
	ngx_md5_update(&md5, token->key.data, token->key.len);
	ngx_md5_update(&md5, expires_str.data, expires_str.len);
	ngx_md5_final(md5hash_buf, &md5);

	md5hash_str.data = md5hash_buf;
	md5hash_str.len = sizeof(md5hash_buf);

	token_str.data = token_buf;
	ngx_encode_base64url(&token_str, &md5hash_str);

	// get the result size
	result_size = sizeof(TOKEN_PART1) + token_str.len + sizeof(TOKEN_PART2) + expires_str.len;

	// allocate the result
	p = ngx_pnalloc(r->pool, result_size);
	if (p == NULL)
	{
		return NGX_ERROR;
	}

	v->data = p;

	// build the result
	p = ngx_copy(p, TOKEN_PART1, sizeof(TOKEN_PART1) - 1);
	p = ngx_copy(p, token_str.data, token_str.len);
	p = ngx_copy(p, TOKEN_PART2, sizeof(TOKEN_PART2) - 1);
	p = ngx_copy(p, expires_str.data, expires_str.len);
	*p = '\0';

	v->len = p - v->data;
	v->valid = 1;
	v->no_cacheable = 0;
	v->not_found = 0;

	return NGX_OK;
}

char *
ngx_secure_token_cht_block(ngx_conf_t *cf, ngx_command_t *cmd, void *conf)
{
	ngx_secure_token_cht_token_t* token;
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
		ngx_http_secure_token_cht_cmds,
		token,
		ngx_secure_token_cht_get_var);
	if (rv != NGX_CONF_OK)
	{
		return rv;
	}

	// validate required params
	if (token->key.data == NULL)
	{
		ngx_conf_log_error(NGX_LOG_EMERG, cf, 0,
			"\"key\" is mandatory for cht tokens");
		return NGX_CONF_ERROR;
	}

	// populate unset optional params
	if (token->end.type == NGX_HTTP_SECURE_TOKEN_TIME_UNSET)
	{
		token->end.type = NGX_HTTP_SECURE_TOKEN_TIME_RELATIVE;
		token->end.val = 86400;
	}

	return NGX_CONF_OK;
}
