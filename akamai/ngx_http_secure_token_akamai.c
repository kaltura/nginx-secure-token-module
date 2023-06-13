#include "ngx_http_secure_token_akamai.h"
#include "../ngx_http_secure_token_filter_module.h"
#include "../ngx_http_secure_token_utils.h"

// constants
#define TOKEN_FORMAT "st=%uD~exp=%uD~acl=%V"
#define IP_TOKEN_PARAM "ip=%V~"
#define HMAC_PARAM "~hmac="

// typedefs
typedef struct {
	ngx_http_complex_value_t *acl;
	ngx_str_t key;
	ngx_str_t param_name;
	ngx_http_complex_value_t *ip_address;
	ngx_secure_token_time_t start;
	ngx_secure_token_time_t end;
} ngx_secure_token_akamai_token_t;

// globals
static ngx_command_t ngx_http_secure_token_akamai_cmds[] = {
	{ ngx_string("acl"),
	NGX_CONF_TAKE1,
	ngx_http_set_complex_value_slot,
	0,
	offsetof(ngx_secure_token_akamai_token_t, acl),
	NULL },

	{ ngx_string("key"),
	NGX_CONF_TAKE1,
	ngx_http_secure_token_conf_set_hex_str_slot,
	0,
	offsetof(ngx_secure_token_akamai_token_t, key),
	NULL },

	{ ngx_string("param_name"),
	NGX_CONF_TAKE1,
	ngx_conf_set_str_slot,
	0,
	offsetof(ngx_secure_token_akamai_token_t, param_name),
	NULL },

	{ ngx_string("ip_address"),
	NGX_CONF_TAKE1,
	ngx_http_set_complex_value_slot,
	0,
	offsetof(ngx_secure_token_akamai_token_t, ip_address),
	NULL },

	{ ngx_string("start"),
	NGX_CONF_TAKE1,
	ngx_http_secure_token_conf_set_time_slot,
	0,
	offsetof(ngx_secure_token_akamai_token_t, start),
	NULL },

	{ ngx_string("end"),
	NGX_CONF_TAKE1,
	ngx_http_secure_token_conf_set_time_slot,
	0,
	offsetof(ngx_secure_token_akamai_token_t, end),
	NULL },
};

static ngx_int_t
ngx_secure_token_akamai_get_var(
	ngx_http_request_t *r,
	ngx_http_variable_value_t *v,
	uintptr_t data)
{
	ngx_secure_token_akamai_token_t* token = (void*)data;
	time_t start_time;
	time_t end_time;
	u_char hash[10];
	unsigned hash_len;

	ngx_str_t signed_part;
	ngx_str_t ip_address;
	ngx_str_t acl;
	size_t result_size;
	u_char* p;
	ngx_int_t rc;

	// get the acl
	rc = ngx_http_secure_token_get_acl(r, token->acl, &acl);
	if (rc != NGX_OK)
	{
		return rc;
	}

	// get the result size
	result_size = token->param_name.len + 1 + sizeof(TOKEN_FORMAT) +
		2 * NGX_INT32_LEN + acl.len + sizeof(HMAC_PARAM) - 1 + 10 * 2 + 1;

	// get the ip address
	if (token->ip_address != NULL)
	{
		if (ngx_http_complex_value(
			r,
			token->ip_address,
			&ip_address) != NGX_OK)
		{
			return NGX_ERROR;
		}

		result_size += sizeof(IP_TOKEN_PARAM) + ip_address.len;
	}

	// allocate the result
	p = ngx_pnalloc(r->pool, result_size);
	if (p == NULL)
	{
		return NGX_ERROR;
	}

	v->data = p;

	// get the start / end time (mandatory fields)
	start_time = token->start.val;
	if (token->start.type == NGX_HTTP_SECURE_TOKEN_TIME_RELATIVE)
	{
		start_time += ngx_time();
	}

	end_time = token->end.val;
	if (token->end.type == NGX_HTTP_SECURE_TOKEN_TIME_RELATIVE)
	{
		end_time += ngx_time();
	}

	// build the result
	p = ngx_copy(p, token->param_name.data, token->param_name.len);
	*p++ = '=';

	signed_part.data = p;
	if (token->ip_address != NULL)
	{
		p = ngx_sprintf(p, IP_TOKEN_PARAM, &ip_address);
	}
	p = ngx_sprintf(p, TOKEN_FORMAT, start_time, end_time, &acl);
	signed_part.len = p - signed_part.data;

	p = ngx_copy(p, HMAC_PARAM, sizeof(HMAC_PARAM) - 1);
	p = ngx_hex_dump(p, hash, hash_len);
	*p = '\0';

	v->len = p - v->data;
	v->valid = 1;
	v->no_cacheable = 0;
	v->not_found = 0;

	return NGX_OK;
}

char *
ngx_secure_token_akamai_block(ngx_conf_t *cf, ngx_command_t *cmd, void *conf)
{
	ngx_secure_token_akamai_token_t* token;
	char* rv;

	// init config
	token = ngx_pcalloc(cf->pool, sizeof(*token));
	if (token == NULL)
	{
		return NGX_CONF_ERROR;
	}

	token->start.type = NGX_HTTP_SECURE_TOKEN_TIME_UNSET;
	token->end.type = NGX_HTTP_SECURE_TOKEN_TIME_UNSET;

	// parse the block
	rv = ngx_http_secure_token_conf_block(
		cf,
		ngx_http_secure_token_akamai_cmds,
		token,
		ngx_secure_token_akamai_get_var);
	if (rv != NGX_CONF_OK)
	{
		return rv;
	}

	// validate required params
	if (token->key.data == NULL)
	{
		ngx_conf_log_error(NGX_LOG_EMERG, cf, 0,
			"\"key\" is mandatory for akamai tokens");
		return NGX_CONF_ERROR;
	}

	// populate unset optional params
	if (token->param_name.data == NULL)
	{
		ngx_str_set(&token->param_name, "__hdnea__");
	}

	if (token->start.type == NGX_HTTP_SECURE_TOKEN_TIME_UNSET)
	{
		token->start.type = NGX_HTTP_SECURE_TOKEN_TIME_RELATIVE;
	}

	if (token->end.type == NGX_HTTP_SECURE_TOKEN_TIME_UNSET)
	{
		token->end.type = NGX_HTTP_SECURE_TOKEN_TIME_RELATIVE;
		token->end.val = 86400;
	}

	return NGX_CONF_OK;
}
