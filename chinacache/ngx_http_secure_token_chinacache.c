#include "ngx_http_secure_token_chinacache.h"
#include "../ngx_http_secure_token_filter_module.h"
#include "../ngx_http_secure_token_utils.h"

// constants
#define TOKEN_PART1 "ACL="
#define TOKEN_PART2 "&P1=%V&P2=%V&P3=%uD&P4="

// typedefs
typedef struct {
	ngx_http_complex_value_t *acl;
	ngx_str_t key;
	ngx_str_t key_id;
	ngx_uint_t algorithm;
	ngx_secure_token_time_t end;
} ngx_secure_token_chinacache_token_t;

enum {
	ALGO_HMACSHA1 = 1,
	ALGO_HMACSHA256 = 2
};

// constants
static ngx_conf_enum_t algorithms[] = {
	{ ngx_string("hmacsha1"), ALGO_HMACSHA1 },
	{ ngx_string("hmacsha256"), ALGO_HMACSHA256 },
	{ ngx_null_string, 0 }
};

// globals
static ngx_command_t ngx_http_secure_token_chinacache_cmds[] = {
	{ ngx_string("acl"),
	NGX_CONF_TAKE1,
	ngx_http_set_complex_value_slot,
	0,
	offsetof(ngx_secure_token_chinacache_token_t, acl),
	NULL },

	{ ngx_string("key"),
	NGX_CONF_TAKE1,
	ngx_conf_set_str_slot,
	0,
	offsetof(ngx_secure_token_chinacache_token_t, key),
	NULL },

	{ ngx_string("key_id"),
	NGX_CONF_TAKE1,
	ngx_conf_set_str_slot,
	0,
	offsetof(ngx_secure_token_chinacache_token_t, key_id),
	NULL },

	{ ngx_string("algorithm"),
	NGX_CONF_TAKE1,
	ngx_conf_set_enum_slot,
	0,
	offsetof(ngx_secure_token_chinacache_token_t, algorithm),
	algorithms },
	
	{ ngx_string("end"),
	NGX_CONF_TAKE1,
	ngx_http_secure_token_conf_set_time_slot,
	0,
	offsetof(ngx_secure_token_chinacache_token_t, end),
	NULL },
};

static ngx_int_t
ngx_secure_token_chinacache_get_var(
	ngx_http_request_t *r,
	ngx_http_variable_value_t *v,
	uintptr_t data)
{
	ngx_secure_token_chinacache_token_t* token = (void*)data;
	ngx_str_t hash_base64_str;
	unsigned hash_len;

	ngx_str_t expiry_str;
	ngx_str_t hash_str;
	ngx_str_t acl;
	uintptr_t hash_escape;
	uintptr_t acl_escape;
	u_char hash_base64_buf[ngx_base64_encoded_length(EVP_MAX_MD_SIZE)];
	u_char expiry_buf[NGX_TIME_T_LEN];
	u_char hash_buf[EVP_MAX_MD_SIZE];
	size_t result_size;
	time_t end_time;
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
	
	expiry_str.data = expiry_buf;
	expiry_str.len = ngx_sprintf(expiry_buf, "%T", end_time) - expiry_buf;

	// calc the signature
	switch (token->algorithm)
	{
	case ALGO_HMACSHA1:
		
		break;
		
	case ALGO_HMACSHA256:
		break;
		
	default:
		return NGX_ERROR;
	}
	
	// base64 encode
	hash_str.data = hash_buf;
	hash_str.len = hash_len;
	hash_base64_str.data = hash_base64_buf;
	ngx_encode_base64(&hash_base64_str, &hash_str);

	hash_escape = 2 * ngx_escape_uri(NULL, hash_base64_str.data, hash_base64_str.len, NGX_ESCAPE_URI_COMPONENT);
	acl_escape = 2 * ngx_escape_uri(NULL, acl.data, acl.len, NGX_ESCAPE_URI_COMPONENT);

	// get the result size
	result_size = sizeof(TOKEN_PART1) + sizeof(TOKEN_PART2) + acl.len + acl_escape + 
		expiry_str.len + token->key_id.len + NGX_INT32_LEN + 
		hash_base64_str.len + hash_escape;

	// allocate the result
	p = ngx_pnalloc(r->pool, result_size);
	if (p == NULL)
	{
		return NGX_ERROR;
	}

	v->data = p;

	// build the result
	p = ngx_copy(p, TOKEN_PART1, sizeof(TOKEN_PART1) - 1);

	p = (u_char*)ngx_escape_uri(p, acl.data, acl.len, NGX_ESCAPE_URI_COMPONENT);

	p = ngx_sprintf(p, TOKEN_PART2, &expiry_str, &token->key_id, (uint32_t)token->algorithm);
	if (hash_escape)
	{
		p = (u_char*)ngx_escape_uri(p, hash_base64_str.data, hash_base64_str.len, NGX_ESCAPE_URI_COMPONENT);
	}
	else
	{
		p = ngx_copy(p, hash_base64_str.data, hash_base64_str.len);
	}
		
	*p = '\0';

	v->len = p - v->data;
	v->valid = 1;
	v->no_cacheable = 0;
	v->not_found = 0;

	return NGX_OK;
}

char *
ngx_secure_token_chinacache_block(ngx_conf_t *cf, ngx_command_t *cmd, void *conf)
{
	ngx_secure_token_chinacache_token_t* token;
	char* rv;

	// init config
	token = ngx_pcalloc(cf->pool, sizeof(*token));
	if (token == NULL)
	{
		return NGX_CONF_ERROR;
	}

	token->algorithm = NGX_CONF_UNSET_UINT;
	token->end.type = NGX_HTTP_SECURE_TOKEN_TIME_UNSET;

	// parse the block
	rv = ngx_http_secure_token_conf_block(
		cf,
		ngx_http_secure_token_chinacache_cmds,
		token,
		ngx_secure_token_chinacache_get_var);
	if (rv != NGX_CONF_OK)
	{
		return rv;
	}

	// validate required params
	if (token->key.data == NULL)
	{
		ngx_conf_log_error(NGX_LOG_EMERG, cf, 0,
			"\"key\" is mandatory for chinacache tokens");
		return NGX_CONF_ERROR;
	}

	if (token->key_id.data == NULL)
	{
		ngx_conf_log_error(NGX_LOG_EMERG, cf, 0,
			"\"key_id\" is mandatory for chinacache tokens");
		return NGX_CONF_ERROR;
	}

	// populate unset optional params
	if (token->algorithm == NGX_CONF_UNSET_UINT)
	{
		token->algorithm = ALGO_HMACSHA256;
	}

	if (token->end.type == NGX_HTTP_SECURE_TOKEN_TIME_UNSET)
	{
		token->end.type = NGX_HTTP_SECURE_TOKEN_TIME_RELATIVE;
		token->end.val = 86400;
	}

	return NGX_CONF_OK;
}
