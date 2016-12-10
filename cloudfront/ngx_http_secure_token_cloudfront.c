#include "ngx_http_secure_token_cloudfront.h"
#include "../ngx_http_secure_token_filter_module.h"
#include "../ngx_http_secure_token_utils.h"
#include <openssl/pem.h>

// constants
#define POLICY_HEADER "{\"Statement\":[{\"Resource\":\"%V\",\"Condition\":{\"DateLessThan\":{\"AWS:EpochTime\":%uD}"		// DateLessThan is required
#define POLICY_CONDITION_IPADDRESS ",\"IpAddress\":{\"AWS:SourceIp\":\"%V\"}"
#define POLICY_FOOTER "}}]}"

#define POLICY_PARAM "Policy="
#define SIGNATURE_PARAM "&Signature="
#define KEY_PAIR_ID_PARAM "&Key-Pair-Id="

// typedefs
typedef struct {
	ngx_http_complex_value_t *acl;
	ngx_str_t key_pair_id;
	EVP_PKEY *private_key;
	ngx_http_complex_value_t *ip_address;
	ngx_secure_token_time_t end;
} ngx_secure_token_cloudfront_token_t;

// globals
static ngx_command_t ngx_http_secure_token_cloudfront_cmds[] = {
	{ ngx_string("acl"),
	NGX_CONF_TAKE1,
	ngx_http_set_complex_value_slot,
	0,
	offsetof(ngx_secure_token_cloudfront_token_t, acl),
	NULL },

	{ ngx_string("key_pair_id"),
	NGX_CONF_TAKE1,
	ngx_conf_set_str_slot,
	0,
	offsetof(ngx_secure_token_cloudfront_token_t, key_pair_id),
	NULL },

	{ ngx_string("private_key_file"),
	NGX_CONF_TAKE1,
	ngx_http_secure_token_conf_set_private_key_slot,
	0,
	offsetof(ngx_secure_token_cloudfront_token_t, private_key),
	NULL },

	{ ngx_string("ip_address"),
	NGX_CONF_TAKE1,
	ngx_http_set_complex_value_slot,
	0,
	offsetof(ngx_secure_token_cloudfront_token_t, ip_address),
	NULL },

	{ ngx_string("end"),
	NGX_CONF_TAKE1,
	ngx_http_secure_token_conf_set_time_slot,
	0,
	offsetof(ngx_secure_token_cloudfront_token_t, end),
	NULL },
};

// copied from ngx_string, changed the charset: + => -, / => ~, = => _
static u_char*
ngx_encode_base64_cloudfront(u_char *d, ngx_str_t *src)
{
	static u_char basis64[] =
		"ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789-~";

	return ngx_http_secure_token_encode_base64_internal(d, src, basis64, '_');
}

static ngx_int_t
ngx_secure_token_cloudfront_get_var(
	ngx_http_request_t *r,
	ngx_http_variable_value_t *v,
	uintptr_t data)
{
	ngx_secure_token_cloudfront_token_t* token = (void*)data;
	ngx_str_t ip_address;
	ngx_str_t signature;
	ngx_str_t policy;
	ngx_str_t acl;
	ngx_int_t rc;
	size_t policy_size;
	time_t end_time;
	u_char* p;

	// get the acl
	rc = ngx_http_secure_token_get_acl(r, token->acl, &acl);
	if (rc != NGX_OK)
	{
		return rc;
	}

	// get the size of the policy json
	policy_size = sizeof(POLICY_HEADER) + sizeof(POLICY_FOOTER) + acl.len + NGX_INT32_LEN;
	if (token->ip_address != NULL)
	{
		if (ngx_http_complex_value(
			r,
			token->ip_address,
			&ip_address) != NGX_OK)
		{
			return NGX_ERROR;
		}

		policy_size += sizeof(POLICY_CONDITION_IPADDRESS) + ip_address.len;
	}

	// build the policy json
	policy.data = ngx_pnalloc(r->pool, policy_size);
	if (policy.data == NULL)
	{
		return NGX_ERROR;
	}

	// get the end time
	end_time = token->end.val;
	if (token->end.type == NGX_HTTP_SECURE_TOKEN_TIME_RELATIVE)
	{
		end_time += ngx_time();
	}

	p = ngx_sprintf(policy.data, POLICY_HEADER, &acl, end_time);
	if (token->ip_address != NULL)
	{
		p = ngx_sprintf(p, POLICY_CONDITION_IPADDRESS, &ip_address);
	}
	p = ngx_copy(p, POLICY_FOOTER, sizeof(POLICY_FOOTER) - 1);

	policy.len = p - policy.data;

	// sign the policy
	rc = ngx_http_secure_token_sign(r, token->private_key, &policy, &signature);
	if (rc != NGX_OK)
	{
		return rc;
	}

	// build the token
	p = ngx_pnalloc(
		r->pool,
		sizeof(POLICY_PARAM) - 1 +
		ngx_base64_encoded_length(policy.len) +
		sizeof(SIGNATURE_PARAM) - 1 +
		ngx_base64_encoded_length(signature.len) +
		sizeof(KEY_PAIR_ID_PARAM) - 1 +
		token->key_pair_id.len + 1);
	if (p == NULL)
	{
		return NGX_ERROR;
	}

	v->data = p;

	p = ngx_copy(p, POLICY_PARAM, sizeof(POLICY_PARAM) - 1);
	p = ngx_encode_base64_cloudfront(p, &policy);
	p = ngx_copy(p, SIGNATURE_PARAM, sizeof(SIGNATURE_PARAM) - 1);
	p = ngx_encode_base64_cloudfront(p, &signature);
	p = ngx_copy(p, KEY_PAIR_ID_PARAM, sizeof(KEY_PAIR_ID_PARAM) - 1);
	p = ngx_copy(p, token->key_pair_id.data, token->key_pair_id.len);
	*p = '\0';

	v->len = p - v->data;
	v->valid = 1;
	v->no_cacheable = 0;
	v->not_found = 0;

	return NGX_OK;
}

char *
ngx_secure_token_cloudfront_block(ngx_conf_t *cf, ngx_command_t *cmd, void *conf)
{
	ngx_secure_token_cloudfront_token_t* token;
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
		ngx_http_secure_token_cloudfront_cmds,
		token,
		ngx_secure_token_cloudfront_get_var);
	if (rv != NGX_CONF_OK)
	{
		return rv;
	}

	// validate required params
	if (token->key_pair_id.data == NULL)
	{
		ngx_conf_log_error(NGX_LOG_EMERG, cf, 0,
			"\"key_pair_id\" is mandatory for cloudfront tokens");
		return NGX_CONF_ERROR;
	}

	if (token->private_key == NULL)
	{
		ngx_conf_log_error(NGX_LOG_EMERG, cf, 0,
			"\"private_key\" is mandatory for cloudfront tokens");
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
