#include <ngx_config.h>

#include "ngx_http_secure_token_iijpta.h"
#include "../ngx_http_secure_token_filter_module.h"
#include "../ngx_http_secure_token_utils.h"

#include <openssl/evp.h>

// constants
#define CRC32_SIZE    4
#define DEADLINE_SIZE 8
#define PATH_LIMIT    1024

static char *ngx_conf_check_byte_len_bounds(ngx_conf_t *cf, void *post, void *data);

// typedefs
typedef struct {
	ngx_str_t key;
	ngx_str_t iv;
	ngx_str_t path;
	time_t    timelimit;
} ngx_secure_token_iijpta_token_t;

static ngx_conf_num_bounds_t ngx_http_secure_token_iijpta_key_bounds = {
	ngx_conf_check_byte_len_bounds, 16, 16
};

static ngx_conf_num_bounds_t ngx_http_secure_token_iijpta_iv_bounds = {
	ngx_conf_check_byte_len_bounds, 16, 16
};

// globals
static ngx_command_t ngx_http_secure_token_iijpta_cmds[] = {
	{ ngx_string("key"),
	NGX_CONF_TAKE1,
	ngx_http_secure_token_conf_set_hex_str_slot,
	0,
	offsetof(ngx_secure_token_iijpta_token_t, key),
	&ngx_http_secure_token_iijpta_key_bounds },

	{ ngx_string("iv"),
	NGX_CONF_TAKE1,
	ngx_http_secure_token_conf_set_hex_str_slot,
	0,
	offsetof(ngx_secure_token_iijpta_token_t, iv),
	&ngx_http_secure_token_iijpta_iv_bounds },

	{ ngx_string("path"),
	NGX_CONF_TAKE1,
	ngx_conf_set_str_slot,
	0,
	offsetof(ngx_secure_token_iijpta_token_t, path),
	NULL },

	{ ngx_string("timelimit"),
	NGX_CONF_TAKE1,
	ngx_conf_set_sec_slot,
	0,
	offsetof(ngx_secure_token_iijpta_token_t, timelimit),
	NULL },
};

static char *
ngx_conf_check_byte_len_bounds(ngx_conf_t *cf, void *post, void *data)
{
	ngx_conf_num_bounds_t  *bounds = post;
	ngx_str_t  *sp = data;

	if (bounds->high == -1) {
		if (sp->len >= (size_t)bounds->low) {
			return NGX_CONF_OK;
		}

		ngx_conf_log_error(NGX_LOG_EMERG, cf, 0,
			"value must be equal to or greater than %i",
			bounds->low);

		return NGX_CONF_ERROR;
	}

	if (sp->len >= (size_t)bounds->low && sp->len <= (size_t)bounds->high) {
		return NGX_CONF_OK;
	}

	ngx_conf_log_error(NGX_LOG_EMERG, cf, 0,
		"value must be between %i byte and %i byte",
		bounds->low, bounds->high);

	return NGX_CONF_ERROR;
}

static ngx_int_t
ngx_secure_token_iijpta_get_var(
	ngx_http_request_t *r,
	ngx_http_variable_value_t *v,
	uintptr_t data)
{
	EVP_CIPHER_CTX ctx;
	uint32_t crc;
	ngx_secure_token_iijpta_token_t* token = (void*)data;
	u_char* in;
	size_t in_len  = CRC32_SIZE + DEADLINE_SIZE + token->path.len;
	u_char *p;
	uint8_t out[PATH_LIMIT * 2];
	int out_len1, out_len2;
	time_t now;
	uint64_t deadline;

	in = ngx_pnalloc(r->pool, in_len);
	if (in == NULL)
	{
		return NGX_ERROR;
	}

	now = ngx_time();
	deadline = now + token->timelimit;
	deadline = htobe64(deadline);
	memcpy(&in[CRC32_SIZE], &deadline, sizeof(deadline));
	memcpy(&in[CRC32_SIZE + DEADLINE_SIZE], token->path.data, token->path.len);
	crc = ngx_crc32_long(&in[CRC32_SIZE], DEADLINE_SIZE + token->path.len);
	crc = htobe32(crc);
	memcpy(in, &crc, sizeof(crc));

	EVP_EncryptInit(&ctx, EVP_aes_128_cbc(), token->key.data, token->iv.data);
	EVP_EncryptUpdate(&ctx, out, &out_len1, in, in_len);
	EVP_EncryptFinal(&ctx, out + out_len1, &out_len2);

	/* sizeof("pta=") returns 5, includes null termination. */
	p = ngx_pnalloc(r->pool, sizeof("pta=") + ((out_len1 + out_len2) * 2));
	if (p == NULL)
	{
		return NGX_ERROR;
	}

	v->data = p;
	p = ngx_copy(p, "pta=", sizeof("pta=") - 1);
	p = ngx_hex_dump(p, out, out_len1 + out_len2);
	*p = '\0';

	v->len = p - v->data;
	v->valid = 1;
	v->no_cacheable = 0;
	v->not_found = 0;

	return NGX_OK;
}

char *
ngx_secure_token_iijpta_block(ngx_conf_t *cf, ngx_command_t *cmd, void *conf)
{
	ngx_secure_token_iijpta_token_t* token;
	char* rv;

	// init config
	token = ngx_pcalloc(cf->pool, sizeof(*token));
	if (token == NULL)
	{
		return NGX_CONF_ERROR;
	}

	token->timelimit = NGX_CONF_UNSET;

	// parse the block
	rv = ngx_http_secure_token_conf_block(
		cf,
		ngx_http_secure_token_iijpta_cmds,
		token,
		ngx_secure_token_iijpta_get_var);
	if (rv != NGX_CONF_OK)
	{
		return rv;
	}

	if (token->path.data == NULL)
	{
		ngx_str_set(&token->path, "/*");
	}
	else
	{
		if (token->path.len > PATH_LIMIT)
		{
			ngx_conf_log_error(NGX_LOG_EMERG, cf, 0,
					   "\"path\" is too long for iijpta tokens");
			return NGX_CONF_ERROR;
		}
	}

	if (token->timelimit == NGX_CONF_UNSET)
	{
		token->timelimit = 86400;
	}

	return NGX_CONF_OK;
}
