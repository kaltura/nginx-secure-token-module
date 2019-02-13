#include "ngx_http_secure_token_iijpta.h"
#include "../ngx_http_secure_token_filter_module.h"
#include "../ngx_http_secure_token_utils.h"

#include <openssl/evp.h>

// constants
#define CRC32_SIZE    4
#define DEADLINE_SIZE 8
#define PATH_LIMIT    1024

// typedefs
typedef struct {
	ngx_str_t key;
	ngx_str_t iv;
	ngx_str_t path;
	time_t    timelimit;
} ngx_secure_token_iijpta_token_t;

// globals
static ngx_command_t ngx_http_secure_token_iijpta_cmds[] = {
	{ ngx_string("key"),
	NGX_CONF_TAKE1,
	ngx_http_secure_token_conf_set_hex_str_slot,
	0,
	offsetof(ngx_secure_token_iijpta_token_t, key),
	NULL },

	{ ngx_string("iv"),
	NGX_CONF_TAKE1,
	ngx_http_secure_token_conf_set_hex_str_slot,
	0,
	offsetof(ngx_secure_token_iijpta_token_t, iv),
	NULL },

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
	u_char *qparam;
	uint8_t out[PATH_LIMIT * 2];
	int out_len1, out_len2;
	time_t now;
	uint64_t deadline;

	in = ngx_pnalloc(r->pool, in_len);
	if (in == NULL)
	{
		return NGX_ERROR;
	}

	now = time(NULL);
	if (now == -1)
	{
		ngx_log_error(NGX_LOG_ERR, r->connection->log, 0,
				   "%s", "couldn't get current time");
		return NGX_ERROR;
	}

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
	qparam = ngx_pnalloc(r->pool, sizeof("pta=") + ((out_len1 + out_len2) * 2));
	if (qparam == NULL)
	{
		return NGX_ERROR;
	}

	v->data = qparam;
	qparam = ngx_copy(qparam, "pta=", sizeof("pta=") - 1);
	qparam = ngx_hex_dump(qparam, out, out_len1 + out_len2);
	*qparam = '\0';

	v->len = qparam - v->data;
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

	// validate required params
	if (token->key.data == NULL)
	{
		ngx_conf_log_error(NGX_LOG_EMERG, cf, 0,
			"\"key\" is mandatory for iijpta tokens");
		return NGX_CONF_ERROR;
	}

        if (token->key.len != 16)
        {
		ngx_conf_log_error(NGX_LOG_EMERG, cf, 0,
			"\"key\" must be 16 byte hex string(32 characters)");
		return NGX_CONF_ERROR;
        }

	if (token->iv.data == NULL)
	{
		ngx_conf_log_error(NGX_LOG_EMERG, cf, 0,
			"\"iv\" is mandatory for iijpta tokens");
		return NGX_CONF_ERROR;
	}

        if (token->iv.len != 16)
        {
		ngx_conf_log_error(NGX_LOG_EMERG, cf, 0,
			"\"iv\" must be 16 byte hex string(32 characters)");
		return NGX_CONF_ERROR;
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
