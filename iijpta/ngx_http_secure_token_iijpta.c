#include <ngx_config.h>

#include "ngx_http_secure_token_iijpta.h"
#include "../ngx_http_secure_token_filter_module.h"
#include "../ngx_http_secure_token_utils.h"

#include <openssl/evp.h>

// constants
#define CRC32_SIZE    4
#define EXPIRY_SIZE   8
#define PATH_LIMIT    1024

// typedefs
typedef struct {
	ngx_str_t key;
	ngx_str_t iv;
        ngx_http_complex_value_t *acl;
	ngx_secure_token_time_t end;
} ngx_secure_token_iijpta_token_t;

typedef struct {
        u_char crc[CRC32_SIZE];
        u_char expiry[EXPIRY_SIZE];
} ngx_http_secure_token_iijpta_header_t;

static ngx_conf_num_bounds_t ngx_http_secure_token_iijpta_key_bounds = {
	ngx_conf_check_str_len_bounds, 16, 16
};

static ngx_conf_num_bounds_t ngx_http_secure_token_iijpta_iv_bounds = {
	ngx_conf_check_str_len_bounds, 16, 16
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

	{ ngx_string("acl"),
	NGX_CONF_TAKE1,
        ngx_http_set_complex_value_slot,
	0,
	offsetof(ngx_secure_token_iijpta_token_t, acl),
	NULL },

	{ ngx_string("end"),
	NGX_CONF_TAKE1,
        ngx_http_secure_token_conf_set_time_slot,
	0,
	offsetof(ngx_secure_token_iijpta_token_t, end),
	NULL },
};

static ngx_int_t
ngx_secure_token_iijpta_get_var(
	ngx_http_request_t *r,
	ngx_http_variable_value_t *v,
	uintptr_t data)
{
	EVP_CIPHER_CTX *ctx;
	uint32_t crc;
	ngx_secure_token_iijpta_token_t* token = (void*)data;
	ngx_http_secure_token_iijpta_header_t hdr;
	size_t in_len;
	u_char *p;
	u_char *out;
	int out_len;
	u_char *outp;
	uint64_t end;
	ngx_str_t acl;
	ngx_int_t rc;

	rc = ngx_http_secure_token_get_acl_iijpta(r, token->acl, &acl);
	if (rc != NGX_OK)
	{
	    return rc;
	}

	if (acl.len > PATH_LIMIT)
	{
	    ngx_log_error(NGX_LOG_ERR, r->connection->log, 0,
			  "ngx_secure_token_iijpta_get_var: acl is too long for the iijpta token");
	    goto error;
	}

	if (token->end.type == NGX_HTTP_SECURE_TOKEN_TIME_RELATIVE)
	{
	    end = htobe64(ngx_time() + token->end.val);
	}
	if (token->end.type == NGX_HTTP_SECURE_TOKEN_TIME_ABSOLUTE)
	{
	    end = htobe64(token->end.val);
	}

	memcpy(&hdr.expiry, &end, sizeof(end));
	ngx_crc32_init(crc);
        ngx_crc32_update(&crc, (u_char *)&end, sizeof(end));
        ngx_crc32_update(&crc, acl.data, acl.len);
        ngx_crc32_final(crc);
	crc = htobe32(crc);
	memcpy(&hdr.crc, &crc, sizeof(crc));

	ctx = EVP_CIPHER_CTX_new();
	if (ctx == NULL)
	{
	    ngx_log_error(NGX_LOG_ERR, r->connection->log, 0,
			  "ngx_secure_token_iijpta_get_var: EVP_CIPHER_CTX_new failed");
	    return NGX_ERROR;
	}

	if (!EVP_EncryptInit(ctx, EVP_aes_128_cbc(), token->key.data, token->iv.data))
	{
	    ngx_log_error(NGX_LOG_ERR, r->connection->log, 0,
			  "ngx_secure_token_iijpta_get_var: EVP_EncryptInit failed");
	    goto error;
	}

	in_len = sizeof(ngx_http_secure_token_iijpta_header_t) + acl.len;
	// in_len rounded up to block + one block for padding
	out = ngx_pnalloc(r->pool,
			  (((in_len + 15) / 16) * 16) + ((in_len % 16 == 0) ? 16 : 0));
	if (out == NULL) {
	    return NGX_ERROR;
	}

	outp = out;
        if (!EVP_EncryptUpdate(ctx, outp, &out_len, (void *)&hdr, sizeof(hdr)))
	{
	    ngx_log_error(NGX_LOG_ERR, r->connection->log, 0,
			  "ngx_secure_token_iijpta_get_var: EVP_EncryptUpdate failed (1)");
	    goto error;
	}
	outp += out_len;

	if (!EVP_EncryptUpdate(ctx, outp, &out_len, acl.data, acl.len))
	{
	    ngx_log_error(NGX_LOG_ERR, r->connection->log, 0,
			  "ngx_secure_token_iijpta_get_var: EVP_EncryptUpdate failed (2)");
	    goto error;
	}
	outp += out_len;

	if (!EVP_EncryptFinal(ctx, outp, &out_len))
	{
	    ngx_log_error(NGX_LOG_ERR, r->connection->log, 0,
			  "ngx_secure_token_iijpta_get_var: EVP_EncryptFinal failed");
	    goto error;
	}
	outp += out_len;

	out_len = outp - out;
	/* sizeof("pta=") returns 5, includes null termination. */
	p = ngx_pnalloc(r->pool, sizeof("pta=") + (out_len * 2));
	if (p == NULL)
	{
	    goto error;
	}

	v->data = p;
	p = ngx_copy(p, "pta=", sizeof("pta=") - 1);
	p = ngx_hex_dump(p, out, out_len);
	*p = '\0';

	v->len = p - v->data;
	v->valid = 1;
	v->no_cacheable = 0;
	v->not_found = 0;

	EVP_CIPHER_CTX_free(ctx);

	return NGX_OK;

error:
	EVP_CIPHER_CTX_free(ctx);
	return NGX_ERROR;
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

	token->end.type = NGX_HTTP_SECURE_TOKEN_TIME_UNSET;

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

	if (token->end.type == NGX_HTTP_SECURE_TOKEN_TIME_UNSET)
	{
		token->end.type = NGX_HTTP_SECURE_TOKEN_TIME_RELATIVE;
		token->end.val  = 86400;
	}

	return NGX_CONF_OK;
}
