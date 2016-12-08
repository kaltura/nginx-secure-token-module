#include "ngx_http_secure_token_utils.h"
#include <openssl/pem.h>

// typedefs
typedef struct {
	ngx_conf_t *cf;
	ngx_command_t *cmds;
} ngx_secure_token_conf_ctx_t;

// constants
static ngx_uint_t argument_number[] = {
	NGX_CONF_NOARGS,
	NGX_CONF_TAKE1,
	NGX_CONF_TAKE2,
	NGX_CONF_TAKE3,
	NGX_CONF_TAKE4,
	NGX_CONF_TAKE5,
	NGX_CONF_TAKE6,
	NGX_CONF_TAKE7
};

static int
ngx_http_secure_token_get_hex_char_value(int ch)
{
	if (ch >= '0' && ch <= '9') {
		return (ch - '0');
	}

	ch = (ch | 0x20);		// lower case

	if (ch >= 'a' && ch <= 'f') {
		return (ch - 'a' + 10);
	}

	return -1;
}

static ngx_int_t
ngx_http_secure_token_decode_hex(ngx_pool_t* pool, ngx_str_t* src, ngx_str_t* dest)
{
	u_char* cur_pos;
	u_char* end_pos;
	u_char* p;
	int digit1;
	int digit2;

	if (src->len & 0x1) 
	{
		return NGX_ERROR;
	}

	dest->data = ngx_palloc(pool, src->len >> 1);
	if (dest->data == NULL) 
	{
		return NGX_ERROR;
	}
	p = dest->data;

	end_pos = src->data + src->len;
	for (cur_pos = src->data; cur_pos < end_pos; cur_pos += 2)
	{
		digit1 = ngx_http_secure_token_get_hex_char_value(cur_pos[0]);
		digit2 = ngx_http_secure_token_get_hex_char_value(cur_pos[1]);
		if (digit1 < 0 || digit2 < 0) 
		{
			return NGX_ERROR;
		}

		*p++ = (digit1 << 4) | digit2;
	}
	dest->len = p - dest->data;

	return NGX_OK;
}

char *
ngx_http_secure_token_conf_set_hex_str_slot(ngx_conf_t *cf, ngx_command_t *cmd, void *conf)
{
	ngx_str_t *field;
	ngx_str_t *value;
	ngx_int_t rc;

	field = (ngx_str_t *)((u_char*)conf + cmd->offset);

	if (field->data)
	{
		return "is duplicate";
	}

	value = cf->args->elts;

	rc = ngx_http_secure_token_decode_hex(
		cf->pool,
		&value[1],
		field);
	if (rc != NGX_OK)
	{
		return "invalid hex string";
	}

	return NGX_CONF_OK;
}

char *
ngx_http_secure_token_conf_set_time_slot(ngx_conf_t *cf, ngx_command_t *cmd, void *conf)
{
	ngx_secure_token_time_t* result;
	ngx_uint_t minus;
	ngx_str_t *value;

	result = (void *)((u_char*)conf + cmd->offset);

	if (result->type != NGX_HTTP_SECURE_TOKEN_TIME_UNSET)
	{
		return "is duplicate";
	}

	value = &((ngx_str_t*)cf->args->elts)[1];

	if (value->len <= 0)
	{
		return "is empty";
	}

	if (value->len == 5 && ngx_strncmp(value->data, "epoch", 5) == 0)
	{
		result->type = NGX_HTTP_SECURE_TOKEN_TIME_ABSOLUTE;
		result->val = 0;
		return NGX_OK;
	}

	if (value->len == 3 && ngx_strncmp(value->data, "max", 3) == 0)
	{
		result->type = NGX_HTTP_SECURE_TOKEN_TIME_ABSOLUTE;
		result->val = INT_MAX;
		return NGX_OK;
	}

	switch (value->data[0])
	{
	case '@':
		value->data++;
		value->len--;
		minus = 0;
		result->type = NGX_HTTP_SECURE_TOKEN_TIME_ABSOLUTE;
		break;

	case '-':
		value->data++;
		value->len--;
		minus = 1;
		result->type = NGX_HTTP_SECURE_TOKEN_TIME_RELATIVE;
		break;

	case '+':
		value->data++;
		value->len--;
		// fallthrough

	default:
		minus = 0;
		result->type = NGX_HTTP_SECURE_TOKEN_TIME_RELATIVE;
		break;
	}

	result->val = ngx_parse_time(value, 1);

	if (result->val == (time_t)NGX_ERROR)
	{
		return "invalid value";
	}

	if (minus)
	{
		result->val = -result->val;
	}

	return NGX_CONF_OK;
}

char *
ngx_http_secure_token_conf_set_private_key_slot(ngx_conf_t *cf, ngx_command_t *cmd, void *conf)
{
	ngx_pool_cleanup_t* cln;
	ngx_str_t *value;
	EVP_PKEY** result;
	BIO *in;

	result = (void *)((u_char*)conf + cmd->offset);

	if (*result != NULL)
	{
		return "is duplicate";
	}

	value = cf->args->elts;

	cln = ngx_pool_cleanup_add(cf->pool, 0);
	if (cln == NULL)
	{
		return NGX_CONF_ERROR;
	}

	in = BIO_new_file((char *)value[1].data, "r");
	if (in == NULL)
	{
		return "cannot be opened";
	}

	*result = PEM_read_bio_PrivateKey(in, NULL, NULL, NULL);

	BIO_free(in);

	if (*result == NULL)
	{
		return "cannot be loaded";
	}

	cln->handler = (ngx_pool_cleanup_pt)EVP_PKEY_free;
	cln->data = *result;

	return NGX_CONF_OK;
}

// copied from ngx_conf_handler, removed support for modules
static char *
ngx_http_secure_token_command_handler(ngx_conf_t *cf, ngx_command_t *dummy, void *conf)
{
	ngx_secure_token_conf_ctx_t* ctx;
	ngx_command_t *cmd;
	ngx_str_t *name;
	char *rv;

	ctx = cf->ctx;
	cmd = ctx->cmds;

	name = cf->args->elts;

	for ( /* void */; cmd->name.len; cmd++) {

		if (name->len != cmd->name.len) {
			continue;
		}

		if (ngx_strcmp(name->data, cmd->name.data) != 0) {
			continue;
		}

		/* is the directive's argument count right ? */

		if (!(cmd->type & NGX_CONF_ANY)) {

			if (cmd->type & NGX_CONF_FLAG) {

				if (cf->args->nelts != 2) {
					goto invalid;
				}

			}
			else if (cmd->type & NGX_CONF_1MORE) {

				if (cf->args->nelts < 2) {
					goto invalid;
				}

			}
			else if (cmd->type & NGX_CONF_2MORE) {

				if (cf->args->nelts < 3) {
					goto invalid;
				}

			}
			else if (cf->args->nelts > NGX_CONF_MAX_ARGS) {

				goto invalid;

			}
			else if (!(cmd->type & argument_number[cf->args->nelts - 1]))
			{
				goto invalid;
			}
		}

		rv = cmd->set(ctx->cf, cmd, conf);

		if (rv == NGX_CONF_OK) {
			return NGX_CONF_OK;
		}

		if (rv == NGX_CONF_ERROR) {
			return NGX_CONF_ERROR;
		}

		ngx_conf_log_error(NGX_LOG_EMERG, cf, 0,
			"\"%s\" directive %s", name->data, rv);

		return NGX_CONF_ERROR;
	}

	ngx_conf_log_error(NGX_LOG_EMERG, cf, 0,
		"unknown directive \"%s\"", name->data);

	return NGX_CONF_ERROR;

invalid:

	ngx_conf_log_error(NGX_LOG_EMERG, cf, 0,
		"invalid number of arguments in \"%s\" directive",
		name->data);

	return NGX_CONF_ERROR;
}

char *
ngx_http_secure_token_conf_block(
	ngx_conf_t *cf, 
	ngx_command_t *cmds, 
	void *conf,
	ngx_http_get_variable_pt get_handler)
{
	ngx_secure_token_conf_ctx_t ctx;
	ngx_http_variable_t *var;
	ngx_conf_t save;
	ngx_str_t *value;
	ngx_str_t name;
	char *rv;

	value = cf->args->elts;

	name = value[1];

	if (name.data[0] != '$')
	{
		ngx_conf_log_error(NGX_LOG_EMERG, cf, 0,
			"invalid variable name \"%V\"", &name);
		return NGX_CONF_ERROR;
	}

	name.len--;
	name.data++;

	var = ngx_http_add_variable(cf, &name, NGX_HTTP_VAR_CHANGEABLE);
	if (var == NULL)
	{
		return NGX_CONF_ERROR;
	}

	var->get_handler = get_handler;
	var->data = (uintptr_t)conf;

	ctx.cmds = cmds;
	ctx.cf = &save;

	save = *cf;
	cf->ctx = &ctx;
	cf->handler = ngx_http_secure_token_command_handler;
	cf->handler_conf = conf;

	rv = ngx_conf_parse(cf, NULL);

	*cf = save;

	return rv;
}

// copied from ngx_string, changed the interface:
//	1. get a u_char* dest pointer and return the write end position
//	2. get the padding char as param

u_char*
ngx_http_secure_token_encode_base64_internal(
	u_char *d, 
	ngx_str_t *src, 
	const u_char *basis, 
	u_char padding)
{
    u_char         *s;
    size_t          len;

    len = src->len;
    s = src->data;

    while (len > 2) {
        *d++ = basis[(s[0] >> 2) & 0x3f];
        *d++ = basis[((s[0] & 3) << 4) | (s[1] >> 4)];
        *d++ = basis[((s[1] & 0x0f) << 2) | (s[2] >> 6)];
        *d++ = basis[s[2] & 0x3f];

        s += 3;
        len -= 3;
    }

    if (len) {
        *d++ = basis[(s[0] >> 2) & 0x3f];

        if (len == 1) {
            *d++ = basis[(s[0] & 3) << 4];
            if (padding) {
                *d++ = padding;
            }

        } else {
            *d++ = basis[((s[0] & 3) << 4) | (s[1] >> 4)];
            *d++ = basis[(s[1] & 0x0f) << 2];
        }

        if (padding) {
            *d++ = padding;
        }
    }

    return d;
}

ngx_int_t
ngx_http_secure_token_sign(
	ngx_http_request_t* r, 
	EVP_PKEY* private_key, 
	ngx_str_t* message, 
	ngx_str_t* signature)
{
	EVP_MD_CTX md_ctx;
	unsigned int siglen;

	signature->data = ngx_pnalloc(r->pool, EVP_PKEY_size(private_key) + 1);
	if (signature->data == NULL)
	{
		return NGX_ERROR;
	}

	EVP_MD_CTX_init(&md_ctx);

	if (!EVP_SignInit_ex(&md_ctx, EVP_sha1(), NULL))
	{
		goto error;
	}

	if (!EVP_SignUpdate(&md_ctx, message->data, message->len))
	{
		goto error;
	}

	if (!EVP_SignFinal(&md_ctx, signature->data, &siglen, private_key))
	{
		goto error;
	}

	EVP_MD_CTX_cleanup(&md_ctx);

	signature->len = siglen;
	return NGX_OK;

error:

	EVP_MD_CTX_cleanup(&md_ctx);
	return NGX_ERROR;
}
