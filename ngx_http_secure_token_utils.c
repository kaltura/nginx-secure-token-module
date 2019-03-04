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
	ngx_conf_post_t *post;
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

	if (cmd->post) {
		post = cmd->post;
		return post->post_handler(cf, post, field);
	}

	return NGX_CONF_OK;
}

char *
ngx_http_secure_token_conf_set_time_slot(ngx_conf_t *cf, ngx_command_t *cmd, void *conf)
{
	ngx_secure_token_time_t* result;
	ngx_conf_post_t *post;
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
		goto done;
	}

	if (value->len == 3 && ngx_strncmp(value->data, "max", 3) == 0)
	{
		result->type = NGX_HTTP_SECURE_TOKEN_TIME_ABSOLUTE;
		result->val = INT_MAX;
		goto done;
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

done:

	if (cmd->post) {
		post = cmd->post;
		return post->post_handler(cf, post, result);
	}

	return NGX_CONF_OK;
}

char *
ngx_http_secure_token_conf_set_private_key_slot(ngx_conf_t *cf, ngx_command_t *cmd, void *conf)
{
	ngx_pool_cleanup_t* cln;
	ngx_conf_post_t *post;
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

	if (cmd->post) {
		post = cmd->post;
		return post->post_handler(cf, post, *result);
	}

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
#if (OPENSSL_VERSION_NUMBER < 0x10100000L)
	EVP_MD_CTX md_ctx_buf;
#endif
	EVP_MD_CTX* md_ctx;
	unsigned int siglen;

	signature->data = ngx_pnalloc(r->pool, EVP_PKEY_size(private_key) + 1);
	if (signature->data == NULL)
	{
		return NGX_ERROR;
	}

#if (OPENSSL_VERSION_NUMBER >= 0x10100000L)
	md_ctx = EVP_MD_CTX_new();
	if (md_ctx == NULL)
	{
		return NGX_ERROR;
	}
#else
	md_ctx = &md_ctx_buf;
	EVP_MD_CTX_init(md_ctx);
#endif

	if (!EVP_SignInit_ex(md_ctx, EVP_sha1(), NULL))
	{
		goto error;
	}

	if (!EVP_SignUpdate(md_ctx, message->data, message->len))
	{
		goto error;
	}

	if (!EVP_SignFinal(md_ctx, signature->data, &siglen, private_key))
	{
		goto error;
	}

#if (OPENSSL_VERSION_NUMBER >= 0x10100000L)
	EVP_MD_CTX_free(md_ctx);
#else
	EVP_MD_CTX_cleanup(md_ctx);
#endif

	signature->len = siglen;
	return NGX_OK;

error:

#if (OPENSSL_VERSION_NUMBER >= 0x10100000L)
	EVP_MD_CTX_free(md_ctx);
#else
	EVP_MD_CTX_cleanup(md_ctx);
#endif
	return NGX_ERROR;
}

// code copied from ngx_escape_html, added apos
static uintptr_t
ngx_escape_xml(u_char *dst, u_char *src, size_t size)
{
    u_char      ch;
    ngx_uint_t  len;

    if (dst == NULL) {

        len = 0;

        while (size) {
            switch (*src++) {

            case '<':
                len += sizeof("&lt;") - 2;
                break;

            case '>':
                len += sizeof("&gt;") - 2;
                break;

            case '&':
                len += sizeof("&amp;") - 2;
                break;

            case '"':
                len += sizeof("&quot;") - 2;
                break;

            case '\'':
                len += sizeof("&apos;") - 2;
                break;

            default:
                break;
            }
            size--;
        }

        return (uintptr_t) len;
    }

    while (size) {
        ch = *src++;

        switch (ch) {

        case '<':
            *dst++ = '&'; *dst++ = 'l'; *dst++ = 't'; *dst++ = ';';
            break;

        case '>':
            *dst++ = '&'; *dst++ = 'g'; *dst++ = 't'; *dst++ = ';';
            break;

        case '&':
            *dst++ = '&'; *dst++ = 'a'; *dst++ = 'm'; *dst++ = 'p';
            *dst++ = ';';
            break;

        case '"':
            *dst++ = '&'; *dst++ = 'q'; *dst++ = 'u'; *dst++ = 'o';
            *dst++ = 't'; *dst++ = ';';
            break;

        case '\'':
            *dst++ = '&'; *dst++ = 'a'; *dst++ = 'p'; *dst++ = 'o';
            *dst++ = 's'; *dst++ = ';';
            break;

        default:
            *dst++ = ch;
            break;
        }
        size--;
    }

    return (uintptr_t) dst;
}

ngx_int_t
ngx_http_secure_token_escape_xml(
	ngx_pool_t* pool,
	ngx_str_t* src,
	ngx_str_t* dst)
{
	uintptr_t escape_xml;

	escape_xml = ngx_escape_xml(NULL, src->data, src->len);
	if (escape_xml == 0)
	{
		*dst = *src;
		return NGX_OK;
	}

	dst->len = src->len + escape_xml;
	dst->data = ngx_pnalloc(pool, dst->len + 1);
	if (dst->data == NULL)
	{
		return NGX_ERROR;
	}

	ngx_escape_xml(dst->data, src->data, src->len);
	dst->data[dst->len] = '\0';

	return NGX_OK;
}

// Note: copy of ngx_conf_check_num_bounds adjusted for string length validation
char *
ngx_conf_check_str_len_bounds(ngx_conf_t *cf, void *post, void *data)
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
		"value must be between %i and %i",
		bounds->low, bounds->high);

	return NGX_CONF_ERROR;
}
