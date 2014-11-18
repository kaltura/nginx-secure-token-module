#include <ngx_config.h>
#include <ngx_core.h>
#include <ngx_http.h>

#include <openssl/hmac.h>
#include <openssl/evp.h>

#define TOKEN_FORMAT "st=%uD~exp=%uD~acl=%V*"
#define HMAC_PARAM "~hmac="

static char *ngx_conf_set_hex_str_slot(ngx_conf_t *cf, ngx_command_t *cmd, void *conf);
static void *ngx_http_akamai_token_create_loc_conf(ngx_conf_t *cf);
static char *ngx_http_akamai_token_merge_loc_conf(ngx_conf_t *cf, void *parent, void *child);

ngx_str_t  ngx_http_akamai_token_default_types[] = {
    ngx_null_string
};

typedef struct {
    ngx_flag_t  enable;
	ngx_str_t 	param_name;
	ngx_str_t 	key;
	ngx_uint_t  window;
	ngx_array_t* filename_prefixes;
	time_t 		expires_time;
	time_t 		tokenized_expires_time;
    ngx_hash_t  types;
    ngx_array_t *types_keys;
} ngx_http_akamai_token_loc_conf_t;

static ngx_command_t  ngx_http_akamai_token_commands[] = {
    { ngx_string("akamai_token"),
    NGX_HTTP_MAIN_CONF|NGX_HTTP_SRV_CONF|NGX_HTTP_LOC_CONF|NGX_CONF_FLAG,
    ngx_conf_set_flag_slot,
    NGX_HTTP_LOC_CONF_OFFSET,
    offsetof(ngx_http_akamai_token_loc_conf_t, enable),
    NULL },

	{ ngx_string("akamai_token_key"),
	NGX_HTTP_MAIN_CONF|NGX_HTTP_SRV_CONF|NGX_HTTP_LOC_CONF|NGX_CONF_TAKE1,
	ngx_conf_set_hex_str_slot,
	NGX_HTTP_LOC_CONF_OFFSET,
	offsetof(ngx_http_akamai_token_loc_conf_t, key),
	NULL },

	{ ngx_string("akamai_token_window"),
	NGX_HTTP_MAIN_CONF|NGX_HTTP_SRV_CONF|NGX_HTTP_LOC_CONF|NGX_CONF_TAKE1,
	ngx_conf_set_num_slot,
	NGX_HTTP_LOC_CONF_OFFSET,
	offsetof(ngx_http_akamai_token_loc_conf_t, window),
	NULL },

	{ ngx_string("akamai_token_param_name"),
	NGX_HTTP_MAIN_CONF|NGX_HTTP_SRV_CONF|NGX_HTTP_LOC_CONF|NGX_CONF_TAKE1,
	ngx_conf_set_str_slot,
	NGX_HTTP_LOC_CONF_OFFSET,
	offsetof(ngx_http_akamai_token_loc_conf_t, param_name),
	NULL },
	
	{ ngx_string("akamai_token_uri_filename_prefix"),
    NGX_HTTP_MAIN_CONF|NGX_HTTP_SRV_CONF|NGX_HTTP_LOC_CONF|NGX_CONF_TAKE1,
    ngx_conf_set_str_array_slot,
    NGX_HTTP_LOC_CONF_OFFSET,
    offsetof(ngx_http_akamai_token_loc_conf_t, filename_prefixes),
    NULL },

    { ngx_string("akamai_token_expires_time"),
    NGX_HTTP_MAIN_CONF|NGX_HTTP_SRV_CONF|NGX_HTTP_LOC_CONF|NGX_CONF_TAKE1,
    ngx_conf_set_sec_slot,
    NGX_HTTP_LOC_CONF_OFFSET,
    offsetof(ngx_http_akamai_token_loc_conf_t, expires_time),
    NULL },

    { ngx_string("akamai_token_tokenized_expires_time"),
    NGX_HTTP_MAIN_CONF|NGX_HTTP_SRV_CONF|NGX_HTTP_LOC_CONF|NGX_CONF_TAKE1,
    ngx_conf_set_sec_slot,
    NGX_HTTP_LOC_CONF_OFFSET,
    offsetof(ngx_http_akamai_token_loc_conf_t, tokenized_expires_time),
    NULL },

    { ngx_string("akamai_token_types"),
    NGX_HTTP_MAIN_CONF|NGX_HTTP_SRV_CONF|NGX_HTTP_LOC_CONF|NGX_CONF_1MORE,
    ngx_http_types_slot,
    NGX_HTTP_LOC_CONF_OFFSET,
    offsetof(ngx_http_akamai_token_loc_conf_t, types_keys),
    NULL },
	
    ngx_null_command
};
	  
static ngx_int_t ngx_http_akamai_token_filter_init(ngx_conf_t *cf);

static ngx_http_module_t  ngx_http_akamai_token_filter_module_ctx = {
    NULL,                                  /* preconfiguration */
    ngx_http_akamai_token_filter_init,     /* postconfiguration */

    NULL,                                  /* create main configuration */
    NULL,                                  /* init main configuration */

    NULL,                                  /* create server configuration */
    NULL,                                  /* merge server configuration */

    ngx_http_akamai_token_create_loc_conf, /* create location configuration */
    ngx_http_akamai_token_merge_loc_conf   /* merge location configuration */
};

ngx_module_t  ngx_http_akamai_token_filter_module = {
    NGX_MODULE_V1,
    &ngx_http_akamai_token_filter_module_ctx, /* module context */
    ngx_http_akamai_token_commands,        /* module directives */
    NGX_HTTP_MODULE,                       /* module type */
    NULL,                                  /* init master */
    NULL,                                  /* init module */
    NULL,                                  /* init process */
    NULL,                                  /* init thread */
    NULL,                                  /* exit thread */
    NULL,                                  /* exit process */
    NULL,                                  /* exit master */
    NGX_MODULE_V1_PADDING
};

static ngx_http_output_header_filter_pt  ngx_http_next_header_filter;

static int 
ngx_conf_get_hex_char_value(int ch)
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

static char *
ngx_conf_set_hex_str_slot(ngx_conf_t *cf, ngx_command_t *cmd, void *conf)
{
    ngx_str_t *field;
	ngx_str_t *value;
    u_char *p;
	size_t i;
	int digit1;
	int digit2;

    field = (ngx_str_t *) ((u_char*)conf + cmd->offset);

    if (field->data) {
        return "is duplicate";
    }

    value = cf->args->elts;

	if (value[1].len & 0x1) {
		return "length is odd";
	}
	
	field->data = ngx_palloc(cf->pool, value[1].len >> 1);
	if (field->data == NULL) {
		return "alloc failed";
	}
	p = field->data;
	
	for (i = 0; i < value[1].len; i += 2)
	{
		digit1 = ngx_conf_get_hex_char_value(value[1].data[i]);
		digit2 = ngx_conf_get_hex_char_value(value[1].data[i + 1]);
		if (digit1 < 0 || digit2 < 0) {
			return "contains non hex chars";
		}
		*p++ = (digit1 << 4) | digit2;
	}
	field->len = p - field->data;

    return NGX_CONF_OK;
}

static void *
ngx_http_akamai_token_create_loc_conf(ngx_conf_t *cf)
{
    ngx_http_akamai_token_loc_conf_t  *conf;

    conf = ngx_pcalloc(cf->pool, sizeof(ngx_http_akamai_token_loc_conf_t));
    if (conf == NULL) {
        return NGX_CONF_ERROR;
    }
    conf->enable = NGX_CONF_UNSET;
    conf->window = NGX_CONF_UNSET_UINT;
    conf->filename_prefixes = NGX_CONF_UNSET_PTR;
	conf->expires_time = NGX_CONF_UNSET;
	conf->tokenized_expires_time = NGX_CONF_UNSET;
    return conf;
}

static char *
ngx_http_akamai_token_merge_loc_conf(ngx_conf_t *cf, void *parent, void *child)
{
    ngx_http_akamai_token_loc_conf_t  *prev = parent;
    ngx_http_akamai_token_loc_conf_t  *conf = child;

    ngx_conf_merge_value(conf->enable, prev->enable, 0);
	ngx_conf_merge_uint_value(conf->window, prev->window, 86400);
	ngx_conf_merge_str_value(conf->param_name, prev->param_name, "__hdnea__");
	ngx_conf_merge_str_value(conf->key, prev->key, "");
    ngx_conf_merge_ptr_value(conf->filename_prefixes, prev->filename_prefixes, NULL);
    ngx_conf_merge_sec_value(conf->expires_time, prev->expires_time, NGX_CONF_UNSET);
    ngx_conf_merge_sec_value(conf->tokenized_expires_time, prev->tokenized_expires_time, NGX_CONF_UNSET);

    if (ngx_http_merge_types(cf, &conf->types_keys, &conf->types,
                             &prev->types_keys, &prev->types,
                             ngx_http_akamai_token_default_types)
        != NGX_OK)
    {
        return NGX_CONF_ERROR;
    }
	
    return NGX_CONF_OK;
}

static ngx_int_t
ngx_http_akamai_token_build_cookie(ngx_http_request_t* r, ngx_http_akamai_token_loc_conf_t  *conf, ngx_str_t* acl, ngx_str_t* result)
{
	time_t current_time = ngx_time();
    u_char hash[EVP_MAX_MD_SIZE];
	unsigned hash_len;
    HMAC_CTX hmac;
	ngx_str_t signed_part;
	size_t result_size;
	u_char* p;
	
	result_size = conf->param_name.len + 1 + sizeof(TOKEN_FORMAT) + 2 * NGX_INT32_LEN + acl->len + sizeof(HMAC_PARAM) - 1 + EVP_MAX_MD_SIZE * 2 + 1;
	
	result->data = ngx_palloc(r->pool, result_size);
	if (result->data == NULL)
	{
		return NGX_ERROR;
	}
	
	p = ngx_copy(result->data, conf->param_name.data, conf->param_name.len);
	*p++ = '=';
	
	signed_part.data = p;
	p = ngx_sprintf(p, TOKEN_FORMAT, current_time, current_time + conf->window, acl);
	signed_part.len = p - signed_part.data;
	
    HMAC_Init(&hmac, conf->key.data, conf->key.len, EVP_sha256());
    HMAC_Update(&hmac, signed_part.data, signed_part.len);
    HMAC_Final(&hmac, hash, &hash_len);

	p = ngx_copy(p, HMAC_PARAM, sizeof(HMAC_PARAM) - 1);
	p = ngx_hex_dump(p, hash, hash_len);
	*p = '\0';
	
	result->len = p - result->data;
	return NGX_OK;
}

// a run down version of ngx_http_set_expires with a few changes
// (can't use the existing code since the function is static)
static ngx_int_t
ngx_http_akamai_token_set_expires(ngx_http_request_t *r, time_t expires_time)
{
    size_t            len;
    time_t            max_age;
    ngx_uint_t        i;
    ngx_table_elt_t  *expires, *cc, **ccp;

    expires = r->headers_out.expires;

    if (expires == NULL) {

        expires = ngx_list_push(&r->headers_out.headers);
        if (expires == NULL) {
            return NGX_ERROR;
        }

        r->headers_out.expires = expires;

        expires->hash = 1;
        ngx_str_set(&expires->key, "Expires");
    }

    ccp = r->headers_out.cache_control.elts;

    if (ccp == NULL) {

        if (ngx_array_init(&r->headers_out.cache_control, r->pool,
                           1, sizeof(ngx_table_elt_t *))
            != NGX_OK)
        {
            return NGX_ERROR;
        }

        ccp = ngx_array_push(&r->headers_out.cache_control);
        if (ccp == NULL) {
            return NGX_ERROR;
        }

        cc = ngx_list_push(&r->headers_out.headers);
        if (cc == NULL) {
            return NGX_ERROR;
        }

        cc->hash = 1;
        ngx_str_set(&cc->key, "Cache-Control");
        *ccp = cc;

    } else {
        for (i = 1; i < r->headers_out.cache_control.nelts; i++) {
            ccp[i]->hash = 0;
        }

        cc = ccp[0];
    }
	
    if (expires_time == 0) {
		ngx_str_set(&expires->value, "Sun, 19 Nov 2000 08:52:00 GMT");
        ngx_str_set(&cc->value, "no-store, no-cache, must-revalidate, post-check=0, pre-check=0");
        return NGX_OK;
    }

    len = sizeof("Mon, 28 Sep 1970 06:00:00 GMT");
    expires->value.len = len - 1;

    expires->value.data = ngx_pnalloc(r->pool, len);
    if (expires->value.data == NULL) {
        return NGX_ERROR;
    }

	max_age = expires_time;
	expires_time += ngx_time();

    ngx_http_time(expires->value.data, expires_time);

    cc->value.data = ngx_pnalloc(r->pool,
                                 sizeof("max-age=") + NGX_TIME_T_LEN + 1);
    if (cc->value.data == NULL) {
        return NGX_ERROR;
    }

    cc->value.len = ngx_sprintf(cc->value.data, "max-age=%T", max_age)
                    - cc->value.data;

    return NGX_OK;
}

static ngx_int_t
ngx_http_akamai_token_call_next_filter(ngx_http_request_t *r, time_t expires)
{
	ngx_int_t rc;

	if (expires != NGX_CONF_UNSET)
	{
		rc = ngx_http_akamai_token_set_expires(r, expires);
		if (rc != NGX_OK)
		{
			return rc;
		}
	}

	return ngx_http_next_header_filter(r);
}

static ngx_int_t
ngx_http_akamai_token_header_filter(ngx_http_request_t *r)
{
    ngx_http_akamai_token_loc_conf_t  *conf;
	ngx_table_elt_t  *set_cookie;
	ngx_flag_t prefix_matched;
	ngx_uint_t i;
	ngx_str_t* cur_prefix;
	ngx_str_t cookie_value;
	ngx_str_t uri_filename;
	ngx_str_t acl;
	ngx_int_t rc;
	u_char* last_slash_pos;
	u_char* acl_end_pos;
	u_char* comma_pos;

    conf = ngx_http_get_module_loc_conf(r, ngx_http_akamai_token_filter_module);
	
	// decide whether the token should be added
    if (!conf->enable || 
		r->headers_out.status != NGX_HTTP_OK ||
		r != r->main)
	{
		return ngx_http_next_header_filter(r);
	}
	
	if (ngx_http_test_content_type(r, &conf->types) == NULL)
    {
        return ngx_http_akamai_token_call_next_filter(r, conf->expires_time);
    }

	// check the file name
	last_slash_pos = memrchr(r->uri.data, '/', r->uri.len);
	if (last_slash_pos == NULL) 
	{
		return NGX_ERROR;
	}

	if (conf->filename_prefixes != NULL)
	{
		uri_filename.data = last_slash_pos + 1;
		uri_filename.len = r->uri.data + r->uri.len - uri_filename.data;

		prefix_matched = 0;
		for (i = 0; i < conf->filename_prefixes->nelts; i++)
		{
			cur_prefix = &((ngx_str_t*)conf->filename_prefixes->elts)[i];
			if (uri_filename.len >= cur_prefix->len &&
				ngx_memcmp(uri_filename.data, cur_prefix->data, cur_prefix->len) == 0)
			{
				prefix_matched = 1;
				break;
			}
		}

		if (!prefix_matched)
		{
			return ngx_http_akamai_token_call_next_filter(r, conf->expires_time);
		}
	}

	// get the acl
	acl_end_pos = last_slash_pos + 1;
	
	comma_pos = memchr(r->uri.data, ',', r->uri.len);
	if (comma_pos != NULL)
	{
		acl_end_pos = ngx_min(acl_end_pos, comma_pos);
	}
	acl.data = r->uri.data;
	acl.len = acl_end_pos - r->uri.data;

	// build the cookie
	rc = ngx_http_akamai_token_build_cookie(r, conf, &acl, &cookie_value);
	if (rc != NGX_OK)
	{
		return rc;
	}
	
	// add the cookie to the response headers
    set_cookie = ngx_list_push(&r->headers_out.headers);
    if (set_cookie == NULL) {
        return NGX_ERROR;
    }

    set_cookie->hash = 1;
    ngx_str_set(&set_cookie->key, "Set-Cookie");
	set_cookie->value = cookie_value;
	
    return ngx_http_akamai_token_call_next_filter(r, conf->tokenized_expires_time);
}

static ngx_int_t
ngx_http_akamai_token_filter_init(ngx_conf_t *cf)
{
    ngx_http_next_header_filter = ngx_http_top_header_filter;
    ngx_http_top_header_filter = ngx_http_akamai_token_header_filter;

    return NGX_OK;
}
