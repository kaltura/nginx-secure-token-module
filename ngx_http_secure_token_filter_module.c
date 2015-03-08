#include <ngx_config.h>
#include <ngx_core.h>
#include <ngx_http.h>
#include <ctype.h>

#include "ngx_http_secure_token_filter_module.h"
#include "ngx_http_secure_token_cloudfront.h"
#include "ngx_http_secure_token_akamai.h"
#include "ngx_http_secure_token_conf.h"
#include "ngx_http_secure_token_m3u8.h"
#include "ngx_http_secure_token_mpd.h"

#define CACHE_CONTROL_FORMAT "%V, max-age=%T, max-stale=0"

static char *ngx_conf_set_hex_str_slot(ngx_conf_t *cf, ngx_command_t *cmd, void *conf);
static char *ngx_http_secure_token_command(ngx_conf_t *cf, ngx_command_t *cmd, void *conf);
static void *ngx_http_secure_token_create_loc_conf(ngx_conf_t *cf);
static char *ngx_http_secure_token_merge_loc_conf(ngx_conf_t *cf, void *parent, void *child);

enum {
	TOKEN_PREFIX_NONE,
	TOKEN_PREFIX_QUESTION,
	TOKEN_PREFIX_AMPERSAND,

	TOKEN_PREFIX_COUNT
};

static ngx_str_t token_prefixes[TOKEN_PREFIX_COUNT] = {
	ngx_string(""),
	ngx_string("?"),
	ngx_string("&"),
};

ngx_str_t  ngx_http_secure_token_default_types[] = {
    ngx_null_string
};

struct ngx_http_secure_token_ctx_s {
	ngx_str_t prefixed_tokens[TOKEN_PREFIX_COUNT];
	ngx_str_t token;
	ngx_http_secure_token_body_processor_t process;
	off_t processor_context_offset;
	union {
		ngx_http_secure_token_m3u8_ctx_t m3u8;
		ngx_http_secure_token_mpd_ctx_t mpd;
	} u;
};

static ngx_command_t  ngx_http_secure_token_commands[] = {
    { ngx_string("secure_token"),
    NGX_HTTP_MAIN_CONF|NGX_HTTP_SRV_CONF|NGX_HTTP_LOC_CONF|NGX_CONF_TAKE1,
    ngx_http_secure_token_command,
    NGX_HTTP_LOC_CONF_OFFSET,
    offsetof(ngx_http_secure_token_loc_conf_t, build_token),
    NULL },

	{ ngx_string("secure_token_window"),
	NGX_HTTP_MAIN_CONF|NGX_HTTP_SRV_CONF|NGX_HTTP_LOC_CONF|NGX_CONF_TAKE1,
	ngx_conf_set_num_slot,
	NGX_HTTP_LOC_CONF_OFFSET,
	offsetof(ngx_http_secure_token_loc_conf_t, window),
	NULL },

	{ ngx_string("secure_token_avoid_cookies"),
	NGX_HTTP_MAIN_CONF | NGX_HTTP_SRV_CONF | NGX_HTTP_LOC_CONF | NGX_CONF_FLAG,
	ngx_conf_set_flag_slot,
	NGX_HTTP_LOC_CONF_OFFSET,
	offsetof(ngx_http_secure_token_loc_conf_t, avoid_cookies),
	NULL },

	{ ngx_string("secure_token_tokenize_segments"),
	NGX_HTTP_MAIN_CONF|NGX_HTTP_SRV_CONF|NGX_HTTP_LOC_CONF|NGX_CONF_FLAG,
	ngx_conf_set_flag_slot,
	NGX_HTTP_LOC_CONF_OFFSET,
	offsetof(ngx_http_secure_token_loc_conf_t, processor_conf.tokenize_segments),
	NULL },

	{ ngx_string("secure_token_types"),
	NGX_HTTP_MAIN_CONF | NGX_HTTP_SRV_CONF | NGX_HTTP_LOC_CONF | NGX_CONF_1MORE,
	ngx_http_types_slot,
	NGX_HTTP_LOC_CONF_OFFSET,
	offsetof(ngx_http_secure_token_loc_conf_t, types_keys),
	NULL },

	{ ngx_string("secure_token_uri_filename_prefix"),
    NGX_HTTP_MAIN_CONF|NGX_HTTP_SRV_CONF|NGX_HTTP_LOC_CONF|NGX_CONF_TAKE1,
    ngx_conf_set_str_array_slot,
    NGX_HTTP_LOC_CONF_OFFSET,
    offsetof(ngx_http_secure_token_loc_conf_t, filename_prefixes),
    NULL },

    { ngx_string("secure_token_expires_time"),
    NGX_HTTP_MAIN_CONF|NGX_HTTP_SRV_CONF|NGX_HTTP_LOC_CONF|NGX_CONF_TAKE1,
    ngx_conf_set_sec_slot,
    NGX_HTTP_LOC_CONF_OFFSET,
    offsetof(ngx_http_secure_token_loc_conf_t, expires_time),
    NULL },

    { ngx_string("secure_token_cookie_token_expires_time"),
    NGX_HTTP_MAIN_CONF|NGX_HTTP_SRV_CONF|NGX_HTTP_LOC_CONF|NGX_CONF_TAKE1,
    ngx_conf_set_sec_slot,
    NGX_HTTP_LOC_CONF_OFFSET,
	offsetof(ngx_http_secure_token_loc_conf_t, cookie_token_expires_time),
    NULL },

	{ ngx_string("secure_token_query_token_expires_time"),
	NGX_HTTP_MAIN_CONF | NGX_HTTP_SRV_CONF | NGX_HTTP_LOC_CONF | NGX_CONF_TAKE1,
	ngx_conf_set_sec_slot,
	NGX_HTTP_LOC_CONF_OFFSET,
	offsetof(ngx_http_secure_token_loc_conf_t, query_token_expires_time),
	NULL },
	
	{ ngx_string("secure_token_cache_scope"),
	NGX_HTTP_MAIN_CONF|NGX_HTTP_SRV_CONF|NGX_HTTP_LOC_CONF|NGX_CONF_TAKE1,
	ngx_conf_set_str_slot,
	NGX_HTTP_LOC_CONF_OFFSET,
	offsetof(ngx_http_secure_token_loc_conf_t, cache_scope),
	NULL },

	{ ngx_string("secure_token_token_cache_scope"),
	NGX_HTTP_MAIN_CONF|NGX_HTTP_SRV_CONF|NGX_HTTP_LOC_CONF|NGX_CONF_TAKE1,
	ngx_conf_set_str_slot,
	NGX_HTTP_LOC_CONF_OFFSET,
	offsetof(ngx_http_secure_token_loc_conf_t, token_cache_scope),
	NULL },
	
	{ ngx_string("secure_token_last_modified"),
	NGX_HTTP_MAIN_CONF | NGX_HTTP_SRV_CONF | NGX_HTTP_LOC_CONF | NGX_CONF_TAKE1,
	ngx_conf_set_str_slot,
	NGX_HTTP_LOC_CONF_OFFSET,
	offsetof(ngx_http_secure_token_loc_conf_t, last_modified),
	NULL },

	{ ngx_string("secure_token_token_last_modified"),
	NGX_HTTP_MAIN_CONF | NGX_HTTP_SRV_CONF | NGX_HTTP_LOC_CONF | NGX_CONF_TAKE1,
	ngx_conf_set_str_slot,
	NGX_HTTP_LOC_CONF_OFFSET,
	offsetof(ngx_http_secure_token_loc_conf_t, token_last_modified),
	NULL },

#include "ngx_http_secure_token_akamai_commands.h"
#include "ngx_http_secure_token_cloudfront_commands.h"

    ngx_null_command
};
	  
static ngx_int_t ngx_http_secure_token_filter_init(ngx_conf_t *cf);

static ngx_http_module_t  ngx_http_secure_token_filter_module_ctx = {
    NULL,                                  /* preconfiguration */
    ngx_http_secure_token_filter_init,     /* postconfiguration */

    NULL,                                  /* create main configuration */
    NULL,                                  /* init main configuration */

    NULL,                                  /* create server configuration */
    NULL,                                  /* merge server configuration */

    ngx_http_secure_token_create_loc_conf, /* create location configuration */
    ngx_http_secure_token_merge_loc_conf   /* merge location configuration */
};

ngx_module_t  ngx_http_secure_token_filter_module = {
    NGX_MODULE_V1,
    &ngx_http_secure_token_filter_module_ctx, /* module context */
    ngx_http_secure_token_commands,        /* module directives */
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
static ngx_http_output_body_filter_pt    ngx_http_next_body_filter;

typedef struct {
	ngx_str_t content_type;
	ngx_http_secure_token_body_processor_t process;
	off_t processor_context_offset;
} body_processor_t;

static body_processor_t body_processors[] = {
	{ ngx_string("application/vnd.apple.mpegurl"),	(ngx_http_secure_token_body_processor_t)ngx_http_secure_token_m3u8_processor,	offsetof(ngx_http_secure_token_ctx_t, u.m3u8) },
	{ ngx_string("application/dash+xml"),			(ngx_http_secure_token_body_processor_t)ngx_http_secure_token_mpd_processor,	offsetof(ngx_http_secure_token_ctx_t, u.mpd) },
};

static ngx_int_t
ngx_http_secure_token_init_processors_hash(ngx_conf_t *cf, ngx_http_secure_token_loc_conf_t* conf)
{
	ngx_hash_key_t hash_keys[sizeof(body_processors) / sizeof(body_processors[0])];
	ngx_hash_init_t hash;
	ngx_str_t* content_type;
	ngx_int_t rc;
	unsigned i;

	for (i = 0; i < sizeof(hash_keys) / sizeof(hash_keys[0]); i++)
	{
		content_type = &body_processors[i].content_type;
		hash_keys[i].key = *content_type;
		hash_keys[i].key_hash = ngx_hash_key_lc(content_type->data, content_type->len);
		hash_keys[i].value = &body_processors[i];
	}

	hash.hash = &conf->processors_hash;
	hash.key = ngx_hash_key;
	hash.max_size = 512;
	hash.bucket_size = 64;
	hash.name = "processors_hash";
	hash.pool = cf->pool;
	hash.temp_pool = NULL;

	rc = ngx_hash_init(&hash, hash_keys, sizeof(hash_keys) / sizeof(hash_keys[0]));
	if (rc != NGX_OK)
	{
		ngx_conf_log_error(NGX_LOG_EMERG, cf, 0, "ngx_hash_init failed %i", rc);
		return rc;
	}

	return NGX_OK;
}

static char *
ngx_http_secure_token_command(ngx_conf_t *cf, ngx_command_t *cmd, void *conf)
{
	ngx_http_secure_token_loc_conf_t *secure_token_conf = conf;
	ngx_str_t *value;

	value = cf->args->elts;

	if (ngx_strcasecmp(value[1].data, (u_char *) "akamai") == 0) 
	{
		secure_token_conf->build_token = ngx_http_secure_token_akamai_build;
	}
	else if (ngx_strcasecmp(value[1].data, (u_char *) "cloudfront") == 0) 
	{
		secure_token_conf->build_token = ngx_http_secure_token_cloudfront_build;
	}
	else 
	{
		ngx_conf_log_error(NGX_LOG_EMERG, cf, 0,
			"invalid value \"%s\" in \"%s\" directive, "
			"it must be \"akamai\" or \"cloudfront\"",
			value[1].data, cmd->name.data);
		return NGX_CONF_ERROR;
	}

	return NGX_CONF_OK;
}

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
ngx_http_secure_token_create_loc_conf(ngx_conf_t *cf)
{
    ngx_http_secure_token_loc_conf_t  *conf;

    conf = ngx_pcalloc(cf->pool, sizeof(ngx_http_secure_token_loc_conf_t));
    if (conf == NULL) {
        return NGX_CONF_ERROR;
    }
	conf->build_token = NGX_CONF_UNSET_PTR;
    conf->window = NGX_CONF_UNSET_UINT;
	conf->avoid_cookies = NGX_CONF_UNSET;
	conf->filename_prefixes = NGX_CONF_UNSET_PTR;
	conf->expires_time = NGX_CONF_UNSET;
	conf->cookie_token_expires_time = NGX_CONF_UNSET;
	conf->query_token_expires_time = NGX_CONF_UNSET;
	conf->processor_conf.tokenize_segments = NGX_CONF_UNSET;
	
	ngx_http_secure_token_akamai_create_conf(cf, &conf->akamai);
	ngx_http_secure_token_cloudfront_create_conf(cf, &conf->cloudfront);
	
	return conf;
}

static char *
ngx_http_secure_token_init_time(ngx_str_t* str, time_t* time)
{
	// now => 0
	// empty => NGX_CONF_UNSET
	// other => unix timestamp

	if (str->len == sizeof("now") - 1 &&
		ngx_strncasecmp(str->data, (u_char *)"now", sizeof("now") - 1) == 0)
	{
		*time = 0;
	}
	else if (str->len > 0)
	{
		*time = ngx_http_parse_time(str->data, str->len);
		if (*time == NGX_ERROR)
		{
			return NGX_CONF_ERROR;
		}
	}
	else
	{
		*time = NGX_CONF_UNSET;
	}

	return NGX_CONF_OK;
}

static char *
ngx_http_secure_token_merge_loc_conf(ngx_conf_t *cf, void *parent, void *child)
{
    ngx_http_secure_token_loc_conf_t  *prev = parent;
    ngx_http_secure_token_loc_conf_t  *conf = child;
	char* err;

    ngx_conf_merge_ptr_value(conf->build_token, prev->build_token, NULL);
	
	ngx_conf_merge_uint_value(conf->window, prev->window, 86400);
	ngx_conf_merge_value(conf->avoid_cookies, prev->avoid_cookies, 1);
	
	ngx_conf_merge_ptr_value(conf->filename_prefixes, prev->filename_prefixes, NULL);
    
	ngx_conf_merge_sec_value(conf->expires_time, prev->expires_time, NGX_CONF_UNSET);
	ngx_conf_merge_sec_value(conf->cookie_token_expires_time, prev->cookie_token_expires_time, NGX_CONF_UNSET);
	ngx_conf_merge_sec_value(conf->query_token_expires_time, prev->query_token_expires_time, NGX_CONF_UNSET);
	ngx_conf_merge_str_value(conf->cache_scope, prev->cache_scope, "public");
	ngx_conf_merge_str_value(conf->token_cache_scope, prev->token_cache_scope, "private");
	ngx_conf_merge_str_value(conf->last_modified, prev->last_modified, "Sun, 19 Nov 2000 08:52:00 GMT");
	ngx_conf_merge_str_value(conf->token_last_modified, prev->token_last_modified, "now");

    ngx_conf_merge_value(conf->processor_conf.tokenize_segments, prev->processor_conf.tokenize_segments, 1);
	
    if (ngx_http_merge_types(cf, &conf->types_keys, &conf->types,
                             &prev->types_keys, &prev->types,
                             ngx_http_secure_token_default_types)
        != NGX_OK)
    {
        return NGX_CONF_ERROR;
    }

	if (ngx_http_secure_token_init_processors_hash(cf, conf) != NGX_OK)
	{
		return NGX_CONF_ERROR;
	}

	err = ngx_http_secure_token_init_time(&conf->last_modified, &conf->last_modified_time);
	if (err != NGX_CONF_OK)
	{
		return err;
	}

	err = ngx_http_secure_token_init_time(&conf->token_last_modified, &conf->token_last_modified_time);
	if (err != NGX_CONF_OK)
	{
		return err;
	}
	
	err = ngx_http_secure_token_akamai_merge_conf(cf, conf, &conf->akamai, &prev->akamai);
	if (err != NGX_CONF_OK)
	{
		return err;
	}

	err = ngx_http_secure_token_cloudfront_merge_conf(cf, conf, &conf->cloudfront, &prev->cloudfront);
	if (err != NGX_CONF_OK)
	{
		return err;
	}
	
    return NGX_CONF_OK;
}

// a run down version of ngx_http_set_expires with a few changes
// (can't use the existing code since the function is static)
static ngx_int_t
ngx_http_secure_token_set_expires(ngx_http_request_t *r, time_t expires_time, ngx_str_t* cache_scope)
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
                                 sizeof(CACHE_CONTROL_FORMAT) + cache_scope->len + NGX_TIME_T_LEN + 1);
    if (cc->value.data == NULL) {
        return NGX_ERROR;
    }

    cc->value.len = ngx_sprintf(cc->value.data, CACHE_CONTROL_FORMAT, cache_scope, max_age)
                    - cc->value.data;

    return NGX_OK;
}

static ngx_int_t
ngx_http_secure_token_call_next_filter(
	ngx_http_request_t *r, 
	time_t expires, 
	ngx_str_t* cache_scope,
	time_t last_modified,
	ngx_str_t* last_modified_str)
{
	ngx_table_elt_t *h;
	ngx_int_t rc;

	if (expires != NGX_CONF_UNSET)
	{
		rc = ngx_http_secure_token_set_expires(r, expires, cache_scope);
		if (rc != NGX_OK)
		{
			return rc;
		}
	}
	
	if (last_modified == 0)
	{
		if (r->headers_out.last_modified != NULL)
		{
			r->headers_out.last_modified->hash = 0;
			r->headers_out.last_modified = NULL;
		}
		r->headers_out.last_modified_time = ngx_time();
	}
	else if (last_modified != NGX_CONF_UNSET)
	{
		if (r->headers_out.last_modified) 
		{
			h = r->headers_out.last_modified;
		}
		else 
		{
			h = ngx_list_push(&r->headers_out.headers);
			if (h == NULL) 
			{
				return NGX_ERROR;
			}

			r->headers_out.last_modified = h;
		}
		h->hash = 1;
		h->key.data = (u_char*)"Last-Modified";
		h->key.len = sizeof("Last-Modified") - 1;
		h->value = *last_modified_str;

		r->headers_out.last_modified_time = last_modified;
	}

	return ngx_http_next_header_filter(r);
}

static ngx_int_t
ngx_http_secure_token_header_filter(ngx_http_request_t *r)
{
    ngx_http_secure_token_loc_conf_t  *conf;
	ngx_http_secure_token_ctx_t* ctx;
	body_processor_t* processor = NULL;
	ngx_table_elt_t  *set_cookie;
	ngx_flag_t prefix_matched;
	ngx_uint_t i;
	ngx_str_t* cur_prefix;
	ngx_str_t token;
	ngx_str_t uri_filename;
	ngx_str_t acl;
	ngx_int_t rc;
	u_char* last_slash_pos;
	u_char* acl_end_pos;
	u_char* comma_pos;

    conf = ngx_http_get_module_loc_conf(r, ngx_http_secure_token_filter_module);
	
	// decide whether the token should be added
    if (conf->build_token == NULL || 
		r->headers_out.status != NGX_HTTP_OK ||
		r != r->main)
	{
		return ngx_http_next_header_filter(r);
	}
	
	if (ngx_http_test_content_type(r, &conf->types) == NULL)
    {
        return ngx_http_secure_token_call_next_filter(
			r, 
			conf->expires_time, 
			&conf->cache_scope,
			conf->last_modified_time, 
			&conf->last_modified);
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
			return ngx_http_secure_token_call_next_filter(
				r, 
				conf->expires_time, 
				&conf->cache_scope, 
				conf->last_modified_time,
				&conf->last_modified);
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

	// build the token
	rc = conf->build_token(r, conf, &acl, &token);
	if (rc != NGX_OK)
	{
		return rc;
	}

	if (conf->avoid_cookies)
	{
		// Note: content_type_lowcase is already initialized since we called ngx_http_test_content_type
		processor = ngx_hash_find(&conf->processors_hash, r->headers_out.content_type_hash, r->headers_out.content_type_lowcase, r->headers_out.content_type_len);
	}

	if (processor != NULL)
	{
		// add the token to all the URLs in the response
		ctx = ngx_pcalloc(r->pool, sizeof(*ctx));
		if (ctx == NULL)
		{
			return NGX_ERROR;
		}

		ctx->token = token;
		ctx->process = processor->process;
		ctx->processor_context_offset = processor->processor_context_offset;

		ngx_http_set_ctx(r, ctx, ngx_http_secure_token_filter_module);

		r->filter_need_in_memory = 1;

		ngx_http_clear_content_length(r);
		ngx_http_clear_accept_ranges(r);
		ngx_http_clear_etag(r);

		return ngx_http_secure_token_call_next_filter(
			r, 
			conf->query_token_expires_time, 
			&conf->token_cache_scope,
			conf->token_last_modified_time,
			&conf->token_last_modified);
	}
	else
	{
		// add a cookie token to the response headers
		set_cookie = ngx_list_push(&r->headers_out.headers);
		if (set_cookie == NULL) {
			return NGX_ERROR;
		}

		set_cookie->hash = 1;
		ngx_str_set(&set_cookie->key, "Set-Cookie");
		set_cookie->value = token;

		return ngx_http_secure_token_call_next_filter(
			r, 
			conf->cookie_token_expires_time, 
			&conf->token_cache_scope,
			conf->token_last_modified_time,
			&conf->token_last_modified);
	}
}

ngx_chain_t**
ngx_http_secure_token_add_to_chain(ngx_pool_t* pool, ngx_chain_t** out, u_char* start, u_char* end, ngx_flag_t memory, ngx_flag_t last_buf)
{
	ngx_chain_t* cl;
	ngx_buf_t* b;

	b = ngx_calloc_buf(pool);
	if (b == NULL)
	{
		return NULL;
	}

	cl = ngx_alloc_chain_link(pool);
	if (cl == NULL)
	{
		return NULL;
	}

	b->pos = start;
	b->last = end;
	b->memory = memory;
	b->last_buf = last_buf;
	cl->buf = b;

	*out = cl;
	out = &cl->next;

	return out;
}

static ngx_buf_t* 
ngx_http_secure_token_get_token(ngx_http_secure_token_ctx_t* ctx, ngx_pool_t* pool, int index)
{
	ngx_buf_t* b;
	u_char* p;

	if (ctx->prefixed_tokens[index].len == 0)
	{
		ctx->prefixed_tokens[index].data = ngx_palloc(pool, token_prefixes[index].len + ctx->token.len);
		if (ctx->prefixed_tokens[index].data == NULL)
		{
			return NULL;
		}

		p = ngx_copy(ctx->prefixed_tokens[index].data, token_prefixes[index].data, token_prefixes[index].len);
		p = ngx_copy(p, ctx->token.data, ctx->token.len);

		ctx->prefixed_tokens[index].len = p - ctx->prefixed_tokens[index].data;
	}

	b = ngx_calloc_buf(pool);
	if (b == NULL)
	{
		return NULL;
	}

	b->pos = ctx->prefixed_tokens[index].data;
	b->last = b->pos + ctx->prefixed_tokens[index].len;
	b->memory = 1;

	return b;
}

ngx_chain_t**
ngx_http_secure_token_add_token(
	ngx_http_secure_token_ctx_t* ctx, 
	ngx_pool_t* pool,
	u_char** last_sent,
	u_char* cur_pos,
	ngx_flag_t has_query,
	u_char last_url_char,
	ngx_chain_t** out)
{
	ngx_chain_t* cl;
	int token_prefix;

	if (cur_pos > *last_sent)
	{
		out = ngx_http_secure_token_add_to_chain(pool, out, *last_sent, cur_pos, 1, 0);
		if (out == NULL)
		{
			return NULL;
		}

		*last_sent = cur_pos;
	}

	cl = ngx_alloc_chain_link(pool);
	if (cl == NULL)
	{
		return NULL;
	}

	if (has_query)
	{
		if (last_url_char == '?' || last_url_char == '&')
		{
			token_prefix = TOKEN_PREFIX_NONE;
		}
		else
		{
			token_prefix = TOKEN_PREFIX_AMPERSAND;
		}
	}
	else
	{
		token_prefix = TOKEN_PREFIX_QUESTION;
	}

	cl->buf = ngx_http_secure_token_get_token(ctx, pool, token_prefix);
	if (cl->buf == NULL)
	{
		return NULL;
	}

	*out = cl;
	out = &cl->next;

	return out;
}

static ngx_int_t
ngx_http_secure_token_body_filter(ngx_http_request_t *r, ngx_chain_t *in)
{
	ngx_http_secure_token_loc_conf_t *conf;
	ngx_http_secure_token_ctx_t* ctx;
	ngx_chain_t** cur_out;
	ngx_chain_t* out;
	ngx_flag_t last_buf = 0;

	ctx = ngx_http_get_module_ctx(r, ngx_http_secure_token_filter_module);
	
	if (ctx == NULL || in == NULL)
	{
		return ngx_http_next_body_filter(r, in);
	}

	conf = ngx_http_get_module_loc_conf(r, ngx_http_secure_token_filter_module);
	
	cur_out = &out;

	for (; in != NULL; in = in->next)
	{
		if (in->buf == NULL)
		{
			continue;
		}

		last_buf |= in->buf->last_buf;

		cur_out = ctx->process(
			&conf->processor_conf,
			in->buf,
			ctx,
			(u_char*)ctx + ctx->processor_context_offset,
			r->pool,
			cur_out);
		if (cur_out == NULL)
		{
			return NGX_ERROR;
		}
	}

	if (last_buf)
	{
		cur_out = ngx_http_secure_token_add_to_chain(r->pool, cur_out, NULL, NULL, 0, 1);
		if (cur_out == NULL)
		{
			return NGX_ERROR;
		}
	}

	*cur_out = NULL;

	return ngx_http_next_body_filter(r, out);
}

static ngx_int_t
ngx_http_secure_token_filter_init(ngx_conf_t *cf)
{
    ngx_http_next_header_filter = ngx_http_top_header_filter;
    ngx_http_top_header_filter = ngx_http_secure_token_header_filter;

    ngx_http_next_body_filter = ngx_http_top_body_filter;
    ngx_http_top_body_filter = ngx_http_secure_token_body_filter;	
	
    return NGX_OK;
}
