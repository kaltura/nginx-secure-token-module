#include <ngx_config.h>
#include <ngx_core.h>
#include <ngx_http.h>
#include <ctype.h>

#include "ngx_http_secure_token_processor_base.h"
#include "ngx_http_secure_token_filter_module.h"
#include "ngx_http_secure_token_encrypt_uri.h"
#include "cloudfront/ngx_http_secure_token_cloudfront.h"
#include "akamai/ngx_http_secure_token_akamai.h"
#include "cht/ngx_http_secure_token_cht.h"
#include "ngx_http_secure_token_utils.h"
#include "ngx_http_secure_token_conf.h"
#include "ngx_http_secure_token_m3u8.h"
#include "ngx_http_secure_token_xml.h"

#define CACHE_CONTROL_FORMAT "%V, max-age=%T, max-stale=0"

static char *ngx_conf_check_str_len_bounds(ngx_conf_t *cf, void *post, void *data);
static void *ngx_http_secure_token_create_loc_conf(ngx_conf_t *cf);
static char *ngx_http_secure_token_merge_loc_conf(ngx_conf_t *cf, void *parent, void *child);
static ngx_int_t ngx_http_secure_token_add_variables(ngx_conf_t *cf);
static ngx_int_t ngx_http_secure_token_filter_init(ngx_conf_t *cf);
static ngx_int_t ngx_http_secure_token_set_baseuri_comma(ngx_http_request_t *r, ngx_http_variable_value_t *v, uintptr_t data);

static ngx_str_t  ngx_http_secure_token_default_types[] = {
	ngx_null_string
};

static ngx_str_t  ngx_http_baseuri = ngx_string("secure_token_baseuri");
static ngx_str_t  ngx_http_baseuri_comma = ngx_string("secure_token_baseuri_comma");

static ngx_conf_num_bounds_t  ngx_http_secure_token_encrypt_uri_key_bounds = {
	ngx_conf_check_str_len_bounds, 32, 32
};

static ngx_conf_num_bounds_t  ngx_http_secure_token_encrypt_uri_iv_bounds = {
	ngx_conf_check_str_len_bounds, 16, 16
};

static ngx_conf_num_bounds_t  ngx_http_secure_token_encrypt_uri_hash_size_bounds = {
	ngx_conf_check_num_bounds, 0, 16
};

static ngx_command_t  ngx_http_secure_token_commands[] = {
	{ ngx_string("secure_token"),
	NGX_HTTP_MAIN_CONF|NGX_HTTP_SRV_CONF|NGX_HTTP_LOC_CONF|NGX_CONF_TAKE1,
	ngx_http_set_complex_value_slot,
	NGX_HTTP_LOC_CONF_OFFSET,
	offsetof(ngx_http_secure_token_loc_conf_t, token),
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

	{ ngx_string("secure_token_content_type_m3u8"),
	NGX_HTTP_MAIN_CONF | NGX_HTTP_SRV_CONF | NGX_HTTP_LOC_CONF | NGX_CONF_TAKE1,
	ngx_conf_set_str_slot,
	NGX_HTTP_LOC_CONF_OFFSET,
	offsetof(ngx_http_secure_token_loc_conf_t, content_type_m3u8),
	NULL },

	{ ngx_string("secure_token_content_type_mpd"),
	NGX_HTTP_MAIN_CONF | NGX_HTTP_SRV_CONF | NGX_HTTP_LOC_CONF | NGX_CONF_TAKE1,
	ngx_conf_set_str_slot,
	NGX_HTTP_LOC_CONF_OFFSET,
	offsetof(ngx_http_secure_token_loc_conf_t, content_type_mpd),
	NULL },

	{ ngx_string("secure_token_content_type_f4m"),
	NGX_HTTP_MAIN_CONF | NGX_HTTP_SRV_CONF | NGX_HTTP_LOC_CONF | NGX_CONF_TAKE1,
	ngx_conf_set_str_slot,
	NGX_HTTP_LOC_CONF_OFFSET,
	offsetof(ngx_http_secure_token_loc_conf_t, content_type_f4m),
	NULL },

#include "akamai/ngx_http_secure_token_akamai_commands.h"
#include "cloudfront/ngx_http_secure_token_cloudfront_commands.h"
#include "cht/ngx_http_secure_token_cht_commands.h"

	{ ngx_string("secure_token_encrypt_uri"),
	NGX_HTTP_MAIN_CONF|NGX_HTTP_SRV_CONF|NGX_HTTP_LOC_CONF|NGX_CONF_FLAG,
	ngx_conf_set_flag_slot,
	NGX_HTTP_LOC_CONF_OFFSET,
	offsetof(ngx_http_secure_token_loc_conf_t, processor_conf.encrypt_uri),
	NULL },

	{ ngx_string("secure_token_encrypt_uri_key"),
	NGX_HTTP_MAIN_CONF | NGX_HTTP_SRV_CONF | NGX_HTTP_LOC_CONF | NGX_CONF_TAKE1,
	ngx_http_secure_token_conf_set_hex_str_slot,
	NGX_HTTP_LOC_CONF_OFFSET,
	offsetof(ngx_http_secure_token_loc_conf_t, encrypt_uri_key),
	&ngx_http_secure_token_encrypt_uri_key_bounds },

	{ ngx_string("secure_token_encrypt_uri_iv"),
	NGX_HTTP_MAIN_CONF | NGX_HTTP_SRV_CONF | NGX_HTTP_LOC_CONF | NGX_CONF_TAKE1,
	ngx_http_secure_token_conf_set_hex_str_slot,
	NGX_HTTP_LOC_CONF_OFFSET,
	offsetof(ngx_http_secure_token_loc_conf_t, encrypt_uri_iv),
	&ngx_http_secure_token_encrypt_uri_iv_bounds },

	{ ngx_string("secure_token_encrypt_uri_part"),
	NGX_HTTP_MAIN_CONF | NGX_HTTP_SRV_CONF | NGX_HTTP_LOC_CONF | NGX_CONF_TAKE1,
	ngx_http_set_complex_value_slot,
	NGX_HTTP_LOC_CONF_OFFSET,
	offsetof(ngx_http_secure_token_loc_conf_t, encrypt_uri_part),
	NULL },

	{ ngx_string("secure_token_encrypt_uri_hash_size"),
	NGX_HTTP_MAIN_CONF | NGX_HTTP_SRV_CONF | NGX_HTTP_LOC_CONF | NGX_CONF_TAKE1,
	ngx_conf_set_size_slot,
	NGX_HTTP_LOC_CONF_OFFSET,
	offsetof(ngx_http_secure_token_loc_conf_t, encrypt_uri_hash_size),
	&ngx_http_secure_token_encrypt_uri_hash_size_bounds },

	ngx_null_command
};

static ngx_http_module_t  ngx_http_secure_token_filter_module_ctx = {
    ngx_http_secure_token_add_variables,   /* preconfiguration */
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


// Note: copy of ngx_conf_check_num_bounds adjusted for string length validation
static char *
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

static void *
ngx_http_secure_token_create_loc_conf(ngx_conf_t *cf)
{
	ngx_http_secure_token_loc_conf_t  *conf;

	conf = ngx_pcalloc(cf->pool, sizeof(ngx_http_secure_token_loc_conf_t));
	if (conf == NULL) {
		return NGX_CONF_ERROR;
	}
	conf->avoid_cookies = NGX_CONF_UNSET;
	conf->filename_prefixes = NGX_CONF_UNSET_PTR;
	conf->expires_time = NGX_CONF_UNSET;
	conf->cookie_token_expires_time = NGX_CONF_UNSET;
	conf->query_token_expires_time = NGX_CONF_UNSET;
	conf->processor_conf.tokenize_segments = NGX_CONF_UNSET;
	conf->processor_conf.encrypt_uri = NGX_CONF_UNSET;
	conf->encrypt_uri_hash_size = NGX_CONF_UNSET_SIZE;
		
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

	if (conf->token == NULL)
	{
		conf->token = prev->token;
	}
	ngx_conf_merge_value(conf->avoid_cookies, prev->avoid_cookies, 1);
	
	ngx_conf_merge_ptr_value(conf->filename_prefixes, prev->filename_prefixes, NULL);
    
	ngx_conf_merge_sec_value(conf->expires_time, prev->expires_time, NGX_CONF_UNSET);
	ngx_conf_merge_sec_value(conf->cookie_token_expires_time, prev->cookie_token_expires_time, NGX_CONF_UNSET);
	ngx_conf_merge_sec_value(conf->query_token_expires_time, prev->query_token_expires_time, NGX_CONF_UNSET);
	ngx_conf_merge_str_value(conf->cache_scope, prev->cache_scope, "public");
	ngx_conf_merge_str_value(conf->token_cache_scope, prev->token_cache_scope, "private");
	ngx_conf_merge_str_value(conf->last_modified, prev->last_modified, "Sun, 19 Nov 2000 08:52:00 GMT");
	ngx_conf_merge_str_value(conf->token_last_modified, prev->token_last_modified, "now");

	ngx_conf_merge_str_value(conf->content_type_m3u8, prev->content_type_m3u8, "application/vnd.apple.mpegurl");
	ngx_conf_merge_str_value(conf->content_type_mpd, prev->content_type_mpd, "application/dash+xml");
	ngx_conf_merge_str_value(conf->content_type_f4m, prev->content_type_f4m, "video/f4m");

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
		
	ngx_conf_merge_value(conf->processor_conf.encrypt_uri, prev->processor_conf.encrypt_uri, 0);
	ngx_conf_merge_str_value(conf->encrypt_uri_key, prev->encrypt_uri_key, "");
	ngx_conf_merge_str_value(conf->encrypt_uri_iv, prev->encrypt_uri_iv, "");
	if (conf->encrypt_uri_part == NULL)
	{
		conf->encrypt_uri_part = prev->encrypt_uri_part;
	}
	ngx_conf_merge_size_value(conf->encrypt_uri_hash_size, prev->encrypt_uri_hash_size, 8);

	if (conf->processor_conf.encrypt_uri)
	{
		if (!conf->encrypt_uri_key.len)
		{
			ngx_conf_log_error(NGX_LOG_EMERG, cf, 0,
				"\"secure_token_encrypt_uri_key\" is mandatory when encrypt uri is enabled");
			return NGX_CONF_ERROR;
		}

		if (!conf->encrypt_uri_iv.len)
		{
			ngx_conf_log_error(NGX_LOG_EMERG, cf, 0,
				"\"secure_token_encrypt_uri_iv\" is mandatory when encrypt uri is enabled");
			return NGX_CONF_ERROR;
		}
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

ngx_int_t
ngx_http_secure_token_get_acl(ngx_http_request_t *r, ngx_http_complex_value_t *acl_conf, ngx_str_t* acl)
{
	ngx_http_variable_value_t var_value;

	// get the acl
	if (acl_conf != NULL)
	{
		if (ngx_http_complex_value(r, acl_conf, acl) != NGX_OK)
		{
			return NGX_ERROR;
		}
	}
	else
	{
		// the default is 'baseuri_comma'
		if (ngx_http_secure_token_set_baseuri_comma(r, &var_value, 0) != NGX_OK)
		{
			return NGX_ERROR;
		}

		acl->data = var_value.data;
		acl->len = var_value.len;
	}

	return NGX_OK;
}

static void *
ngx_http_secure_token_memrchr(const u_char *s, int c, size_t n)
{
	const u_char *cp;

	for (cp = s + n; cp > s;)
	{
		if (*(--cp) == (u_char)c)
			return (void*)cp;
	}
	return NULL;
}

static ngx_int_t
ngx_http_secure_token_header_filter(ngx_http_request_t *r)
{
	ngx_http_secure_token_loc_conf_t  *conf;
	ngx_table_elt_t  *set_cookie;
	ngx_flag_t body_filter_inited;
	ngx_flag_t prefix_matched;
	ngx_uint_t i;
	ngx_str_t* cur_prefix;
	ngx_str_t token;
	ngx_str_t uri_filename;
	ngx_int_t rc;
	u_char* last_slash_pos;

	conf = ngx_http_get_module_loc_conf(r, ngx_http_secure_token_filter_module);

	// decide whether the token should be added
	if ((conf->token == NULL && !conf->processor_conf.encrypt_uri) ||
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
	last_slash_pos = ngx_http_secure_token_memrchr(r->uri.data, '/', r->uri.len);
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

	// build the token
	token.len = 0;
	token.data = NULL;

	if (conf->token != NULL)
	{
		if (ngx_http_complex_value(
			r,
			conf->token,
			&token) != NGX_OK)
		{
			return NGX_ERROR;
		}
	}

	// init the body filter if needed
	body_filter_inited = 0;
	if (conf->avoid_cookies || conf->processor_conf.encrypt_uri)
	{
		// Note: this function returns NGX_DONE when a matching body processor is not found
		rc = ngx_http_secure_token_init_body_filter(r, &token);
		if (rc == NGX_OK)
		{
			body_filter_inited = 1;
		}
		else if (rc != NGX_DONE)
		{
			return rc;
		}
	}

	// if no token, we are done
	if (token.len == 0)
	{
		return ngx_http_secure_token_call_next_filter(
			r,
			conf->expires_time,
			&conf->cache_scope,
			conf->last_modified_time,
			&conf->last_modified);
	}

	// if the token will be added to the body we are done
	if (body_filter_inited)
	{
		return ngx_http_secure_token_call_next_filter(
			r,
			conf->query_token_expires_time,
			&conf->token_cache_scope,
			conf->token_last_modified_time,
			&conf->token_last_modified);
	}

	// add a cookie token
	set_cookie = ngx_list_push(&r->headers_out.headers);
	if (set_cookie == NULL)
	{
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

static ngx_int_t
ngx_http_secure_token_filter_init(ngx_conf_t *cf)
{
	ngx_http_handler_pt		*h;
	ngx_http_core_main_conf_t  *cmcf;

	// header filter
	ngx_http_next_header_filter = ngx_http_top_header_filter;
	ngx_http_top_header_filter = ngx_http_secure_token_header_filter;

	// body filter
	ngx_http_secure_token_install_body_filter();

	// access handler
	cmcf = ngx_http_conf_get_module_main_conf(cf, ngx_http_core_module);

	h = ngx_array_push(&cmcf->phases[NGX_HTTP_ACCESS_PHASE].handlers);
	if (h == NULL)
	{
		return NGX_ERROR;
	}

	*h = ngx_http_secure_token_decrypt_uri;

	return NGX_OK;
}

static ngx_int_t
ngx_http_secure_token_set_baseuri(ngx_http_request_t *r, ngx_http_variable_value_t *v, uintptr_t data)
{
	u_char* last_slash_pos;

	last_slash_pos = ngx_http_secure_token_memrchr(r->uri.data, '/', r->uri.len);
	if (last_slash_pos == NULL)
	{
		return NGX_ERROR;
	}

	v->valid = 1;
	v->no_cacheable = 0;
	v->not_found = 0;

	v->len = last_slash_pos + 1 - r->uri.data;
	v->data = r->uri.data;

	return NGX_OK;
}

static ngx_int_t
ngx_http_secure_token_set_baseuri_comma(ngx_http_request_t *r, ngx_http_variable_value_t *v, uintptr_t data)
{
	u_char* last_slash_pos;
	u_char* acl_end_pos;
	u_char* comma_pos;

	last_slash_pos = ngx_http_secure_token_memrchr(r->uri.data, '/', r->uri.len);
	if (last_slash_pos == NULL)
	{
		return NGX_ERROR;
	}

	acl_end_pos = last_slash_pos + 1;

	comma_pos = memchr(r->uri.data, ',', r->uri.len);
	if (comma_pos != NULL)
	{
		acl_end_pos = ngx_min(acl_end_pos, comma_pos);
	}

	v->valid = 1;
	v->no_cacheable = 0;
	v->not_found = 0;

	v->len = acl_end_pos - r->uri.data;
	v->data = r->uri.data;

	return NGX_OK;
}

static ngx_int_t
ngx_http_secure_token_add_variables(ngx_conf_t *cf)
{
	ngx_http_variable_t  *var;

	var = ngx_http_add_variable(cf, &ngx_http_baseuri, NGX_HTTP_VAR_CHANGEABLE);
	if (var == NULL) {
		return NGX_ERROR;
	}

	var->get_handler = ngx_http_secure_token_set_baseuri;

	var = ngx_http_add_variable(cf, &ngx_http_baseuri_comma, NGX_HTTP_VAR_CHANGEABLE);
	if (var == NULL) {
		return NGX_ERROR;
	}

	var->get_handler = ngx_http_secure_token_set_baseuri_comma;

	return NGX_OK;
}
