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

typedef struct {
	ngx_str_t 	param_name;
	ngx_str_t 	key;
	ngx_uint_t  window;
    ngx_str_t   extensions;
	ngx_hash_t  extensions_hash;
} ngx_http_akamai_token_loc_conf_t;

static ngx_command_t  ngx_http_akamai_token_commands[] = {
	{ ngx_string("akamai_token_key"),
	NGX_HTTP_MAIN_CONF | NGX_HTTP_SRV_CONF | NGX_HTTP_LOC_CONF | NGX_CONF_TAKE1,
	ngx_conf_set_hex_str_slot,
	NGX_HTTP_LOC_CONF_OFFSET,
	offsetof(ngx_http_akamai_token_loc_conf_t, key),
	NULL },

	{ ngx_string("akamai_token_window"),
	NGX_HTTP_MAIN_CONF | NGX_HTTP_SRV_CONF | NGX_HTTP_LOC_CONF | NGX_CONF_TAKE1,
	ngx_conf_set_num_slot,
	NGX_HTTP_LOC_CONF_OFFSET,
	offsetof(ngx_http_akamai_token_loc_conf_t, window),
	NULL },

	{ ngx_string("akamai_token_param_name"),
	NGX_HTTP_MAIN_CONF | NGX_HTTP_SRV_CONF | NGX_HTTP_LOC_CONF | NGX_CONF_TAKE1,
	ngx_conf_set_str_slot,
	NGX_HTTP_LOC_CONF_OFFSET,
	offsetof(ngx_http_akamai_token_loc_conf_t, param_name),
	NULL },
	
    { ngx_string("akamai_token_uri_extens"),
    NGX_HTTP_MAIN_CONF|NGX_HTTP_SRV_CONF|NGX_HTTP_LOC_CONF|NGX_CONF_TAKE1,
    ngx_conf_set_str_slot,
    NGX_HTTP_LOC_CONF_OFFSET,
    offsetof(ngx_http_akamai_token_loc_conf_t, extensions),
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
    conf->window = NGX_CONF_UNSET_UINT;
    return conf;
}

static char *
ngx_http_akamai_token_merge_loc_conf(ngx_conf_t *cf, void *parent, void *child)
{
    ngx_http_akamai_token_loc_conf_t  *prev = parent;
    ngx_http_akamai_token_loc_conf_t  *conf = child;
	ngx_hash_key_t* hash_keys;
	ngx_hash_init_t hash;
	ngx_str_t cur_extension;
	ngx_int_t rc;
	unsigned extension_count;
	unsigned i = 0;
	u_char* end_pos;
	u_char* cur_pos;

	ngx_conf_merge_uint_value(conf->window, prev->window, 86400);
	ngx_conf_merge_str_value(conf->param_name, prev->param_name, "__hdnea__");
	ngx_conf_merge_str_value(conf->key, prev->key, "");
    ngx_conf_merge_str_value(conf->extensions, prev->extensions, "");
	
	extension_count = 1;
	end_pos = conf->extensions.data + conf->extensions.len;
	for (cur_pos = conf->extensions.data; cur_pos < end_pos; cur_pos++)
	{
		if (*cur_pos == ',')
		{
			extension_count++;
		}
	}
	
	hash_keys = ngx_palloc(cf->pool, sizeof(hash_keys[0]) * extension_count);
	if (hash_keys == NULL)
	{
		ngx_conf_log_error(NGX_LOG_EMERG, cf, 0, "failed to allocate hash keys");
		return NGX_CONF_ERROR;
	}

	cur_extension.data = conf->extensions.data;
	for (cur_pos = conf->extensions.data; cur_pos <= end_pos; cur_pos++)
	{
		if (cur_pos < end_pos && *cur_pos != ',')
		{
			continue;
		}
		
		cur_extension.len = cur_pos - cur_extension.data;
		hash_keys[i].key = cur_extension;
		hash_keys[i].key_hash = ngx_hash_key_lc(cur_extension.data, cur_extension.len);
		hash_keys[i].value = (void *) 1;
		i++;
		
		cur_extension.data = cur_pos + 1;
	}
	
	hash.hash = &conf->extensions_hash;
	hash.key = ngx_hash_key;
	hash.max_size = 512;
	hash.bucket_size = 64;
	hash.name = "extensions_hash";
	hash.pool = cf->pool;
	hash.temp_pool = NULL;

	rc = ngx_hash_init(&hash, hash_keys, i);
	if (rc != NGX_OK)
	{
		ngx_conf_log_error(NGX_LOG_EMERG, cf, 0, "ngx_hash_init failed %i", rc);
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

static ngx_int_t
ngx_http_akamai_token_header_filter(ngx_http_request_t *r)
{
    ngx_http_akamai_token_loc_conf_t  *conf;
	ngx_table_elt_t  *set_cookie;
	ngx_str_t cookie_value;
	ngx_str_t acl;
	ngx_int_t rc;
	u_char* acl_end_pos;
	u_char* comma_pos;

    conf = ngx_http_get_module_loc_conf(r, ngx_http_akamai_token_filter_module);
	
	// decide whether the token should be added
    if (conf->key.len == 0 ||
		!ngx_hash_find(&conf->extensions_hash, ngx_hash_key_lc(r->exten.data, r->exten.len), r->exten.data, r->exten.len) ||
		r->headers_out.status != NGX_HTTP_OK ||
        r != r->main)
    {
        return ngx_http_next_header_filter(r);
    }
	
	// get the acl
	acl_end_pos = memrchr(r->uri.data, '/', r->uri.len);
	if (acl_end_pos == NULL) {
		return NGX_ERROR;
	}
	acl_end_pos++;
	
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
	
    return ngx_http_next_header_filter(r);
}

static ngx_int_t
ngx_http_akamai_token_filter_init(ngx_conf_t *cf)
{
    ngx_http_next_header_filter = ngx_http_top_header_filter;
    ngx_http_top_header_filter = ngx_http_akamai_token_header_filter;

    return NGX_OK;
}
