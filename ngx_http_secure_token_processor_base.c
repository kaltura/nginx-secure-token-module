#include "ngx_http_secure_token_processor_base.h"
#include "ngx_http_secure_token_filter_module.h"
#include "ngx_http_secure_token_encrypt_uri.h"
#include "ngx_http_secure_token_m3u8.h"
#include "ngx_http_secure_token_xml.h"

// typedefs
enum {
	TOKEN_PREFIX_NONE,
	TOKEN_PREFIX_QUESTION,
	TOKEN_PREFIX_AMPERSAND,

	TOKEN_PREFIX_COUNT
};

struct ngx_http_secure_token_ctx_s {
	ngx_str_t prefixed_tokens[TOKEN_PREFIX_COUNT];
	ngx_str_t token;
	ngx_http_secure_token_body_processor_t process;
	off_t processor_context_offset;
	void* processor_params;
	union {
		ngx_http_secure_token_m3u8_ctx_t m3u8;
		ngx_http_secure_token_xml_ctx_t xml;
	} u;
};

typedef struct {
	off_t content_type_offset;			// in ngx_http_secure_token_loc_conf_t
	ngx_http_secure_token_body_processor_t process;
	off_t processor_context_offset;		// in ngx_http_secure_token_ctx_t
	void* processor_params;
} body_processor_t;

// body processors config constants
static ngx_str_t mpd_segment_template_attrs[] = {
	ngx_string("media"),
	ngx_string("initialization"),
	ngx_null_string
};

static ngx_str_t mpd_initialization_attrs[] = {
	ngx_string("sourceURL"),
	ngx_null_string
};

static ngx_str_t mpd_segmenturl_attrs[] = {
	ngx_string("media"),
	ngx_null_string
};

static ngx_http_secure_token_xml_node_attrs_t mpd_nodes[] = {
	{ ngx_string("SegmentTemplate"), mpd_segment_template_attrs },
	{ ngx_string("Initialization"), mpd_initialization_attrs },
	{ ngx_string("SegmentURL"), mpd_segmenturl_attrs },
	{ ngx_null_string, NULL }
};

static ngx_str_t f4m_media_attrs[] = {
	ngx_string("url"),
	ngx_null_string
};

static ngx_str_t f4m_bootstrap_info_attrs[] = {
	ngx_string("url"),
	ngx_null_string
};

static ngx_http_secure_token_xml_node_attrs_t f4m_nodes[] = {
	{ ngx_string("media"), f4m_media_attrs },
	{ ngx_string("bootstrapInfo"), f4m_bootstrap_info_attrs },
	{ ngx_null_string, NULL }
};

static body_processor_t body_processors[] = {
	{
		offsetof(ngx_http_secure_token_loc_conf_t, content_type_m3u8), 
		(ngx_http_secure_token_body_processor_t)ngx_http_secure_token_m3u8_processor, 
		offsetof(ngx_http_secure_token_ctx_t, u.m3u8), 
		NULL 
	},
	{ 
		offsetof(ngx_http_secure_token_loc_conf_t, content_type_mpd), 
		(ngx_http_secure_token_body_processor_t)ngx_http_secure_token_xml_processor, 
		offsetof(ngx_http_secure_token_ctx_t, u.xml), 
		&mpd_nodes 
	},
	{
		offsetof(ngx_http_secure_token_loc_conf_t, content_type_f4m), 
		(ngx_http_secure_token_body_processor_t)ngx_http_secure_token_xml_processor, 
		offsetof(ngx_http_secure_token_ctx_t, u.xml), 
		&f4m_nodes 
	},
};

// misc constants
static ngx_str_t token_prefixes[TOKEN_PREFIX_COUNT] = {
	ngx_string(""),
	ngx_string("?"),
	ngx_string("&"),
};

static u_char scheme_delimeter[] = "://";

// globals
static ngx_http_output_body_filter_pt ngx_http_next_body_filter;

ngx_chain_t**
ngx_http_secure_token_add_to_chain(
	ngx_pool_t* pool, 
	u_char* start, 
	u_char* end, 
	ngx_flag_t memory, 
	ngx_flag_t last_buf, 
	ngx_chain_t** out)
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
		ctx->prefixed_tokens[index].data = ngx_pnalloc(pool, token_prefixes[index].len + ctx->token.len);
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

static ngx_chain_t**
ngx_http_secure_token_add_token(
	ngx_http_secure_token_ctx_t* ctx, 
	ngx_pool_t* pool,
	ngx_flag_t has_query,
	u_char last_url_char,
	ngx_chain_t** out)
{
	ngx_chain_t* cl;
	int token_prefix;

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

ngx_chain_t**
ngx_http_secure_token_url_state_machine(
	ngx_http_request_t* r,
	ngx_http_secure_token_processor_conf_t* conf,
	ngx_http_secure_token_ctx_t* root_ctx,
	ngx_http_secure_token_base_ctx_t* ctx,
	u_char* buffer_end,
	u_char** cur_pos,
	u_char** last_sent,
	ngx_chain_t** out)
{
	ngx_str_t encrypted_uri;
	ngx_int_t rc;
	u_char* new_uri_path;
	u_char ch;

	for (; (*cur_pos) < buffer_end; (*cur_pos)++)
	{
		ch = **cur_pos;

		if (ch == ctx->url_end_char || (isspace(ch) && ctx->url_end_char == 0))
		{
			// end of url
			if (conf->encrypt_uri && ctx->state == STATE_URL_PATH)
			{
				rc = ngx_http_secure_token_encrypt_uri(r, &ctx->uri_path, &encrypted_uri);
				if (rc != NGX_OK)
				{
					return NULL;
				}

				out = ngx_http_secure_token_add_to_chain(r->pool, encrypted_uri.data, encrypted_uri.data + encrypted_uri.len, 1, 0, out);
				if (out == NULL)
				{
					return NULL;
				}
			}

			if (ctx->tokenize && root_ctx->token.len != 0)
			{
				if (*cur_pos > *last_sent)
				{
					// todo: copy memory/temporary/mmap from original buffer
					out = ngx_http_secure_token_add_to_chain(r->pool, *last_sent, *cur_pos, 1, 0, out);
					if (out == NULL)
					{
						return NULL;
					}

					*last_sent = *cur_pos;
				}

				out = ngx_http_secure_token_add_token(
					root_ctx, r->pool, ctx->state == STATE_URL_QUERY, ctx->last_url_char, out);
				if (out == NULL)
				{
					return NULL;
				}
			}

			ctx->last_url_char = ch;
			ctx->state = ctx->url_end_state;
			return out;
		}

		switch (ctx->state)
		{
		case STATE_URL_SCHEME:
			if (ch == scheme_delimeter[ctx->scheme_pos])
			{
				ctx->scheme_pos++;
				if (ctx->scheme_pos >= sizeof(scheme_delimeter) - 1)
				{
					ctx->state = STATE_URL_HOST;
				}
			}
			else
			{
				ctx->scheme_pos = 0;
			}
			break;

		case STATE_URL_HOST:
			if (ch != '/')
			{
				break;
			}

			ctx->state = STATE_URL_PATH;
			ctx->uri_path.len = 0;
			ctx->last_url_char = ch;

			if (conf->encrypt_uri && *cur_pos > *last_sent)
			{
				out = ngx_http_secure_token_add_to_chain(r->pool, *last_sent, *cur_pos, 1, 0, out);
				if (out == NULL)
				{
					return NULL;
				}

				*last_sent = *cur_pos;
			}
			// fallthrough

		case STATE_URL_PATH:
			ctx->last_url_char = ch;

			if (ch != '?')
			{
				if (conf->encrypt_uri)
				{
					if (ctx->uri_path.len >= ctx->uri_path_alloc_size)
					{
						ctx->uri_path_alloc_size = ngx_max(ctx->uri_path_alloc_size * 2, 1024);

						new_uri_path = ngx_pnalloc(r->pool, ctx->uri_path_alloc_size);
						if (new_uri_path == NULL)
						{
							return NULL;
						}

						ngx_memcpy(new_uri_path, ctx->uri_path.data, ctx->uri_path.len);
						ctx->uri_path.data = new_uri_path;
					}

					ctx->uri_path.data[ctx->uri_path.len] = ch;
					ctx->uri_path.len++;

					(*last_sent)++;		// dont output this char
				}
				break;
			}

			ctx->state = STATE_URL_QUERY;

			if (conf->encrypt_uri)
			{
				rc = ngx_http_secure_token_encrypt_uri(r, &ctx->uri_path, &encrypted_uri);
				if (rc != NGX_OK)
				{
					return NULL;
				}

				out = ngx_http_secure_token_add_to_chain(r->pool, encrypted_uri.data, encrypted_uri.data + encrypted_uri.len, 1, 0, out);
				if (out == NULL)
				{
					return NULL;
				}
			}
			break;

		case STATE_URL_QUERY:
			ctx->last_url_char = ch;
			break;
		}
	}

	return out;
}

static ngx_int_t
ngx_http_secure_token_body_filter(ngx_http_request_t *r, ngx_chain_t *in)
{
	ngx_http_secure_token_loc_conf_t *conf;
	ngx_http_secure_token_ctx_t* ctx;
	ngx_chain_t** cur_out;
	ngx_chain_t* out;
	ngx_flag_t last_buf;

	ctx = ngx_http_get_module_ctx(r, ngx_http_secure_token_filter_module);

	if (ctx == NULL || in == NULL)
	{
		return ngx_http_next_body_filter(r, in);
	}

	conf = ngx_http_get_module_loc_conf(r, ngx_http_secure_token_filter_module);

	cur_out = &out;
	last_buf = 0;

	for (; in != NULL; in = in->next)
	{
		if (in->buf == NULL)
		{
			continue;
		}

		last_buf |= in->buf->last_buf;

		cur_out = ctx->process(
			r,
			&conf->processor_conf,
			ctx->processor_params,
			in->buf,
			ctx,
			(u_char*)ctx + ctx->processor_context_offset,
			cur_out);
		if (cur_out == NULL)
		{
			return NGX_ERROR;
		}
	}

	if (last_buf)
	{
		cur_out = ngx_http_secure_token_add_to_chain(r->pool, NULL, NULL, 0, 1, cur_out);
		if (cur_out == NULL)
		{
			return NGX_ERROR;
		}
	}

	*cur_out = NULL;

	return ngx_http_next_body_filter(r, out);
}

ngx_int_t
ngx_http_secure_token_init_processors_hash(ngx_conf_t *cf, ngx_http_secure_token_loc_conf_t* conf)
{
	ngx_hash_key_t hash_keys[sizeof(body_processors) / sizeof(body_processors[0])];
	ngx_hash_init_t hash;
	ngx_str_t* content_type;
	ngx_int_t rc;
	unsigned i;

	for (i = 0; i < sizeof(hash_keys) / sizeof(hash_keys[0]); i++)
	{
		content_type = (ngx_str_t*)((u_char*)conf + body_processors[i].content_type_offset);
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

ngx_int_t
ngx_http_secure_token_init_body_filter(ngx_http_request_t *r, ngx_str_t* token)
{
	ngx_http_secure_token_loc_conf_t *conf;
	ngx_http_secure_token_ctx_t* ctx;
	body_processor_t* processor;

	conf = ngx_http_get_module_loc_conf(r, ngx_http_secure_token_filter_module);

	// Note: content_type_lowcase is already initialized since we called ngx_http_test_content_type
	processor = ngx_hash_find(&conf->processors_hash, r->headers_out.content_type_hash, r->headers_out.content_type_lowcase, r->headers_out.content_type_len);
	if (processor == NULL)
	{
		return NGX_DONE;
	}

	// add the token to all the URLs in the response
	ctx = ngx_pcalloc(r->pool, sizeof(*ctx));
	if (ctx == NULL)
	{
		return NGX_ERROR;
	}

	ctx->token = *token;
	ctx->process = processor->process;
	ctx->processor_context_offset = processor->processor_context_offset;
	ctx->processor_params = processor->processor_params;

	ngx_http_set_ctx(r, ctx, ngx_http_secure_token_filter_module);

	r->filter_need_in_memory = 1;

	ngx_http_clear_content_length(r);
	ngx_http_clear_accept_ranges(r);
	ngx_http_clear_etag(r);

	return NGX_OK;
}

void 
ngx_http_secure_token_install_body_filter()
{
	ngx_http_next_body_filter = ngx_http_top_body_filter;
	ngx_http_top_body_filter = ngx_http_secure_token_body_filter;	
}
