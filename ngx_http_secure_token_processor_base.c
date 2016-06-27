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
	ngx_chain_t* out;
	ngx_chain_t** last_out;
	ngx_chain_t* busy;
	ngx_chain_t* free;

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
	{ ngx_string("BaseURL"), NULL },
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

ngx_int_t
ngx_http_secure_token_url_state_machine(
	ngx_http_request_t* r,
	ngx_http_secure_token_processor_conf_t* conf,
	ngx_http_secure_token_base_ctx_t* ctx,
	u_char** cur_pos,
	u_char* buffer_end,
	ngx_http_secure_token_processor_output_t* output)
{
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
				output->copy_input = 0;

				rc = ngx_http_secure_token_encrypt_uri(r, &ctx->uri_path, &output->output_buffer);
				if (rc != NGX_OK)
				{
					return NGX_ERROR;
				}
			}

			if (ctx->tokenize)
			{
				if (ctx->state == STATE_URL_QUERY)
				{
					if (ctx->last_url_char == '?' || ctx->last_url_char == '&')
					{
						output->token_index = TOKEN_PREFIX_NONE;
					}
					else
					{
						output->token_index = TOKEN_PREFIX_AMPERSAND;
					}
				}
				else
				{
					output->token_index = TOKEN_PREFIX_QUESTION;
				}
			}

			ctx->last_url_char = ch;
			ctx->state = ctx->url_end_state;
			
			return NGX_OK;
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

			if (conf->encrypt_uri)
			{
				// flush any buffered data before starting to process the encrypted part
				return NGX_OK;
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
							return NGX_ERROR;
						}

						ngx_memcpy(new_uri_path, ctx->uri_path.data, ctx->uri_path.len);
						ctx->uri_path.data = new_uri_path;
					}

					ctx->uri_path.data[ctx->uri_path.len] = ch;
					ctx->uri_path.len++;

					output->copy_input = 0;
				}
				break;
			}

			ctx->state = STATE_URL_QUERY;

			if (conf->encrypt_uri)
			{
				return ngx_http_secure_token_encrypt_uri(r, &ctx->uri_path, &output->output_buffer);
			}
			break;

		case STATE_URL_QUERY:
			ctx->last_url_char = ch;
			break;
		}
	}

	return NGX_OK;
}

static ngx_int_t
ngx_http_secure_token_get_token_buffer(
	ngx_http_request_t *r, 
	ngx_http_secure_token_ctx_t* ctx, 
	ngx_buf_t* b,
	int token_index)
{
	u_char* p;

	if (ctx->prefixed_tokens[token_index].len == 0)
	{
		ctx->prefixed_tokens[token_index].data = ngx_pnalloc(r->pool, token_prefixes[token_index].len + ctx->token.len);
		if (ctx->prefixed_tokens[token_index].data == NULL)
		{
			return NGX_ERROR;
		}

		p = ngx_copy(ctx->prefixed_tokens[token_index].data, token_prefixes[token_index].data, token_prefixes[token_index].len);
		p = ngx_copy(p, ctx->token.data, ctx->token.len);

		ctx->prefixed_tokens[token_index].len = p - ctx->prefixed_tokens[token_index].data;
	}

	ngx_memzero(b, sizeof(ngx_buf_t));

	b->memory = 1;
	b->pos = ctx->prefixed_tokens[token_index].data;
	b->last = ctx->prefixed_tokens[token_index].data + ctx->prefixed_tokens[token_index].len;

	return NGX_OK;
}

// A slightly simplified version of ngx_http_sub_output
static ngx_int_t
ngx_http_secure_token_output(ngx_http_request_t *r, ngx_http_secure_token_ctx_t *ctx)
{
	ngx_int_t rc;
	ngx_buf_t *b;
	ngx_chain_t *cl;

#if 1
	b = NULL;
	for (cl = ctx->out; cl; cl = cl->next) {
		ngx_log_debug2(NGX_LOG_DEBUG_HTTP, r->connection->log, 0,
			"secure token out: %p %p", cl->buf, cl->buf->pos);
		if (cl->buf == b) {
			ngx_log_error(NGX_LOG_ALERT, r->connection->log, 0,
				"the same buf was used in secure token");
			ngx_debug_point();
			return NGX_ERROR;
		}
		b = cl->buf;
	}
#endif

	rc = ngx_http_next_body_filter(r, ctx->out);

	if (ctx->busy == NULL) {
		ctx->busy = ctx->out;

	}
	else {
		for (cl = ctx->busy; cl->next; cl = cl->next) { /* void */ }
		cl->next = ctx->out;
	}

	ctx->out = NULL;
	ctx->last_out = &ctx->out;

	while (ctx->busy) {

		cl = ctx->busy;
		b = cl->buf;

		if (ngx_buf_size(b) != 0) {
			break;
		}

		if (b->shadow) {
			b->shadow->pos = b->shadow->last;
		}

		ctx->busy = cl->next;

		if (ngx_buf_in_memory(b) || b->in_file) {
			/* add data bufs only to the free buf chain */

			cl->next = ctx->free;
			ctx->free = cl;
		}
	}

	return rc;
}

// the implementation is based on ngx_http_sub_body_filter
static ngx_int_t
ngx_http_secure_token_body_filter(ngx_http_request_t *r, ngx_chain_t *in)
{
	ngx_http_secure_token_processor_output_t output;
	ngx_http_secure_token_loc_conf_t *conf;
	ngx_http_secure_token_ctx_t* ctx;
	ngx_chain_t* in_copy = NULL;
	ngx_chain_t* cl;
	ngx_buf_t* buf;
	ngx_buf_t* b;
	ngx_int_t rc;
	u_char* copy_start;
	u_char* pos = NULL;

	ctx = ngx_http_get_module_ctx(r, ngx_http_secure_token_filter_module);

	if (ctx == NULL) {
		return ngx_http_next_body_filter(r, in);
	}

	if ((in == NULL
		&& ctx->busy == NULL))
	{
		return ngx_http_next_body_filter(r, in);
	}

	conf = ngx_http_get_module_loc_conf(r, ngx_http_secure_token_filter_module);

	/* add the incoming chain to the chain in_copy */

	if (in) {
		if (ngx_chain_add_copy(r->pool, &in_copy, in) != NGX_OK) {
			return NGX_ERROR;
		}
	}

	ngx_log_debug1(NGX_LOG_DEBUG_HTTP, r->connection->log, 0,
		"http secure token filter \"%V\"", &r->uri);

	buf = NULL;

	while (in_copy || buf) {

		if (buf == NULL) {
			buf = in_copy->buf;
			in_copy = in_copy->next;
			pos = buf->pos;
		}

		b = NULL;

		while (pos < buf->last) {

			copy_start = pos;

			output.copy_input = 1;
			output.output_buffer.len = 0;
			output.token_index = -1;

			rc = ctx->process(
				r,
				&conf->processor_conf,
				ctx->processor_params,
				&pos, 
				buf->last,
				(u_char*)ctx + ctx->processor_context_offset, 
				&output);

			ngx_log_debug3(NGX_LOG_DEBUG_HTTP, r->connection->log, 0,
				"process: %d, %p-%p",
				rc, copy_start, pos);

			if (rc == NGX_ERROR) {
				return rc;
			}

			if (output.copy_input && copy_start != pos) {

				cl = ngx_chain_get_free_buf(r->pool, &ctx->free);
				if (cl == NULL) {
					return NGX_ERROR;
				}

				b = cl->buf;

				ngx_memcpy(b, buf, sizeof(ngx_buf_t));

				b->pos = copy_start;
				b->last = pos;
				b->shadow = NULL;
				b->last_buf = 0;
				b->last_in_chain = 0;
				b->recycled = 0;

				if (b->in_file) {
					b->file_last = b->file_pos + (b->last - buf->pos);
					b->file_pos += b->pos - buf->pos;
				}

				*ctx->last_out = cl;
				ctx->last_out = &cl->next;
			}

			if (output.output_buffer.len != 0)
			{
				cl = ngx_chain_get_free_buf(r->pool, &ctx->free);
				if (cl == NULL) {
					return NGX_ERROR;
				}

				b = cl->buf;

				ngx_memzero(b, sizeof(ngx_buf_t));

				b->memory = 1;
				b->pos = output.output_buffer.data;
				b->last = output.output_buffer.data + output.output_buffer.len;

				*ctx->last_out = cl;
				ctx->last_out = &cl->next;
			}

			if (output.token_index >= 0 && ctx->token.len != 0)
			{
				cl = ngx_chain_get_free_buf(r->pool, &ctx->free);
				if (cl == NULL) {
					return NGX_ERROR;
				}

				b = cl->buf;

				rc = ngx_http_secure_token_get_token_buffer(r, ctx, b, output.token_index);
				if (rc != NGX_OK)
				{
					return rc;
				}

				*ctx->last_out = cl;
				ctx->last_out = &cl->next;
			}

			continue;
		}

		if (buf->last_buf || buf->flush || buf->sync
			|| ngx_buf_in_memory(buf))
		{
			if (b == NULL) {
				cl = ngx_chain_get_free_buf(r->pool, &ctx->free);
				if (cl == NULL) {
					return NGX_ERROR;
				}

				b = cl->buf;

				ngx_memzero(b, sizeof(ngx_buf_t));

				b->sync = 1;

				*ctx->last_out = cl;
				ctx->last_out = &cl->next;
			}

			b->last_buf = buf->last_buf;
			b->last_in_chain = buf->last_in_chain;
			b->flush = buf->flush;
			b->shadow = buf;

			b->recycled = buf->recycled;
		}

		buf = NULL;
	}

	if (ctx->out == NULL && ctx->busy == NULL) {
		return NGX_OK;
	}

	return ngx_http_secure_token_output(r, ctx);
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

	ctx->last_out = &ctx->out;

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
