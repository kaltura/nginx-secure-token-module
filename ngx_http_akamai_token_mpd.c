#include "ngx_http_akamai_token_mpd.h"

static u_char segment_template_tag[] = "SegmentTemplate";
static u_char media_attr_name[] = "media";
static u_char init_attr_name[] = "initialization";

enum {
	STATE_INITIAL,
	STATE_TAG_NAME,
	STATE_CLOSING_TAG_NAME,
	STATE_ATTR_NAME,
	STATE_ATTR_VALUE,
	STATE_ATTR_QUOTED_VALUE,
	STATE_ATTR_QUOTED_VALUE_WITH_QUERY,
};

ngx_chain_t** 
ngx_http_akamai_token_mpd_processor(
	ngx_buf_t *in, 
	ngx_http_akamai_token_ctx_t* root_ctx,
	ngx_http_akamai_token_mpd_ctx_t* ctx, 
	ngx_pool_t* pool, 
	ngx_chain_t** out)
{
	u_char* last_sent;
	u_char* cur_pos;
	u_char* buffer_end;
	u_char ch;

	last_sent = in->pos;
	buffer_end = in->last;
	for (cur_pos = in->pos; cur_pos < buffer_end; cur_pos++)
	{
		ch = *cur_pos;

		switch (ctx->state)
		{
		case STATE_INITIAL:
			if (ch == '<')
			{
				ctx->state = STATE_TAG_NAME;
				ctx->tag_name_len = 0;
			}
			break;

		case STATE_TAG_NAME:
		case STATE_CLOSING_TAG_NAME:
			if (isspace(ch))
			{
				if (ctx->tag_name_len == 0)
				{
					break;
				}
				ctx->state = STATE_ATTR_NAME;
				ctx->attr_name_len = 0;
			}
			else if (ch == '>')
			{
				ctx->state = STATE_INITIAL;
			}
			else if (ch == '/' && ctx->tag_name_len == 0)
			{
				ctx->state = STATE_CLOSING_TAG_NAME;
			}
			else if (ctx->tag_name_len < MPD_MAX_TAG_NAME_LEN)
			{
				ctx->tag_name[ctx->tag_name_len] = ch;
				ctx->tag_name_len++;
			}
			break;

		case STATE_ATTR_NAME:
			if (isspace(ch))
			{
				break;
			}
			if (ch == '=')
			{
				ctx->state = STATE_ATTR_VALUE;
			}
			else if (ch == '>')
			{
				ctx->state = STATE_INITIAL;
			}
			else if (ctx->attr_name_len < MPD_MAX_ATTR_NAME_LEN)
			{
				ctx->attr_name[ctx->attr_name_len] = ch;
				ctx->attr_name_len++;
			}
			break;

		case STATE_ATTR_VALUE:
			if (ch == '"')
			{
				ctx->state = STATE_ATTR_QUOTED_VALUE;
				ctx->last_url_char = 0;
			}
			break;

		case STATE_ATTR_QUOTED_VALUE:
		case STATE_ATTR_QUOTED_VALUE_WITH_QUERY:
			if (ch != '"')
			{
				ctx->last_url_char = ch;
				if (ch == '?')
				{
					ctx->state = STATE_ATTR_QUOTED_VALUE_WITH_QUERY;
				}
				break;
			}

			if (ctx->tag_name_len == sizeof(segment_template_tag) - 1 &&
				ngx_memcmp(ctx->tag_name, segment_template_tag, sizeof(segment_template_tag) - 1) == 0 &&
				((ctx->attr_name_len == sizeof(media_attr_name) - 1 &&
				ngx_memcmp(ctx->attr_name, media_attr_name, sizeof(media_attr_name) - 1) == 0) ||
				(ctx->attr_name_len == sizeof(init_attr_name) - 1 &&
				ngx_memcmp(ctx->attr_name, init_attr_name, sizeof(init_attr_name) - 1) == 0)))
			{
				out = ngx_http_akamai_token_add_token(
					root_ctx, pool, &last_sent, cur_pos, ctx->state == STATE_ATTR_QUOTED_VALUE_WITH_QUERY, ctx->last_url_char, out);
				if (out == NULL)
				{
					return NULL;
				}
			}

			ctx->state = STATE_ATTR_NAME;
			ctx->attr_name_len = 0;
			break;
		}
	}

	if (cur_pos > last_sent)
	{
		out = ngx_http_akamai_token_add_to_chain(pool, out, last_sent, cur_pos, 1, 0);
		if (out == NULL)
		{
			return NULL;
		}
	}

	return out;
}
