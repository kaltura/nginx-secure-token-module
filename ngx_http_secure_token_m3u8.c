#include "ngx_http_secure_token_encrypt_uri.h"
#include "ngx_http_secure_token_m3u8.h"

static u_char encryption_key_tag[] = "EXT-X-KEY";
static u_char ext_media_tag[] = "EXT-X-MEDIA";
static u_char ext_i_frame_tag[] = "EXT-X-I-FRAME-STREAM-INF";
static u_char uri_attr_name[] = "URI";

enum {
	STATE_TAG_NAME = STATE_URL_LAST,
	STATE_ATTR_NAME,
	STATE_ATTR_VALUE,
	STATE_ATTR_QUOTED_VALUE,
	STATE_ATTR_WAIT_DELIM,
	STATE_WAIT_NEWLINE,
};


// The example below shows the trasitions between the different states (numbers represent the state value):
// #EXT-X-KEY:METHOD=AES-128,URI="encryption.key"
// 1         2      36      2   34              6

ngx_int_t
ngx_http_secure_token_m3u8_processor(
	ngx_http_request_t* r,
	ngx_http_secure_token_processor_conf_t* conf,
	void* params,
	u_char** pos,
	u_char* buffer_end,
	ngx_http_secure_token_m3u8_ctx_t* ctx,
	ngx_http_secure_token_processor_output_t* output)
{
	ngx_int_t rc;
	u_char* cur_pos;
	u_char ch;

	for (cur_pos = *pos; cur_pos < buffer_end; cur_pos++)
	{
		ch = *cur_pos;

		switch (ctx->base.state)
		{
		case STATE_INITIAL:
			if (ch == '#')
			{
				ctx->base.state = STATE_TAG_NAME;
				ctx->tag_name_len = 0;
			}
			else if (!isspace(ch))
			{
				if (conf->tokenize_segments || conf->encrypt_uri)
				{
					ngx_http_secure_token_url_state_machine_init(
						&ctx->base,
						conf->tokenize_segments,
						STATE_WAIT_NEWLINE,
						0);

					cur_pos--;		// push the current char to the url state machine
				}
				else
				{
					ctx->base.state = STATE_WAIT_NEWLINE;
				}
			}
			break;

		case STATE_TAG_NAME:
			if (ch == ':')
			{
				ctx->base.state = STATE_ATTR_NAME;
				ctx->attr_name_len = 0;
			}
			else if (ch == '\n')
			{
				ctx->base.state = STATE_INITIAL;
			}
			else if (ctx->tag_name_len < M3U8_MAX_TAG_NAME_LEN)
			{
				ctx->tag_name[ctx->tag_name_len] = ch;
				ctx->tag_name_len++;
			}
			break;

		case STATE_ATTR_NAME:
			if (ch == '=')
			{
				ctx->base.state = STATE_ATTR_VALUE;
			}
			else if (ch == '\n')
			{
				ctx->base.state = STATE_INITIAL;
			}
			else if (ctx->attr_name_len < M3U8_MAX_ATTR_NAME_LEN)
			{
				ctx->attr_name[ctx->attr_name_len] = ch;
				ctx->attr_name_len++;
			}
			break;

		case STATE_ATTR_VALUE:
			if (ch == '"')
			{
				if (ctx->attr_name_len == sizeof(uri_attr_name) - 1 &&
					ngx_memcmp(ctx->attr_name, uri_attr_name, sizeof(uri_attr_name) - 1) == 0)
				{
					if ((ctx->tag_name_len == sizeof(encryption_key_tag) - 1 &&
						ngx_memcmp(ctx->tag_name, encryption_key_tag, sizeof(encryption_key_tag) - 1) == 0) ||
						(ctx->tag_name_len == sizeof(ext_media_tag) - 1 &&
						ngx_memcmp(ctx->tag_name, ext_media_tag, sizeof(ext_media_tag) - 1) == 0) ||
						(ctx->tag_name_len == sizeof(ext_i_frame_tag) - 1 &&
						ngx_memcmp(ctx->tag_name, ext_i_frame_tag, sizeof(ext_i_frame_tag) - 1) == 0))
					{
						ngx_http_secure_token_url_state_machine_init(
							&ctx->base,
							1,
							STATE_ATTR_WAIT_DELIM,
							'"');
						break;
					}
				}
				ctx->base.state = STATE_ATTR_QUOTED_VALUE;
			}
			else if (ch == ',')
			{
				ctx->base.state = STATE_ATTR_NAME;
				ctx->attr_name_len = 0;
			}
			else if (ch == '\n')
			{
				ctx->base.state = STATE_INITIAL;
			}
			else
			{
				// dont care about unquoted attribute values
				ctx->base.state = STATE_ATTR_WAIT_DELIM;
			}
			break;

		case STATE_ATTR_QUOTED_VALUE:
			if (ch == '"')
			{
				ctx->base.state = STATE_ATTR_WAIT_DELIM;
			}
			else if (ch == '\n')
			{
				ctx->base.state = STATE_INITIAL;
			}
			break;

		case STATE_ATTR_WAIT_DELIM:
			if (ch == ',')
			{
				ctx->base.state = STATE_ATTR_NAME;
				ctx->attr_name_len = 0;
			}
			else if (ch == '\n')
			{
				ctx->base.state = STATE_INITIAL;
			}
			break;

		case STATE_WAIT_NEWLINE:
			if (ch == '\n')
			{
				ctx->base.state = STATE_INITIAL;
			}
			break;

		default:
			*pos = cur_pos;
			rc = ngx_http_secure_token_url_state_machine(
				r,
				conf,
				&ctx->base,
				pos,
				buffer_end,
				output);

			if (ctx->base.last_url_char == '\n')
			{
				ctx->base.state = STATE_INITIAL;
			}

			return rc;
		}
	}

	*pos = cur_pos;
	return NGX_OK;
}
