#include "ngx_http_secure_token_xml.h"

enum {
	STATE_TAG_NAME = STATE_URL_LAST,
	STATE_CLOSING_TAG_NAME,
	STATE_ATTR_NAME,
	STATE_ATTR_VALUE,
	STATE_ATTR_VALUE_END,
	STATE_ATTR_QUOTED_VALUE,
};

static ngx_flag_t
ngx_http_secure_token_xml_is_relevant_attr(
	ngx_http_secure_token_xml_ctx_t* ctx,
	ngx_http_secure_token_xml_node_attrs_t* nodes,
	size_t attr_name_len)
{
	ngx_http_secure_token_xml_node_attrs_t* cur_node;
	ngx_str_t* cur_attr;

	for (cur_node = nodes; cur_node->tag_name.len != 0; cur_node++)
	{
		if (ctx->tag_name_len != cur_node->tag_name.len ||
			ngx_strncasecmp(ctx->tag_name, cur_node->tag_name.data, cur_node->tag_name.len) != 0)
		{
			continue;
		}

		if (cur_node->attr_names == NULL)
		{
			if (attr_name_len != 0)
			{
				continue;
			}

			return 1;
		}

		if (attr_name_len == 0)
		{
			continue;
		}

		for (cur_attr = cur_node->attr_names; cur_attr->len != 0; cur_attr++)
		{
			if (attr_name_len != cur_attr->len ||
				ngx_strncasecmp(ctx->attr_name, cur_attr->data, cur_attr->len) != 0)
			{
				continue;
			}

			return 1;
		}
	}

	return 0;
}

ngx_int_t
ngx_http_secure_token_xml_processor(
	ngx_http_request_t* r,
	ngx_http_secure_token_processor_conf_t* conf,
	ngx_http_secure_token_xml_node_attrs_t* nodes,
	u_char** pos,
	u_char* buffer_end,
	ngx_http_secure_token_xml_ctx_t* ctx,
	ngx_http_secure_token_processor_output_t* output)
{
	u_char* cur_pos = *pos;
	u_char ch;

	for (cur_pos = *pos; cur_pos < buffer_end; cur_pos++)
	{
		ch = *cur_pos;

		switch (ctx->base.state)
		{
		case STATE_INITIAL:
			if (ch == '<')
			{
				ctx->base.state = STATE_TAG_NAME;
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
				ctx->base.state = STATE_ATTR_NAME;
				ctx->attr_name_len = 0;
			}
			else if (ch == '>')
			{
				if (ctx->base.state == STATE_TAG_NAME && 
					ngx_http_secure_token_xml_is_relevant_attr(ctx, nodes, 0))
				{
					ngx_http_secure_token_url_state_machine_init(
						&ctx->base,
						1,
						STATE_INITIAL,
						'<');
					break;
				}

				ctx->base.state = STATE_INITIAL;
			}
			else if (ch == '/' && ctx->tag_name_len == 0)
			{
				ctx->base.state = STATE_CLOSING_TAG_NAME;
			}
			else if (ctx->tag_name_len < XML_MAX_TAG_NAME_LEN)
			{
				ctx->tag_name[ctx->tag_name_len] = ch;
				ctx->tag_name_len++;
			}
			break;

		case STATE_ATTR_VALUE_END:		// ignore the " char, and move back to attribute name state
			ctx->base.state = STATE_ATTR_NAME;
			break;

		case STATE_ATTR_NAME:
			if (isspace(ch))
			{
				break;
			}
			if (ch == '=')
			{
				ctx->base.state = STATE_ATTR_VALUE;
			}
			else if (ch == '>')
			{
				if (ngx_http_secure_token_xml_is_relevant_attr(ctx, nodes, 0))
				{
					ngx_http_secure_token_url_state_machine_init(
						&ctx->base,
						1,
						STATE_INITIAL,
						'<');
					break;
				}

				ctx->base.state = STATE_INITIAL;
			}
			else if (ctx->attr_name_len < XML_MAX_ATTR_NAME_LEN)
			{
				ctx->attr_name[ctx->attr_name_len] = ch;
				ctx->attr_name_len++;
			}
			break;

		case STATE_ATTR_VALUE:
			if (ch == '"')
			{
				if (ngx_http_secure_token_xml_is_relevant_attr(ctx, nodes, ctx->attr_name_len))
				{
					ngx_http_secure_token_url_state_machine_init(
						&ctx->base,
						1,
						STATE_ATTR_VALUE_END,
						'"');
					ctx->attr_name_len = 0;
					break;
				}

				ctx->base.state = STATE_ATTR_QUOTED_VALUE;
			}
			break;

		case STATE_ATTR_QUOTED_VALUE:
			if (ch != '"')
			{
				break;
			}

			ctx->base.state = STATE_ATTR_NAME;
			ctx->attr_name_len = 0;
			break;

		default:
			*pos = cur_pos;
			return ngx_http_secure_token_url_state_machine(
				r,
				conf,
				&ctx->base,
				pos,
				buffer_end,
				output);
		}
	}

	*pos = cur_pos;
	return NGX_OK;
}
