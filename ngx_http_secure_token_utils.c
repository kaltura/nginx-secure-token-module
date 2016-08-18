#include "ngx_http_secure_token_utils.h"

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

ngx_int_t
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
