#include "ngx_http_secure_token_broadpeak.h"
#include "../ngx_http_secure_token_filter_module.h"
#include "../ngx_http_secure_token_utils.h"
#include <ngx_md5.h>


// typedefs
typedef struct {
	ngx_http_complex_value_t* acl;
	ngx_http_complex_value_t* key;
	ngx_str_t param_name;
	ngx_secure_token_time_t start;
	ngx_secure_token_time_t end;
	ngx_http_complex_value_t* session_start;
	ngx_http_complex_value_t* session_end;
	ngx_http_complex_value_t* additional_querylist;
} ngx_secure_token_broadpeak_token_t;


// globals
static ngx_command_t ngx_http_secure_token_broadpeak_cmds[] = {
	{ ngx_string("acl"),
	NGX_CONF_TAKE1,
	ngx_http_set_complex_value_slot,
	0,
	offsetof(ngx_secure_token_broadpeak_token_t, acl),
	NULL },

	{ ngx_string("key"),
	NGX_CONF_TAKE1,
	ngx_http_set_complex_value_slot,
	0,
	offsetof(ngx_secure_token_broadpeak_token_t, key),
	NULL },

	{ ngx_string("param_name"),
	NGX_CONF_TAKE1,
	ngx_conf_set_str_slot,
	0,
	offsetof(ngx_secure_token_broadpeak_token_t, param_name),
	NULL },

	{ ngx_string("start"),
	NGX_CONF_TAKE1,
	ngx_http_secure_token_conf_set_time_slot,
	0,
	offsetof(ngx_secure_token_broadpeak_token_t, start),
	NULL },

	{ ngx_string("end"),
	NGX_CONF_TAKE1,
	ngx_http_secure_token_conf_set_time_slot,
	0,
	offsetof(ngx_secure_token_broadpeak_token_t, end),
	NULL },

	{ ngx_string("session_start"),
	NGX_CONF_TAKE1,
	ngx_http_set_complex_value_slot,
	0,
	offsetof(ngx_secure_token_broadpeak_token_t, session_start),
	NULL },

	{ ngx_string("session_end"),
	NGX_CONF_TAKE1,
	ngx_http_set_complex_value_slot,
	0,
	offsetof(ngx_secure_token_broadpeak_token_t, session_end),
	NULL },

	{ ngx_string("additional_querylist"),
	NGX_CONF_TAKE1,
	ngx_http_set_complex_value_slot,
	0,
	offsetof(ngx_secure_token_broadpeak_token_t, additional_querylist),
	NULL },
};


static uint64_t
ngx_secure_token_broadpeak_scramble(uint64_t se)
{
	return
		(((se & 0x0800000000000000) >> 53) |
		 ((se & 0x2400000000000000) >> 50) |
		 ((se & 0x0000600000000000) >> 44) |
		 ((se & 0x0000800000000000) >> 43) |
		 ((se & 0x0020000000000000) >> 41) |
		 ((se & 0x0000100000000000) >> 30) |
		 ((se & 0x0000004000000000) >> 28) |
		 ((se & 0x0042000000000000) >> 26) |
		 ((se & 0x0000000002000000) >> 25) |
		 ((se & 0x0000000020000000) >> 24) |
		 ((se & 0x0004009000000000) >> 23) |
		 ((se & 0x1000000000000000) >> 21) |
		 ((se & 0x0010000000000000) >> 20) |
		 ((se & 0x0100000000000000) >> 18) |
		 ((se & 0x0080000400000000) >> 14) |
		 ((se & 0x8000000000000000) >> 13) |
		 ((se & 0x0000000000002000) >> 10) |
		 ((se & 0x0000000010000000) >>  7) |
		 ((se & 0x0000010000000000) >>  6) |
		 ((se & 0x4000002000000000) >>  4) |
		 ((se & 0x0000000000001000) >>  3) |
		 ((se & 0x0200000100000200) >>  2) |
		  (se & 0x0000000080020000)        |
		 ((se & 0x0001000000000000) <<  1) |
		 ((se & 0x0000000008000000) <<  2) |
		 ((se & 0x0000000000010000) <<  3) |
		 ((se & 0x0000080000100000) <<  5) |
		 ((se & 0x0008040000000000) << 10) |
		 ((se & 0x0000000001008000) << 11) |
		 ((se & 0x0000000000000008) << 12) |
		 ((se & 0x0000000000400000) << 15) |
		 ((se & 0x0000000040000000) << 16) |
		 ((se & 0x0000000000000002) << 17) |
		 ((se & 0x0000000000000050) << 18) |
		 ((se & 0x0000020200000000) << 21) |
		 ((se & 0x0000000000080000) << 23) |
		 ((se & 0x0000000000040000) << 25) |
		 ((se & 0x0000000000200000) << 26) |
		 ((se & 0x0000000800000000) << 28) |
		 ((se & 0x0000000000000080) << 29) |
		 ((se & 0x0000000000004000) << 30) |
		 ((se & 0x0000000004000000) << 33) |
		 ((se & 0x0000000000800800) << 34) |
		 ((se & 0x0000000000000001) << 40) |
		 ((se & 0x0000000000000100) << 43) |
		 ((se & 0x0000000000000400) << 50) |
		 ((se & 0x0000000000000024) << 51));
}


int64_t
ngx_atoll(u_char* line, size_t n)
{
	int64_t  value, cutoff, cutlim;

	if (n == 0) {
		return NGX_ERROR;
	}

	cutoff = LLONG_MAX / 10;
	cutlim = LLONG_MAX % 10;

	for (value = 0; n--; line++) {
		if (*line < '0' || *line > '9') {
			return NGX_ERROR;
		}

		if (value >= cutoff && (value > cutoff || *line - '0' > cutlim)) {
			return NGX_ERROR;
		}

		value = value * 10 + (*line - '0');
	}

	return value;
}


static time_t
ngx_secure_token_broadpeak_parse_time(ngx_pool_t* pool, ngx_str_t* ts)
{
	ngx_tm_t tm;
	int64_t n;
	char* fmt;
	char* s;

	switch (ts->len)
	{
	case 10:	/* unixtime */
		return ngx_atotm(ts->data, ts->len);

	case 13:	/* unixtime millis */
		n = ngx_atoll(ts->data, ts->len);
		if (n == NGX_ERROR) {
			return NGX_ERROR;
		}

		return n / 1000;

	case 15:
		fmt = "%Y%m%dT%H%M%S";
		break;

	case 16:
		if (ts->data[15] != 'Z') {
			/* unixtime micros */
			n = ngx_atoll(ts->data, ts->len);
			if (n == NGX_ERROR) {
				return NGX_ERROR;
			}

			return n / 1000000;
		}

		fmt = "%Y%m%dT%H%M%SZ";
		break;

	case 19:
		fmt = "%Y-%m-%dT%H:%M:%S";
		break;

	case 20:
		fmt = "%Y-%m-%dT%H:%M:%SZ";
		break;

	default:
		return NGX_ERROR;
	}

	s = ngx_pnalloc(pool, ts->len + 1);
	if (s == NULL) {
		return NGX_ERROR;
	}

	ngx_memcpy(s, ts->data, ts->len);
	s[ts->len] = '\0';

	if (strptime(s, fmt, &tm) != s + ts->len) {
		return NGX_ERROR;
	}

	tm.ngx_tm_isdst = -1;

	return timegm(&tm);
}


static time_t
ngx_secure_token_broadpeak_get_time(ngx_http_request_t* r, ngx_http_complex_value_t* val)
{
	ngx_str_t str;
	time_t res;

	if (val == NULL) {
		return 0;
	}

	if (ngx_http_complex_value(r, val, &str) != NGX_OK) {
		return NGX_ERROR;
	}

	if (str.len == 0) {
		return 0;
	}

	res = ngx_secure_token_broadpeak_parse_time(r->pool, &str);
	if (res == NGX_ERROR) {
		ngx_log_error(NGX_LOG_ERR, r->connection->log, 0,
			"ngx_secure_token_broadpeak_get_time: failed to parse \"%V\"", &str);
		return NGX_ERROR;
	}

	return res;
}


static ngx_int_t
ngx_secure_token_broadpeak_get_var(
	ngx_http_request_t* r,
	ngx_http_variable_value_t* v,
	uintptr_t data)
{
	ngx_secure_token_broadpeak_token_t* token = (void*)data;
	ngx_str_t additional_querylist;
	ngx_str_t acl;
	ngx_str_t key;
	ngx_md5_t md5;
	ngx_int_t rc;
	uint64_t start_end;
	size_t result_size;
	time_t session_start;
	time_t session_end;
	time_t start_time;
	time_t end_time;
	u_char md5hash_buf[MD5_DIGEST_LENGTH];
	u_char temp_buf[sizeof(uint64_t) * 2];
	u_char* p;

	// get the acl + key
	rc = ngx_http_secure_token_get_acl(r, token->acl, &acl);
	if (rc != NGX_OK)
	{
		return rc;
	}

	if (ngx_http_complex_value(r, token->key, &key) != NGX_OK)
	{
		return NGX_ERROR;
	}

	session_start = ngx_secure_token_broadpeak_get_time(r, token->session_start);
	if (session_start == NGX_ERROR)
	{
		return NGX_ERROR;
	}

	session_end = ngx_secure_token_broadpeak_get_time(r, token->session_end);
	if (session_end == NGX_ERROR)
	{
		return NGX_ERROR;
	}

	if (token->additional_querylist != NULL)
	{
		if (ngx_http_complex_value(r, token->additional_querylist, &additional_querylist) != NGX_OK)
		{
			return NGX_ERROR;
		}
	}
	else
	{
		additional_querylist.data = NULL;
		additional_querylist.len = 0;
	}

	// allocate the result
	result_size = token->param_name.len + sizeof(uint64_t) * 2 + sizeof(md5hash_buf) * 2 + sizeof("=_");

	p = ngx_pnalloc(r->pool, result_size);
	if (p == NULL)
	{
		return NGX_ERROR;
	}

	v->data = p;

	// get the start / end time (mandatory fields)
	start_time = token->start.val;
	if (token->start.type == NGX_HTTP_SECURE_TOKEN_TIME_RELATIVE)
	{
		start_time += ngx_time();
	}

	end_time = token->end.val;
	if (token->end.type == NGX_HTTP_SECURE_TOKEN_TIME_RELATIVE)
	{
		end_time += ngx_time();
	}

	start_end = ((uint64_t)start_time << 32) | (uint64_t)end_time;

	// calculate the signature
	ngx_md5_init(&md5);
	ngx_md5_update(&md5, key.data, key.len);
	ngx_md5_update(&md5, acl.data, acl.len);

	ngx_sprintf(temp_buf, "%016uxL", start_end);
	ngx_md5_update(&md5, temp_buf, sizeof(uint64_t) * 2);

	if (session_start != 0)
	{
		ngx_sprintf(temp_buf, "%08uxD", (uint32_t) session_start);
		ngx_md5_update(&md5, temp_buf, sizeof(uint32_t) * 2);
	}

	if (session_end != 0)
	{
		ngx_sprintf(temp_buf, "%08uxD", (uint32_t) session_end);
		ngx_md5_update(&md5, temp_buf, sizeof(uint32_t) * 2);
	}

	ngx_md5_update(&md5, additional_querylist.data, additional_querylist.len);

	ngx_md5_final(md5hash_buf, &md5);

	// build the result
	p = ngx_copy(p, token->param_name.data, token->param_name.len);
	*p++ = '=';
	p = ngx_sprintf(p, "%016uxL", ngx_secure_token_broadpeak_scramble(start_end));
	*p++ = '_';
	p = ngx_hex_dump(p, md5hash_buf, sizeof(md5hash_buf));
	*p = '\0';

	v->len = p - v->data;
	v->valid = 1;
	v->no_cacheable = 0;
	v->not_found = 0;

	return NGX_OK;
}

char *
ngx_secure_token_broadpeak_block(ngx_conf_t *cf, ngx_command_t *cmd, void *conf)
{
	ngx_secure_token_broadpeak_token_t* token;
	char* rv;

	// init config
	token = ngx_pcalloc(cf->pool, sizeof(*token));
	if (token == NULL)
	{
		return NGX_CONF_ERROR;
	}

	token->start.type = NGX_HTTP_SECURE_TOKEN_TIME_UNSET;
	token->end.type = NGX_HTTP_SECURE_TOKEN_TIME_UNSET;

	// parse the block
	rv = ngx_http_secure_token_conf_block(
		cf,
		ngx_http_secure_token_broadpeak_cmds,
		token,
		ngx_secure_token_broadpeak_get_var);
	if (rv != NGX_CONF_OK)
	{
		return rv;
	}

	// validate required params
	if (token->key == NULL)
	{
		ngx_conf_log_error(NGX_LOG_EMERG, cf, 0,
			"\"key\" is mandatory for broadpeak tokens");
		return NGX_CONF_ERROR;
	}

	if (token->acl == NULL)
	{
		ngx_conf_log_error(NGX_LOG_EMERG, cf, 0,
			"\"acl\" is mandatory for broadpeak tokens");
		return NGX_CONF_ERROR;
	}

	// populate unset optional params
	if (token->param_name.data == NULL)
	{
		ngx_str_set(&token->param_name, "token");
	}

	if (token->start.type == NGX_HTTP_SECURE_TOKEN_TIME_UNSET)
	{
		token->start.type = NGX_HTTP_SECURE_TOKEN_TIME_RELATIVE;
	}

	if (token->end.type == NGX_HTTP_SECURE_TOKEN_TIME_UNSET)
	{
		token->end.type = NGX_HTTP_SECURE_TOKEN_TIME_RELATIVE;
		token->end.val = 86400;
	}

	return NGX_CONF_OK;
}
