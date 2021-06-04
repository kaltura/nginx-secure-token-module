#ifndef _NGX_HTTP_SECURE_TOKEN_PROCESSOR_BASE_H_INCLUDED_
#define _NGX_HTTP_SECURE_TOKEN_PROCESSOR_BASE_H_INCLUDED_

// includes
#include <ngx_core.h>
#include "ngx_http_secure_token_conf.h"

#define MAX_SCHEME_LEN (10)

// enums
enum {
	STATE_INITIAL,

	STATE_URL_SCHEME,
	STATE_URL_NON_HTTP,
	STATE_URL_HOST,
	STATE_URL_PATH,
	STATE_URL_QUERY,

	STATE_URL_LAST,
};

// typedefs
struct ngx_http_secure_token_ctx_s;
typedef struct ngx_http_secure_token_ctx_s ngx_http_secure_token_ctx_t;

typedef struct {
	int url_end_state;
	u_char url_end_char;
	ngx_flag_t tokenize;

	int state;
	unsigned scheme_pos;
	u_char scheme[MAX_SCHEME_LEN];
	unsigned scheme_delim_pos;
	u_char last_url_char;
	size_t uri_path_alloc_size;
	ngx_str_t uri_path;
} ngx_http_secure_token_base_ctx_t;

typedef struct {
	ngx_flag_t copy_input;
	ngx_str_t output_buffer;
	int token_index;
} ngx_http_secure_token_processor_output_t;

typedef ngx_int_t (*ngx_http_secure_token_body_processor_t)(
	ngx_http_request_t* r,
	ngx_http_secure_token_processor_conf_t* conf,
	void* params,
	u_char** pos,
	u_char* last,
	void* ctx,
	ngx_http_secure_token_processor_output_t* output);

// processor utility functions

void ngx_http_secure_token_url_state_machine_init(
	ngx_http_secure_token_base_ctx_t* ctx,
	ngx_flag_t tokenize,
	int url_end_state,
	u_char url_end_char);

ngx_int_t ngx_http_secure_token_url_state_machine(
	ngx_http_request_t* r,
	ngx_http_secure_token_processor_conf_t* conf,
	ngx_http_secure_token_base_ctx_t* ctx,
	u_char** cur_pos,
	u_char* buffer_end,
	ngx_http_secure_token_processor_output_t* output);

// main functions

ngx_int_t ngx_http_secure_token_init_processors_hash(
	ngx_conf_t* cf,
	ngx_http_secure_token_loc_conf_t* conf);

ngx_int_t ngx_http_secure_token_init_body_filter(
	ngx_http_request_t* r,
	ngx_str_t* token);

void ngx_http_secure_token_install_body_filter();

#endif // _NGX_HTTP_SECURE_TOKEN_PROCESSOR_BASE_H_INCLUDED_
