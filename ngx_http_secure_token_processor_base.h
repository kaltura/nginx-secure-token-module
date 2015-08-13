#ifndef _NGX_HTTP_SECURE_TOKEN_PROCESSOR_BASE_H_INCLUDED_
#define _NGX_HTTP_SECURE_TOKEN_PROCESSOR_BASE_H_INCLUDED_

// includes
#include <ngx_core.h>
#include "ngx_http_secure_token_conf.h"

// enums
enum {
	STATE_INITIAL,

	STATE_URL_SCHEME,
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
	u_char last_url_char;
	size_t uri_path_alloc_size;
	ngx_str_t uri_path;
} ngx_http_secure_token_base_ctx_t;

typedef ngx_chain_t** (*ngx_http_secure_token_body_processor_t)(
	ngx_http_request_t* r,
	ngx_http_secure_token_processor_conf_t* conf,
	void* params,
	ngx_buf_t* in,
	ngx_http_secure_token_ctx_t* root_ctx,
	void* ctx,
	ngx_chain_t** out);

// processor utility functions

ngx_chain_t** ngx_http_secure_token_add_to_chain(
	ngx_pool_t* pool,
	u_char* start,
	u_char* end,
	ngx_flag_t memory,
	ngx_flag_t last_buf,
	ngx_chain_t** out);

ngx_chain_t** ngx_http_secure_token_url_state_machine(
	ngx_http_request_t* r,
	ngx_http_secure_token_processor_conf_t* conf,
	ngx_http_secure_token_ctx_t* root_ctx,
	ngx_http_secure_token_base_ctx_t* ctx,
	u_char* buffer_end, 
	u_char** cur_pos,
	u_char** last_sent, 
	ngx_chain_t** out);

// main functions

ngx_int_t ngx_http_secure_token_init_processors_hash(
	ngx_conf_t* cf,
	ngx_http_secure_token_loc_conf_t* conf);

ngx_int_t ngx_http_secure_token_init_body_filter(
	ngx_http_request_t* r,
	ngx_str_t* token);

void ngx_http_secure_token_install_body_filter();

#endif // _NGX_HTTP_SECURE_TOKEN_PROCESSOR_BASE_H_INCLUDED_
