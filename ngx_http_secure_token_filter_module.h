#ifndef _NGX_HTTP_SECURE_TOKEN_FILTER_MODULE_H_INCLUDED_
#define _NGX_HTTP_SECURE_TOKEN_FILTER_MODULE_H_INCLUDED_

// includes
#include <ngx_core.h>
#include "ngx_http_secure_token_conf.h"

// typedefs
struct ngx_http_secure_token_ctx_s;
typedef struct ngx_http_secure_token_ctx_s ngx_http_secure_token_ctx_t;

typedef ngx_chain_t** (*ngx_http_secure_token_body_processor_t)(
	ngx_http_secure_token_processor_conf_t* conf,
	void* params,
	ngx_buf_t *in, 
	ngx_http_secure_token_ctx_t* root_ctx,
	void* ctx, 
	ngx_pool_t* pool, 
	ngx_chain_t** out);

// functions
ngx_chain_t**
ngx_http_secure_token_add_to_chain(
	ngx_pool_t* pool, 
	ngx_chain_t** out, 
	u_char* start, 
	u_char* end, 
	ngx_flag_t memory, 
	ngx_flag_t last_buf);

ngx_chain_t**
ngx_http_secure_token_add_token(
	ngx_http_secure_token_ctx_t* ctx, 
	ngx_pool_t* pool,
	u_char** last_sent,
	u_char* cur_pos,
	ngx_flag_t has_query,
	u_char last_url_char,
	ngx_chain_t** out);

#endif // _NGX_HTTP_SECURE_TOKEN_FILTER_MODULE_H_INCLUDED_
