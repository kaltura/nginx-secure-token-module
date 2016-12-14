#ifndef _NGX_HTTP_SECURE_TOKEN_UTILS_H_INCLUDED_
#define _NGX_HTTP_SECURE_TOKEN_UTILS_H_INCLUDED_

// includes
#include <ngx_core.h>
#include <ngx_http.h>
#include <openssl/evp.h>

// constants
#ifndef MD5_DIGEST_LENGTH
#define MD5_DIGEST_LENGTH (16)
#endif // MD5_DIGEST_LENGTH

#ifndef AES_BLOCK_SIZE
#define AES_BLOCK_SIZE (16)
#endif // AES_BLOCK_SIZE

// typedefs
typedef enum {
	NGX_HTTP_SECURE_TOKEN_TIME_UNSET,
	NGX_HTTP_SECURE_TOKEN_TIME_RELATIVE,
	NGX_HTTP_SECURE_TOKEN_TIME_ABSOLUTE,
} ngx_secure_token_time_type_t;

typedef struct {
	ngx_secure_token_time_type_t type;
	time_t val;
} ngx_secure_token_time_t;

// conf functions
char* ngx_http_secure_token_conf_set_hex_str_slot(
	ngx_conf_t *cf,
	ngx_command_t *cmd,
	void *conf);

char* ngx_http_secure_token_conf_set_time_slot(
	ngx_conf_t *cf,
	ngx_command_t *cmd,
	void *conf);

char* ngx_http_secure_token_conf_set_private_key_slot(
	ngx_conf_t *cf,
	ngx_command_t *cmd,
	void *conf);

char* ngx_http_secure_token_conf_block(
	ngx_conf_t *cf,
	ngx_command_t *cmds,
	void *conf,
	ngx_http_get_variable_pt get_handler);

// token functions
u_char* ngx_http_secure_token_encode_base64_internal(
	u_char *d,
	ngx_str_t *src,
	const u_char *basis,
	u_char padding);

ngx_int_t ngx_http_secure_token_sign(
	ngx_http_request_t* r,
	EVP_PKEY* private_key,
	ngx_str_t* message,
	ngx_str_t* signature);

#endif // _NGX_HTTP_SECURE_TOKEN_UTILS_H_INCLUDED_
