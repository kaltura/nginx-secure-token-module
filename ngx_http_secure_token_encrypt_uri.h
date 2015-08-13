#ifndef _NGX_HTTP_SECURE_TOKEN_ENCRYPT_URI_H_INCLUDED_
#define _NGX_HTTP_SECURE_TOKEN_ENCRYPT_URI_H_INCLUDED_

// includes
#include <ngx_http.h>

// functions
ngx_int_t ngx_http_secure_token_decrypt_uri(ngx_http_request_t *r);

ngx_int_t ngx_http_secure_token_encrypt_uri(ngx_http_request_t* r, ngx_str_t* src, ngx_str_t* dest);

#endif // _NGX_HTTP_SECURE_TOKEN_ENCRYPT_URI_H_INCLUDED_
