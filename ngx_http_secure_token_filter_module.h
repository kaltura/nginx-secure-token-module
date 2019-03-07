#ifndef _NGX_HTTP_SECURE_TOKEN_FILTER_MODULE_H_INCLUDED_
#define _NGX_HTTP_SECURE_TOKEN_FILTER_MODULE_H_INCLUDED_

// includes
#include <ngx_http.h>

// functions
ngx_int_t ngx_http_secure_token_get_acl(ngx_http_request_t *r, ngx_http_complex_value_t *acl_conf, ngx_str_t* acl);

// globals
extern ngx_module_t ngx_http_secure_token_filter_module;

#endif // _NGX_HTTP_SECURE_TOKEN_FILTER_MODULE_H_INCLUDED_
