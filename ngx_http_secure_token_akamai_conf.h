#ifndef _NGX_HTTP_SECURE_TOKEN_AKAMAI_CONF_H_INCLUDED_
#define _NGX_HTTP_SECURE_TOKEN_AKAMAI_CONF_H_INCLUDED_

#include <ngx_core.h>

typedef struct {
	ngx_http_complex_value_t *acl;
	ngx_http_complex_value_t *key;
	ngx_str_t param_name;
} ngx_http_secure_token_akamai_conf_t;

#endif // _NGX_HTTP_SECURE_TOKEN_AKAMAI_CONF_H_INCLUDED_
