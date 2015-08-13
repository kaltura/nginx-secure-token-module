#ifndef _NGX_HTTP_SECURE_TOKEN_XML_H_INCLUDED_
#define _NGX_HTTP_SECURE_TOKEN_XML_H_INCLUDED_

// includes
#include <ngx_core.h>
#include "ngx_http_secure_token_processor_base.h"

// constants
#define XML_MAX_TAG_NAME_LEN (50)
#define XML_MAX_ATTR_NAME_LEN (50)

// typedefs
typedef struct {
	ngx_str_t tag_name;
	ngx_str_t* attr_names;
} ngx_http_secure_token_xml_node_attrs_t;

typedef struct {
	ngx_http_secure_token_base_ctx_t base;
	size_t tag_name_len;
	u_char tag_name[XML_MAX_TAG_NAME_LEN];
	size_t attr_name_len;
	u_char attr_name[XML_MAX_ATTR_NAME_LEN];
} ngx_http_secure_token_xml_ctx_t;

// functions
ngx_chain_t**
ngx_http_secure_token_xml_processor(
	ngx_http_request_t* r,
	ngx_http_secure_token_processor_conf_t* conf,
	ngx_http_secure_token_xml_node_attrs_t* nodes,
	ngx_buf_t *in,
	ngx_http_secure_token_ctx_t* root_ctx,
	ngx_http_secure_token_xml_ctx_t* ctx,
	ngx_chain_t** out);

#endif // _NGX_HTTP_SECURE_TOKEN_XML_H_INCLUDED_
