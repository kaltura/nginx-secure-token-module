	{ ngx_string("secure_token_cloudfront_private_key_file"),
	NGX_HTTP_MAIN_CONF|NGX_HTTP_SRV_CONF|NGX_HTTP_LOC_CONF|NGX_CONF_TAKE1,
	ngx_conf_set_str_slot,
	NGX_HTTP_LOC_CONF_OFFSET,
	offsetof(ngx_http_secure_token_loc_conf_t, cloudfront.private_key_file),
	NULL },

	{ ngx_string("secure_token_cloudfront_key_pair_id"),
	NGX_HTTP_MAIN_CONF|NGX_HTTP_SRV_CONF|NGX_HTTP_LOC_CONF|NGX_CONF_TAKE1,
	ngx_conf_set_str_slot,
	NGX_HTTP_LOC_CONF_OFFSET,
	offsetof(ngx_http_secure_token_loc_conf_t, cloudfront.key_pair_id),
	NULL },
	
