#include "ngx_http_secure_token_cloud_front.h"
#include <openssl/pem.h>

#define POLICY_FORMAT "{\"Statement\":[{\"Resource\":\"%V\",\"Condition\":{\"DateLessThan\":{\"AWS:EpochTime\":%uD}}}]}"
#define POLICY_PARAM "Policy="
#define SIGNATURE_PARAM "&Signature="
#define KEY_PAIR_ID_PARAM "&Key-Pair-Id="

void
ngx_http_secure_token_cloud_front_create_conf(
	ngx_conf_t *cf,
	ngx_http_secure_token_cloud_front_conf_t *conf)
{
}

char *
ngx_http_secure_token_cloud_front_merge_conf(
	ngx_conf_t *cf,
	ngx_http_secure_token_loc_conf_t *base,
	ngx_http_secure_token_cloud_front_conf_t *conf,
	ngx_http_secure_token_cloud_front_conf_t *prev)
{
	BIO *in;

	ngx_conf_merge_str_value(conf->key_pair_id, prev->key_pair_id, "");	
	ngx_conf_merge_str_value(conf->private_key_file, prev->private_key_file, "");

	if (conf->private_key_file.len)
	{
		in = BIO_new_file((char *) conf->private_key_file.data, "r");
		if (in == NULL) 
		{
			return "cannot be opened";
		}
		
		conf->private_key = PEM_read_bio_PrivateKey(in, NULL, NULL, NULL);
		if (conf->private_key == NULL)
		{
			return "cannot be loaded";
		}
		
		BIO_free(in);
	}

	return NGX_CONF_OK;
}
	
// copied from ngx_string with 2 changes:
//	1. changed the charset: + => -, / => ~, = => _
//	2. changed 

static u_char*
ngx_encode_base64_internal_cloud_front(u_char *d, ngx_str_t *src, const u_char *basis, ngx_uint_t padding)
{
    u_char         *s;
    size_t          len;

    len = src->len;
    s = src->data;

    while (len > 2) {
        *d++ = basis[(s[0] >> 2) & 0x3f];
        *d++ = basis[((s[0] & 3) << 4) | (s[1] >> 4)];
        *d++ = basis[((s[1] & 0x0f) << 2) | (s[2] >> 6)];
        *d++ = basis[s[2] & 0x3f];

        s += 3;
        len -= 3;
    }

    if (len) {
        *d++ = basis[(s[0] >> 2) & 0x3f];

        if (len == 1) {
            *d++ = basis[(s[0] & 3) << 4];
            if (padding) {
                *d++ = '_';
            }

        } else {
            *d++ = basis[((s[0] & 3) << 4) | (s[1] >> 4)];
            *d++ = basis[(s[1] & 0x0f) << 2];
        }

        if (padding) {
            *d++ = '_';
        }
    }

	return d;
}

static u_char*
ngx_encode_base64_cloud_front(u_char *d, ngx_str_t *src)
{
    static u_char basis64[] =
            "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789-~";

    return ngx_encode_base64_internal_cloud_front(d, src, basis64, 1);
}

static ngx_int_t
ngx_http_secure_token_cloud_front_sign(ngx_http_request_t* r, EVP_PKEY *private_key, ngx_str_t* policy, ngx_str_t* signature)
{
	EVP_MD_CTX md_ctx;
	unsigned int siglen;

	signature->data = ngx_palloc(r->pool, EVP_PKEY_size(private_key) + 1);
	if (signature->data == NULL)
	{
		return NGX_ERROR;
	}
	
	EVP_MD_CTX_init(&md_ctx);
	
	if (!EVP_SignInit_ex(&md_ctx, EVP_sha1(), NULL))
	{
		goto error;
	}
	
	if (!EVP_SignUpdate(&md_ctx, policy->data, policy->len))
	{
		goto error;
	}
	
	if (!EVP_SignFinal(&md_ctx, signature->data, &siglen, private_key))
	{
		goto error;
	}

	EVP_MD_CTX_cleanup(&md_ctx);
	
	signature->len = siglen;
	return NGX_OK;
	
error:

	EVP_MD_CTX_cleanup(&md_ctx);
	return NGX_ERROR;
}

ngx_int_t
ngx_http_secure_token_cloud_front_build(
	ngx_http_request_t* r, 
	ngx_http_secure_token_loc_conf_t *conf, 
	ngx_str_t* acl, 
	ngx_str_t* result)
{
	ngx_str_t signature;
	ngx_str_t policy;
	ngx_int_t rc;
	u_char* p;

	// build the policy json
	policy.data = ngx_palloc(r->pool, sizeof(POLICY_FORMAT) + acl->len + NGX_INT32_LEN);
	if (policy.data == NULL)
	{
		return NGX_ERROR;
	}
	
	policy.len = ngx_sprintf(policy.data, POLICY_FORMAT, acl, ngx_time() + conf->window) - policy.data;
	
	// sign the policy
	rc = ngx_http_secure_token_cloud_front_sign(r, conf->cloud_front.private_key, &policy, &signature);
	if (rc != NGX_OK)
	{
		return rc;
	}
	
	// build the token
	result->data = ngx_palloc(
		r->pool, 
		sizeof(POLICY_PARAM) - 1 + 
		ngx_base64_encoded_length(policy.len) + 
		sizeof(SIGNATURE_PARAM) - 1 + 
		ngx_base64_encoded_length(signature.len) +
		sizeof(KEY_PAIR_ID_PARAM) - 1 + 
		conf->cloud_front.key_pair_id.len + 1);
	if (result->data == NULL)
	{
		return NGX_ERROR;
	}
		
	p = ngx_copy(result->data, POLICY_PARAM, sizeof(POLICY_PARAM) - 1);
	p = ngx_encode_base64_cloud_front(p, &policy);
	p = ngx_copy(p, SIGNATURE_PARAM, sizeof(SIGNATURE_PARAM) - 1);
	p = ngx_encode_base64_cloud_front(p, &signature);
	p = ngx_copy(p, KEY_PAIR_ID_PARAM, sizeof(KEY_PAIR_ID_PARAM) - 1);
	p = ngx_copy(p, conf->cloud_front.key_pair_id.data, conf->cloud_front.key_pair_id.len);
	*p = '\0';
	
	result->len = p - result->data;
	return NGX_OK;
}
