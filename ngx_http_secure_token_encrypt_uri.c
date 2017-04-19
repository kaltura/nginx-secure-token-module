#include "ngx_http_secure_token_filter_module.h"
#include "ngx_http_secure_token_encrypt_uri.h"
#include "ngx_http_secure_token_conf.h"
#include "ngx_http_secure_token_utils.h"
#include <openssl/evp.h>
#include <ngx_md5.h>

// Note: a modified version of ngx_strstrn that gets ngx_str_t's
static u_char *
ngx_http_secure_token_strstr(ngx_str_t* haystack, ngx_str_t* needle)
{
	u_char  c1, c2;
	u_char* s1 = haystack->data;
	u_char* s1_end = haystack->data + haystack->len - needle->len;
	u_char* s2 = needle->data + 1;
	size_t s2_len = needle->len - 1;

	c2 = needle->data[0];

	do {
		do {
			if (s1 > s1_end) {
				return NULL;
			}

			c1 = *s1++;

		} while (c1 != c2);

	} while (ngx_memcmp(s1, s2, s2_len) != 0);

	return --s1;
}

static ngx_int_t
ngx_http_secure_token_get_encryted_part(
	ngx_http_request_t *r,
	ngx_str_t* uri,
	ngx_flag_t execute,
	ngx_str_t* encrypt_uri_part, 
	size_t* uri_prefix_len,
	size_t* uri_suffix_len)
{
	ngx_http_secure_token_loc_conf_t *conf;
	ngx_http_core_loc_conf_t *clcf;
	u_char* encrypt_uri_pos;
	ngx_int_t rc;

	clcf = ngx_http_get_module_loc_conf(r, ngx_http_core_module);

	// simple (non regex) location
	if (clcf->regex == NULL)
	{
		if (execute)
		{
			if (uri->len < clcf->name.len ||
				ngx_memcmp(clcf->name.data, uri->data, clcf->name.len) != 0)
			{
				encrypt_uri_part->len = 0;
				return NGX_OK;
			}
		}

		*uri_prefix_len = clcf->name.len;
		*uri_suffix_len = 0;
		encrypt_uri_part->data = uri->data + *uri_prefix_len;
		encrypt_uri_part->len = uri->len - *uri_prefix_len;

		return NGX_OK;
	}

	// regex location
	if (execute)
	{
		// execute the location regex on the current url so that $1,$2 etc. will evaluate correctly
		rc = ngx_http_regex_exec(r, clcf->regex, uri);
		if (rc != NGX_OK)
		{
			ngx_log_debug0(NGX_LOG_DEBUG_HTTP, r->connection->log, 0,
				"ngx_http_secure_token_get_encryted_part: ngx_http_regex_exec failed");
			return NGX_ERROR;
		}
	}

	// evaluate encrypted part
	conf = ngx_http_get_module_loc_conf(r, ngx_http_secure_token_filter_module);
	
	if (conf->encrypt_uri_part == NULL)
	{
		ngx_log_error(NGX_LOG_ERR, r->connection->log, 0,
			"ngx_http_secure_token_get_encryted_part: encrypt_uri_part was not set");
		return NGX_ERROR;
	}

	if (ngx_http_complex_value(
		r,
		conf->encrypt_uri_part,
		encrypt_uri_part) != NGX_OK)
	{
		ngx_log_debug0(NGX_LOG_DEBUG_HTTP, r->connection->log, 0,
			"ngx_http_secure_token_get_encryted_part: ngx_http_complex_value failed");
		return NGX_ERROR;
	}

	if (encrypt_uri_part->len == 0)
	{
		return NGX_OK;
	}

	// find the encrypted part on the uri
	encrypt_uri_pos = ngx_http_secure_token_strstr(uri, encrypt_uri_part);
	if (encrypt_uri_pos == NULL)
	{
		ngx_log_error(NGX_LOG_ERR, r->connection->log, 0,
			"ngx_http_secure_token_get_encryted_part: failed to find the encrypted uri part");
		return NGX_ERROR;
	}
	*uri_prefix_len = encrypt_uri_pos - uri->data;
	*uri_suffix_len = uri->len - *uri_prefix_len - encrypt_uri_part->len;

	return NGX_OK;
}

static ngx_int_t
ngx_http_secure_token_crypt(
	ngx_str_t* dest,
	ngx_http_request_t* r, 
	u_char* key, 
	u_char* iv, 
	ngx_str_t* buffer1, 
	ngx_str_t* buffer2, 
	ngx_flag_t encrypt)
{
	EVP_CIPHER_CTX* ctx;
	u_char* p;
	int output_len;

	ctx = EVP_CIPHER_CTX_new();
	if (ctx == NULL)
	{
		ngx_log_error(NGX_LOG_ERR, r->connection->log, 0,
			"ngx_http_secure_token_crypt: EVP_CIPHER_CTX_new failed");
		return NGX_ERROR;
	}

	if (!EVP_CipherInit_ex(ctx, EVP_aes_256_cbc(), NULL, key, iv, encrypt))
	{
		ngx_log_error(NGX_LOG_ERR, r->connection->log, 0,
			"ngx_http_secure_token_crypt: EVP_CipherInit_ex failed");
		goto error;
	}

	p = dest->data;

	if (!EVP_CipherUpdate(ctx, p, &output_len, buffer1->data, buffer1->len))
	{
		ngx_log_error(NGX_LOG_ERR, r->connection->log, 0,
			"ngx_http_secure_token_crypt: EVP_CipherUpdate failed (1)");
		goto error;
	}
	p += output_len;

	if (buffer2 != NULL)
	{
		if (!EVP_CipherUpdate(ctx, p, &output_len, buffer2->data, buffer2->len))
		{
			ngx_log_error(NGX_LOG_ERR, r->connection->log, 0,
				"ngx_http_secure_token_crypt: EVP_CipherUpdate failed (2)");
			goto error;
		}
		p += output_len;
	}

	if (!EVP_CipherFinal_ex(ctx, p, &output_len))
	{
		ngx_log_error(NGX_LOG_ERR, r->connection->log, 0,
			"ngx_http_secure_token_crypt: EVP_CipherFinal_ex failed");
		goto error;
	}
	p += output_len;

	EVP_CIPHER_CTX_free(ctx);

	dest->len = p - dest->data;

	return NGX_OK;

error:

	EVP_CIPHER_CTX_free(ctx);
	return NGX_ERROR;
}

ngx_int_t
ngx_http_secure_token_decrypt_uri(ngx_http_request_t *r)
{
	ngx_http_secure_token_loc_conf_t *conf;
	ngx_str_t encrypt_uri_part;
	ngx_str_t base64_decoded;
	ngx_str_t decrypted;
	ngx_str_t new_uri;
	ngx_int_t rc;
	ngx_md5_t md5;
	u_char md5hash[MD5_DIGEST_LENGTH];
	size_t uri_prefix_len;
	size_t uri_suffix_len;
	u_char* p;

	conf = ngx_http_get_module_loc_conf(r, ngx_http_secure_token_filter_module);

	if (!conf->processor_conf.encrypt_uri)
	{
		return NGX_OK;
	}
	
	// get the encrypted part
	rc = ngx_http_secure_token_get_encryted_part(r, &r->uri, 0, &encrypt_uri_part, &uri_prefix_len, &uri_suffix_len);
	if (rc != NGX_OK || encrypt_uri_part.len == 0)
	{
		return rc;
	}

	// allocate buffers
	base64_decoded.len = ngx_base64_decoded_length(encrypt_uri_part.len);
	decrypted.len = base64_decoded.len;
	new_uri.len = uri_prefix_len + decrypted.len + uri_suffix_len;

	new_uri.data = ngx_pnalloc(r->pool, new_uri.len + 1);
	if (new_uri.data == NULL)
	{
		ngx_log_debug0(NGX_LOG_DEBUG_HTTP, r->connection->log, 0,
			"ngx_http_secure_token_decrypt_uri: ngx_pnalloc failed (1)");
		return NGX_ERROR;
	}

	decrypted.data = ngx_pnalloc(r->pool, decrypted.len + base64_decoded.len);
	if (decrypted.data == NULL)
	{
		ngx_log_debug0(NGX_LOG_DEBUG_HTTP, r->connection->log, 0,
			"ngx_http_secure_token_decrypt_uri: ngx_pnalloc failed (2)");
		return NGX_ERROR;
	}

	base64_decoded.data = decrypted.data + decrypted.len;

	// base64url decode
	rc = ngx_decode_base64url(&base64_decoded, &encrypt_uri_part);
	if (rc != NGX_OK)
	{
		ngx_log_error(NGX_LOG_ERR, r->connection->log, 0,
			"ngx_http_secure_token_decrypt_uri: ngx_decode_base64url failed %i", rc);
		return NGX_HTTP_BAD_REQUEST;
	}

	// decrypt
	if (base64_decoded.len % AES_BLOCK_SIZE != 0)
	{
		ngx_log_error(NGX_LOG_ERR, r->connection->log, 0,
			"ngx_http_secure_token_decrypt_uri: base64 decoded string length %uz is not a multiple of block size", 
			base64_decoded.len);
		return NGX_HTTP_BAD_REQUEST;
	}

	rc = ngx_http_secure_token_crypt(
		&decrypted,
		r,
		conf->encrypt_uri_key.data,
		conf->encrypt_uri_iv.data,
		&base64_decoded,
		NULL,
		0);
	if (rc != NGX_OK)
	{
		return rc;
	}

	// validate signature
	if (decrypted.len < conf->encrypt_uri_hash_size)
	{
		ngx_log_error(NGX_LOG_ERR, r->connection->log, 0,
			"ngx_http_secure_token_decrypt_uri: decrypted length %uz smaller than hash size", decrypted.len);
		return NGX_HTTP_BAD_REQUEST;
	}

	ngx_md5_init(&md5);
	ngx_md5_update(&md5, decrypted.data + conf->encrypt_uri_hash_size, decrypted.len - conf->encrypt_uri_hash_size);
	ngx_md5_final(md5hash, &md5);

	if (ngx_memcmp(md5hash, decrypted.data, conf->encrypt_uri_hash_size) != 0)
	{
		ngx_log_error(NGX_LOG_ERR, r->connection->log, 0,
			"ngx_http_secure_token_decrypt_uri: invalid hash");
		return NGX_HTTP_FORBIDDEN;
	}

	// update the uri
	p = ngx_copy(new_uri.data, r->uri.data, uri_prefix_len);
	p = ngx_copy(p, decrypted.data + conf->encrypt_uri_hash_size, decrypted.len - conf->encrypt_uri_hash_size);
	p = ngx_copy(p, r->uri.data + r->uri.len - uri_suffix_len, uri_suffix_len);
	*p = 0;

	new_uri.len = p - new_uri.data;

	r->uri = new_uri;
	r->unparsed_uri = new_uri;		// TODO: fix this

	// free temporary buffer
	ngx_pfree(r->pool, decrypted.data);

	return NGX_OK;
}

ngx_int_t
ngx_http_secure_token_encrypt_uri(ngx_http_request_t* r, ngx_str_t* src, ngx_str_t* dest)
{
	ngx_http_secure_token_loc_conf_t *conf;
	ngx_str_t encrypt_uri_part;
	ngx_str_t base64_encoded;
	ngx_str_t encrypted;
	ngx_str_t hash;
	ngx_str_t new_uri;
	ngx_int_t rc;
	ngx_md5_t md5;
	u_char md5hash[MD5_DIGEST_LENGTH];
	size_t uri_prefix_len;
	size_t uri_suffix_len;
	u_char* p;

	conf = ngx_http_get_module_loc_conf(r, ngx_http_secure_token_filter_module);

	// get the encrypted part
	rc = ngx_http_secure_token_get_encryted_part(r, src, 1, &encrypt_uri_part, &uri_prefix_len, &uri_suffix_len);
	if (rc != NGX_OK)
	{
		return rc;
	}

	if (encrypt_uri_part.len == 0)
	{
		dest->data = ngx_pstrdup(r->pool, src);
		if (dest->data == NULL)
		{
			return NGX_ERROR;
		}
		dest->len = src->len;
		return NGX_OK;
	}

	// TODO: consider undoing ngx_http_regex_exec (r->captures, r->variables etc.)

	// allocate buffers
	encrypted.len = conf->encrypt_uri_hash_size + encrypt_uri_part.len + AES_BLOCK_SIZE;
	new_uri.len = uri_prefix_len + ngx_base64_encoded_length(encrypted.len) + uri_suffix_len;

	new_uri.data = ngx_pnalloc(r->pool, new_uri.len + 1);
	if (new_uri.data == NULL)
	{
		ngx_log_debug0(NGX_LOG_DEBUG_HTTP, r->connection->log, 0,
			"ngx_http_secure_token_encrypt_uri: ngx_pnalloc failed (1)");
		return NGX_ERROR;
	}

	encrypted.data = ngx_pnalloc(r->pool, encrypted.len);
	if (encrypted.data == NULL)
	{
		ngx_log_debug0(NGX_LOG_DEBUG_HTTP, r->connection->log, 0,
			"ngx_http_secure_token_encrypt_uri: ngx_pnalloc failed (2)");
		return NGX_ERROR;
	}

	// sign
	ngx_md5_init(&md5);
	ngx_md5_update(&md5, encrypt_uri_part.data, encrypt_uri_part.len);
	ngx_md5_final(md5hash, &md5);

	hash.data = md5hash;
	hash.len = conf->encrypt_uri_hash_size;

	// encrypt
	rc = ngx_http_secure_token_crypt(
		&encrypted,
		r,
		conf->encrypt_uri_key.data,
		conf->encrypt_uri_iv.data,
		&hash,
		&encrypt_uri_part,
		1);
	if (rc != NGX_OK)
	{
		return rc;
	}

	// update the uri
	p = ngx_copy(new_uri.data, src->data, uri_prefix_len);

	base64_encoded.data = p;
	ngx_encode_base64url(&base64_encoded, &encrypted);
	p += base64_encoded.len;

	p = ngx_copy(p, src->data + src->len - uri_suffix_len, uri_suffix_len);
	*p = 0;

	new_uri.len = p - new_uri.data;

	*dest = new_uri;

	// free temporary buffer
	ngx_pfree(r->pool, encrypted.data);

	return NGX_OK;
}
