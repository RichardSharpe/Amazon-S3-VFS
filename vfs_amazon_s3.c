/*
 * Store stuff up on Amazon's S3 service.
 *
 * Copyright (C) Richard Sharpe, 2011-2012
 *
 * This program is free software; you can redistribute it and/or modify it 
 * under the terms of the GNU General Public License as published by the 
 * Free Software Foundation; either version 3 of the License, or
 * (at your option) any later version.
 *
 * This program is distrubuted in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of 
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE. See the 
 * GNU General Public License for more details.
 *
 * You should have received a copy of the GNU General Public License
 * along with this program; if not, see <http://www.gnu.org/licenses/>.
 */

#include <pthread.h>
#include <curl/curl.h>

#include "includes.h"
#include "smbd/smbd.h"
#include <openssl/bio.h>
#include <openssl/buffer.h>
#include <openssl/evp.h>
#include <openssl/hmac.h>
#include <openssl/md5.h>
#include <openssl/sha.h>
#include <semaphore.h>
#include <fcntl.h>

#include <libxml/parser.h>
#include <libxml/tree.h>

#include "vfs_amazon_s3.h"

#undef DBGC_CLASS
#define DBGC_CLASS DBGC_VFS

#define S3_MODULE_NAME "vfs_amazon_s3"

static bool curl_global_init_done = false;

/*
 * We register ourselves as a module. We hook into the connect, disconnect,
 * open, close, read, write, opendir (various), readdir, etc, and FSCTL
 * calls.
 *
 * Connect calls are to allow us to start the needed threads, connect to 
 * Amazon S3, etc.
 *
 * Close calls are to allow us to copy new copies of the file up to S3. We 
 * queue any modified file to the upload thread.
 *
 * Write calls are to allow us to record the fact that the file was modified
 * and thus must be copied up to S3 when the file is closed.
 *
 * Read calls are to allow us to co-ordinate reads during restore of a file.
 *
 * Open calls are to allow us to schedule the return of a file if it has the
 * correct previous version info.
 *
 * Opendir calls are to allow us to query S3 for info that might be needed
 * to display the S3-backed directories as appropriate.
 *
 * Readdir calls are to allow us to return appropriate info to the client.
 *
 * FSCTL calls are to allow us to return info about the previous versions 
 * that exist.
 */

static pthread_t w_thread;

/*
 * A simple queue guarded by semaphores initially. When stuff is working
 * this will have to change ... however, we can always delay clients if this
 * little queue is full or close to full, especially if we turn on background
 * processing of SMB Hello requests.
 */

static sem_t send_sem, recv_sem;
static struct write_thread_struct *write_cmd_queue[WRITE_QUEUE_SIZE];
static unsigned int send_index = 0;
static unsigned int recv_index = 0;

bool send_cmd(struct write_thread_struct *cmd)
{
	int res = 0;

	/*
	 * Is there space? If not we wait 
	 */
	res = sem_wait(&send_sem);
	if (res < 0) {
		DEBUG(1, ("Failed to wait on the send semaphore: %s\n",
			strerror(errno)));
		return false;
	}

	write_cmd_queue[send_index] = cmd;
	send_index++;
	if (send_index >= WRITE_QUEUE_SIZE)
		send_index = 0;

	/*
	 * Tell the write thread that it has something to do
	 */
	res = sem_post(&recv_sem);
	if (res < 0) {
		DEBUG(1, ("Failed to send on the recv semaphore: %s\n",
			strerror(errno)));
		return false;
	}

	return true;
}

/*
 * Perhaps these routines should be placed in a separate library ...
 */

static const char *get_verb_str(struct s3_request_struct *req)
{
	switch (req->request_type) {
	case HDR_GET:
		return "GET";
	case HDR_POST:
		return "POST";
	case HDR_PUT:
		return "PUT";
	case HDR_DELETE:
		return "DELETE";
	case HDR_HEAD:
		return "HEAD";
	default:
		return "NoSuchVerb";
	}
}

/*
 * Get the tmp context
 */
static void *get_tmp_context(struct s3_request_struct *req)
{
	return req->tmp_context;
}

/*
 * A pair of functions to generate the hmac_sha1 hash and base64 encode it.
 * They need the request structure for the key and use it as a context for
 * talloc allocations.
 */

/*
 * Base64 encode a buffer passed in. Return a talloc allocated string.
 */
static char *base64_enc(void *ctx, 
			const char *buf,
			size_t size)
{
	BIO *b64_filter = BIO_new(BIO_f_base64());
	BIO *mem_ssink  = BIO_new(BIO_s_mem());
	BUF_MEM *bio_mem = NULL;
	int ret = 0;
	char *ret_str;

	b64_filter = BIO_push(b64_filter, mem_ssink);
	ret = BIO_write(b64_filter, buf, size);
	if (ret < 0 || ret != size) {
		DEBUG(0, ("Unable to write all data to b64_filter: %s\n",
			strerror(errno)));
	}
	ret = BIO_flush(b64_filter);

	BIO_get_mem_ptr(b64_filter, &bio_mem);

	/* This should append a terminating null to turn it into a string */
	ret_str = talloc_strndup(ctx, bio_mem->data, bio_mem->length);

	BIO_free_all(b64_filter);

	return ret_str;
}

/*
 * Generate the base64 encoded hmac sha1 hash of string str using the secret 
 * key in the amazon_context_struct pointed to in request.
 */
static char *get_hmac_sha1_b64(struct s3_request_struct *req, const char *str)
{
	uint8_t hmac_sha1_buf[EVP_MAX_MD_SIZE];
	unsigned int hmac_sha1_len = 0;

	HMAC(EVP_sha1(), 
	     req->amz_ctx->secret_key,
	     strlen(req->amz_ctx->secret_key),
	     str,
	     strlen(str),
	     hmac_sha1_buf,
	     &hmac_sha1_len);

	return base64_enc(get_tmp_context(req), hmac_sha1_buf, hmac_sha1_len);
}

/*
 * Generate the base64 encoded sha1 hash of the string in str. This is used
 * to generate unique names for files based on whatever the caller adds to
 * the incoming string.
 */
static char *get_sha1_b64(void *ctx, const char *str)
{
	uint8_t sha1_buf[SHA_DIGEST_LENGTH];

	SHA1(str, strlen(str), sha1_buf);

	return base64_enc(ctx, sha1_buf, sizeof(sha1_buf));
}

/*
 * Handle the curl response data. We could probably simplify our chunks by
 * having the header on each chunk be the list as well. Oh well.
 */
static size_t recv_data(void *data, size_t size, size_t nmemb, void *info)
{
	struct chunk_list_struct *chunk = NULL;
	struct s3_request_struct *req = (struct s3_request_struct *)info;

	DEBUG(10, ("Received size = %zu nmemb = %zu\n", size, nmemb));
	dump_data(10, data, size * nmemb);

	chunk = talloc_zero(req->response, struct chunk_list_struct);
	if (!chunk) {
		DEBUG(1, ("Unable to allocate space for chunk: %s, size: %zu, "
			" nmemb = %zu\n", strerror(errno), size, nmemb));
		goto out;
	}

	chunk->chunk_size = size * nmemb;
	chunk->chunk = talloc_memdup(chunk, data, size * nmemb);

	DLIST_ADD_END(req->response->chunks, 
		      chunk,
		      struct chunk_list_struct *);

out:
	return nmemb * size;
}

/*
 * Parse a header into a KVP ... we are looking for the ':'
 */
struct key_value_pair *kvp_parse(struct s3_request_struct *req, 
				 void *data,
				 size_t len)
{
	struct key_value_pair *kvp = NULL;
	char *sep = strchr(data, ':');
	uint32_t key_name_len = 0;
	uint32_t offset = (uint32_t)(sep - (char *)data);

	/* Simple sanity check */

	if (offset > len) {
		DEBUG(0, ("Hmmm, seems that the separator is not there: %s, "
			" len = %zu, sep = %p, data = %p, offset = %u\n",
			data, len, sep, data, offset));
		return NULL;
	}

	kvp = talloc_zero(req, struct key_value_pair);
	if (!kvp) {
		DEBUG(1, ("Could not allocate space for key-value-pair: %s\n",
			data));
		return kvp;
	}

	key_name_len = (uint32_t)((void *)sep - data);
	/* Should check that these work */
	kvp->key_name = talloc_strndup(kvp, data, key_name_len); 
	/* Get rid of the \r\n at the end (the -2 does that */
	kvp->key_val = talloc_strndup(kvp, ++sep, len - key_name_len - 1 - 2);

	return kvp;
}

/*
 * Handle the curl response headers
 */
static size_t recv_hdr(void *data, size_t size, size_t nmemb, void *info)
{
	struct s3_request_struct *req = (struct s3_request_struct *)info;
	char *data_p = (char *)data;

	DEBUG(10, ("Received size = %zu nmemb = %zu\n", size, nmemb));
	DEBUG(10, ("Hdr: %s\n", data));

	/*
	 * Filter out the /r/n empty header
	 */
	if ((size * nmemb) == 2 && data_p[0] == '\r' && data_p[1] == '\n') {
		DEBUG(10, ("Finished with headers\n"));
		return size * nmemb;
	}

	/*
	 * Create the response if needed, and the string we have is the 
	 * response, otherwise it is a header.
	 *
	 * NOTE! We should probably be careful about the size of the header
	 * below!
	 */
	if (!req->response) {
		DEBUG(10, ("Creating response\n"));
		req->response = talloc_zero(req, struct s3_response_struct);
		if (!req->response) {
			DEBUG(0, ("Unable to allocate space for response! "
				" (%s)\n", 
				strerror(errno)));
			return 0;
		}
		req->response->response_code = talloc_strdup(req->response,
								data);
		if (req->response->response_code)
			req->response->response_code[strlen(data) - 2] = 0; 
	} else {
		struct key_value_pair *kvp = NULL;
		/*
		 * Parse it into a key-value pair and add it.
		 */
		kvp = kvp_parse(req, data, size *nmemb);
		if (kvp)
			DLIST_ADD_END(req->response->headers, 
					kvp, 
					struct key_value_pair *);
			
	}

	return nmemb * size;
}

/*
 * Create a request of the appropriate type. We fill in the important fields
 * at this time, including the data field.
 *
 * We defer creating the response structure until we get the header callback.
 *
 * We have separated the talloc_ctx argument from the context argument because
 * this function is called from the VFS routines and from the write thread,
 * so we need to esure that the correct talloc context is used.
 */
static struct s3_request_struct *create_request(enum request_type_enum request_type,
					struct amazon_context_struct *ctx,
					void *talloc_ctx)
{
	struct s3_request_struct *req = NULL;
	time_t sys_time;
	struct tm tm;

	req = talloc_zero(talloc_ctx, struct s3_request_struct);
	if (!req) {
		DEBUG(1, ("Unable to allocate s3_request_struct: %s\n",
			strerror(errno)));
		goto error;
	}

	req->request_type = request_type;
	req->amz_ctx = ctx;

	/*
	 * Create a new context for tmp strings
	 */
	req->tmp_context = talloc_new(req);
	if (!req->tmp_context) {
		DEBUG(1, ("Unable to allocate tmp_context: %s\n",
			strerror(errno)));
		goto error;
	}

	/*
	 * Need a Date header as well. We handle this here ...
	 */
	(void)time(&sys_time);

	gmtime_r(&sys_time, &tm);
	strftime(req->date, sizeof(req->date) - 1, "%a, %d %b %Y %H:%M:%S GMT",
		 &tm);

	return req;

error:
	if (req) 
		TALLOC_FREE(req);
	return NULL;
}

/*
 * Set content type
 */
static bool set_content_type(struct s3_request_struct *req, 
			     const char *content_type)
{
	if (req->content_type)
		TALLOC_FREE(req->content_type);

	req->content_type = talloc_strdup(req, content_type);

	return (req->content_type != NULL);
}

/*
 * Set content MD5
 */
bool set_content_md5(struct s3_request_struct *req, const char *content_md5)
{
	if (req->content_md5)
		TALLOC_FREE(req->content_md5);

	req->content_md5 = talloc_strdup(req, content_md5);

	return (req->content_md5 != NULL);
}

/*
 * Set URI.
 */
bool set_uri(struct s3_request_struct *req, const char *uri)
{
	if (req->uri)
		TALLOC_FREE(req->uri);

	req->uri = talloc_strdup(req, uri);

	return (req->uri != NULL);
}

bool add_param(struct s3_request_struct *req,
	       struct key_value_pair **list,
	       const char *name,
	       const char *val)
{
	struct key_value_pair *kvp = talloc_zero(req, struct key_value_pair);

	kvp->key_name = talloc_strdup(kvp, name);
	kvp->key_val = talloc_strdup(kvp, val);

	DLIST_ADD_END(*list, kvp, struct key_value_pair *);

	return kvp != NULL;
}

/*
 * Get request type ...
 */
static enum request_type_enum get_request_type(struct s3_request_struct *req)
{
	if (req)
		return req->request_type;
	else
		return HDR_INV_REQUEST;
}

/*
 * Construct the correct amazon headers stuff ... 
 */
static char *get_canon_amz_headers(struct s3_request_struct *req,
				   char *str,
				   struct key_value_pair *kvp)
{
	return str;
}

/*
 * Assemble the auth string from the components as per the Amazon spec. This
 * includes base64 encoding the hmac_sha1 digest. Specified here:
 * http://docs.amazonwebservices.com/AmazonS3/2006-03-01/dev/RESTAuthentication.html
 */
static char *get_auth_string(struct s3_request_struct *req)
{
	char *string_to_enc = NULL;
	struct key_value_pair *kvp = NULL;

	/* 
	 * Construct the first bit: Verb, Content-MD5, Content-Type, Date 
	 * However, don't include the date if we have an x-amz-date header.
	 */
	string_to_enc = talloc_asprintf(get_tmp_context(req), 
				"%s\n%s\n%s\n%s\n",
				get_verb_str(req),
				(req->content_md5) ? req->content_md5 : "",
				(req->content_type) ? req->content_type : "", 
				(req->has_x_amz_date) ? "" : req->date);
	/*
	 * Now add the Canonicalized Amz Headers. These damn things must be 
	 * grouped, sorted alphabetically and have \n appended.
	 */
	kvp = req->amz_headers;
	if (kvp)
		string_to_enc = get_canon_amz_headers(req, string_to_enc, kvp);

	/*
	 * Now add the Canonicalized Resource
	 */
	kvp = req->uri_params;
	string_to_enc = talloc_asprintf_append(string_to_enc,
					"/%s%s",
					req->amz_ctx->bucket,
					req->uri);

	/*
	 * We must also include the appropriate sub-resources ... later
	 */

	DEBUG(10, ("string_to_encode: %s\n", string_to_enc));
	dump_data(10, string_to_enc, strlen(string_to_enc));

	return get_hmac_sha1_b64(req, string_to_enc);
}

/*
 * This gets the full URL with the extra bits added.
 */
static char *get_uri(struct s3_request_struct *req)
{
	char *uri = talloc_strdup(get_tmp_context(req), req->uri);
	struct key_value_pair *uri_params = req->uri_params;

	DEBUG(10, ("uri_params = %p\n", uri_params));
	while (uri_params) {
		uri = talloc_asprintf_append(uri, 
			(req->uri_params == uri_params) ? "?%s" : "&%s", 
			uri_params->key_name);
		if (uri_params->key_val)
			uri = talloc_asprintf_append(uri, "=%s", 
					uri_params->key_val);

		uri_params = uri_params->next;
	}

	return uri;
}

/*
 * Parse the chunk which should be a bunch of XML into an error list ...
 */
static bool parse_error_xml(struct s3_response_struct *response)
{
	bool res = false;
	xmlDocPtr doc = NULL;
	xmlNodePtr cur = NULL;

	if (!response || !response->chunks) {
		DEBUG(10, ("No XML doc to parse\n"));
		return res;
	}

	doc = xmlParseMemory(response->chunks->chunk, 
			     response->chunks->chunk_size);

	if (!doc) 
		goto error;

	cur = xmlDocGetRootElement(doc);

	if (xmlStrcmp(cur->name, (const xmlChar *)"Error")) {
		DEBUG(1, ("No Error node in XML document\n"));
		dump_data(1, 
			response->chunks->chunk, 
			response->chunks->chunk_size);
		goto error;
	}

	/*
	 * Now, get the fields ...
	 */
	cur = cur->xmlChildrenNode;
	while (cur != NULL) {
		struct key_value_pair *kvp = talloc_zero(response, 
							struct key_value_pair);

		if (!kvp) {
			DEBUG(1, ("Could not allocate KVP: %s\n",
				strerror(errno)));
			goto error;
		}

		kvp->key_name = (char *)cur->name;
		kvp->key_val = xmlNodeListGetString(doc, 
						cur->xmlChildrenNode, 1);

		DLIST_ADD_END(response->error, 
				kvp, 
				struct key_value_pair *);

		cur = cur->next;
	}

	return res;

error:
	if (doc)
		xmlFreeDoc(doc);

	return false;
}

/*
 * Execute an HTTP request via CURL, including handling the authorization 
 * header. We handle all the curl stuff here.
 *
 * We pass in the curl handle because this must be called from several
 * places, especially places where we do not want to use the handle in the
 * context.
 */
int execute_request(struct amazon_context_struct *ctx, 
		    struct s3_request_struct *req,
		    CURL *c_handle)
{
	int res = 0;
	struct curl_slist *headers = NULL;
	char *host_header = NULL, 
		*auth_header = NULL, 
		*auth = NULL,
		*content_type = NULL,
		*date_header = NULL,
		*uri = NULL,
		*url = NULL;
	CURLcode c_res = CURLE_OK;

	uri = get_uri(req);
	if (!uri) {
		DEBUG(0, ("No URI obtained ... giving up\n"));
		return -1;
	}

	url = talloc_asprintf(get_tmp_context(req), 
			      "http://s3.amazonaws.com%s", 
			      uri);

	DEBUG(10, ("URL: %s\n", url));

	curl_easy_setopt(c_handle, CURLOPT_URL, url);

	/*
	 * Add headers ...
	 */
	if (req->content_type) {
		content_type = talloc_asprintf(get_tmp_context(req),
					       "Content-type: %s",
					       req->content_type);
		headers = curl_slist_append(headers, content_type);
	}

	host_header = talloc_asprintf(get_tmp_context(req), 
				      "Host: %s.s3.amazonaws.com",
				      ctx->bucket);
	if (!host_header) {
		DEBUG(10, ("Unable to allocate space for Host header\n"));
		return -1;
	}

	headers = curl_slist_append(headers, host_header);

	date_header = talloc_asprintf(get_tmp_context(req), 
				      "Date: %s", 
				      req->date);

	headers = curl_slist_append(headers, date_header);

	auth = get_auth_string(req);  /* We can talloc_free this later */

	DEBUG(10, ("Authorization: %s\n", auth));

	auth[strlen(auth) - 1] = 0;  /* There is a stray new-line here */

	auth_header = talloc_asprintf(get_tmp_context(req), 
				      "Authorization: AWS %s:%s",
				      ctx->access_key,
				      auth);

	DEBUG(10, ("Auth hdr: %s\n", auth_header));

	headers = curl_slist_append(headers, auth_header);

	c_res = curl_easy_setopt(c_handle, CURLOPT_HTTPHEADER, headers);
	if (c_res != CURLE_OK) {
		DEBUG(0, ("Setting headers failed: %s\n", 
			curl_easy_errstr(c_res)));
		return -1;
	}

	curl_easy_setopt(c_handle, CURLOPT_NOPROGRESS, 1L);
	curl_easy_setopt(c_handle, CURLOPT_WRITEFUNCTION, req->recv_data);
	curl_easy_setopt(c_handle, CURLOPT_WRITEDATA, (void *)req);
	curl_easy_setopt(c_handle, CURLOPT_HEADERFUNCTION, req->recv_hdr);
	curl_easy_setopt(c_handle, CURLOPT_WRITEHEADER, (void *)req);

	/*
	 * Different requests require different stuff ...
	 * Be careful about which Curl sessions you are on ... :-)
	 */
	switch (get_request_type(req)) {
	case HDR_GET:
		break;

	case HDR_PUT:
		DEBUG(10, ("Content-Length: %lu\n", req->content_length));
		curl_easy_setopt(c_handle, CURLOPT_UPLOAD, 1L);
		curl_easy_setopt(c_handle, CURLOPT_PUT, 1L);
		curl_easy_setopt(c_handle, CURLOPT_INFILESIZE_LARGE,
				req->content_length);
		curl_easy_setopt(c_handle, CURLOPT_READFUNCTION,
					req->send_data);
		curl_easy_setopt(c_handle, CURLOPT_READDATA, (void *)req);
		break;

	default:

		break;
	}

	/*
	 * At this point we are finished with the tmp storage so delete it 
	 * although we migh need the context again.
	 */
	talloc_free(get_tmp_context(req));

	c_res = curl_easy_perform(c_handle);
	if (c_res != CURLE_OK) {
		DEBUG(0, ("Performing request %s failed: %s\n",
			get_verb_str(req), 
			curl_easy_strerror(c_res)));
		return -1;
	}

	/*
	 * Check the result and etc ...
	 */ 
	c_res = curl_easy_getinfo(c_handle, 
				  CURLINFO_RESPONSE_CODE,
				  &req->response_code);
	if (c_res != CURLE_OK) {
		DEBUG(0, ("Getting response code failed: %s\n",
			curl_easy_strerror(c_res)));
		return -1;
	}

	DEBUG(10, ("Response code for request was: %ld\n", req->response_code));

	if (req->response_code != 200) {
		struct key_value_pair *error = NULL;
		(void)parse_error_xml(req->response);
		DEBUG(1, ("Request failed: %s, ", 
			req->response->response_code));
		error = req->response->error;
		while (error) {
			DEBUG(1, ("%s = %s, ",
				error->key_name,
				error->key_val));
			error = error->next;
		}
		DEBUG(1, ("\n"));
		return -1;
	}

	return res;
}

static size_t send_data(void *data, size_t size, size_t nmemb, void *info)
{
	struct s3_request_struct *req = info;
	struct write_thread_struct *cmd = req->private;
	ssize_t res = 0;

	DEBUG(10, ("size = %lu, nmemb = %lu\n", size, nmemb));

	/*
	 * Do we need to open the file ...
	 */
	if (cmd->fd < 0) {
		int s_errno = 0;
		char *file_name = talloc_asprintf(cmd, 
						"%s/%s",
						cmd->ctx->reloc_dir,
						cmd->hash_name);
		if (!file_name) {
			DEBUG(0, 
				("Unable to allocate memory for file name!\n"));
			return 0;
		}
		cmd->fd = open(file_name, O_RDONLY, 0666);
		if (cmd->fd < 0) {
			DEBUG(0, ("Unable to open file %s (%s)\n",
				file_name,
				strerror(errno)));
			talloc_free(file_name);
			return 0;
		}

		DEBUG(10, ("Opened file %s for reading\n", file_name));
		talloc_free(file_name);
	}

	res = read(cmd->fd, data, size * nmemb);
	if (res < 0) {
		DEBUG(0, ("Failed to read file (%s)\n",
			strerror(errno)));
		return 0;
	}

	DEBUG(10, ("Read %lu bytes of data\n", res));

	return res;
}

static bool upload_file(struct write_thread_struct *cmd, 
			struct amazon_context_struct *ctx,
			CURL *c_handle)
{
	struct s3_request_struct *req = NULL;

	req = create_request(HDR_PUT, ctx, cmd);

	/*
	 * Now, add the things we need ...
	 */

	if (!set_content_type(req, "binary/octet-stream")) {
		DEBUG(0, ("Unable to add Content-Type header (%s)\n",
			strerror(errno)));
		return false;
	}

	req->content_length = cmd->file_size;

	if (!set_uri(req, cmd->file_path)) {
		DEBUG(0, ("Unable to add URI %s (%s)\n",
			cmd->file_path,
			strerror(errno)));
		return false;
	}

	/*
	 * Set up the read method and the data to pass to it ...
	 */
	req->send_data = send_data;
	req->recv_hdr = recv_hdr;    /* Will get these too ... */
	req->private = (void *)cmd;
	cmd->fd = -1;       /* Not opened yet */
	cmd->ctx = ctx;     /* Will need this for some info */

	if (execute_request(ctx, req, c_handle)) {
		DEBUG(0, ("Unable to execute request to %s file %s\n",
			get_verb_str(req),
			cmd->file_path));
	}

	return true;
}

/*
 * Upload thread ... this idea has problems for a real implementation because
 * each client gets it own process ... however, it will do for now. We also
 * have to be able to shut down the thread after the connection goes away, 
 * but not before it has uploaded all the pending files etc.
 */
void *amazon_write_thread(void * param)
{
	struct amazon_context_struct *ctx = 
				(struct amazon_context_struct *)param;
	int res = 0;
	struct write_thread_struct *cmd = NULL;
	CURLcode c_res = CURLE_OK;
	CURL *c_handle = NULL;

	DEBUG(10, ("Write thread starting\n"));

	c_handle = curl_easy_init();
	/*
	 * Wait for a command. Probably should not be open coded :-)
	 */

	res = sem_wait(&recv_sem);
	while (!res || (errno != EINTR)) {
		/* What about EINTR? */

		cmd = write_cmd_queue[recv_index];
		recv_index++;
		if (recv_index >= WRITE_QUEUE_SIZE)
			recv_index = 0;

		res = sem_post(&send_sem);

		DEBUG(10, ("Got a request for %s as %s\n",
			cmd->file_path,
			cmd->hash_name));

		switch (cmd->cmd) {
		case WRT_SEND_FILE:
			if (!upload_file(cmd, ctx, c_handle)) {
				DEBUG(10, ("Upload of %s from %s failed\n",
					cmd->file_path, 
					cmd->hash_name));
			}
			break;

		case WRT_EXIT:
			DEBUG(10, ("Got request to exit ...\n"));
			goto done;
			break;

		default:
			DEBUG(1, ("Unknown command, ignoring ...\n"));
			break;
		}

		talloc_free(cmd); /* We can get rid of this now */

		res = sem_wait(&recv_sem);
	}

	if (res < 0) {
		DEBUG(1, ("Failed to wait on the send semaphore: %s\n",
			strerror(errno)));
		return false;
	}

done:
	DEBUG(10, ("Write thread terminating\n"));

	return 0;
}

/*
 * Convert slash in a base64 encoded hash to underscore ... since we use
 * these hashes to create files (actually, links to files) so we cannot allow
 * slashes in them.
 */
void convert_slash_to_under(char *str)
{
	unsigned int i = 0;
	unsigned int len = strlen(str);

	for (i = 0; i < len; i++)
		if (str[i] == '/')
			str[i] = '_';
}

static bool hash_link_file(struct write_thread_struct *write_cmd,
			   struct files_struct *fsp)
{
	char *hash_input = NULL;

	hash_input = talloc_asprintf(talloc_tos(), "%s:%lu:%lu",
				     write_cmd->file_path,
				     fsp->fsp_name->st.st_ex_ctime.tv_sec,
				     fsp->fsp_name->st.st_ex_ctime.tv_nsec);
	if (!hash_input) {
		DEBUG(1, ("Could not allocate space for hash input: %s\n",
			strerror(errno)));
		return false;
	}

	write_cmd->hash_name = get_sha1_b64(write_cmd, hash_input);
	convert_slash_to_under(write_cmd->hash_name);

	/*
	 * There is a NL on the end. Get rid of it. A better way would be 
	 * to eliminate it in the openssl stuff I am using, though.
	 */
	write_cmd->hash_name[strlen(write_cmd->hash_name) - 1] = 0;

	talloc_free(hash_input);  /* Free it here! */

	if (!write_cmd->hash_name) {
		DEBUG(1, ("Could not get the sha1 value: %s\n",
			strerror(errno)));
		return false;
	}

	return true;
}

/*
 * Send a file to the thread for uploading. We have to ensure that the file 
 * system keeps a reference to it, so create a link to it in the reloc dir.
 * Use a hash on the path, name, and time of last modification.
 *
 * Also, since the fsp is going to go away, we need to create a new structure
 * to pass to the write thread.
 */
static bool send_file_to_thread(struct files_struct *fsp, 
				struct amazon_context_struct *ctx)
{
	struct write_thread_struct *write_cmd = NULL;
	char *alt_path = NULL, *real_path = NULL;
	bool res = true;
	int ln_res = 0;

	DEBUG(10, ("Sending file %s/%s to the write thread\n", 
		fsp->conn->connectpath, fsp_str_dbg(fsp)));

	/*
	 * We cannot use talloc_tos() for this object, because this object
	 * is going to another thread and will be used as a talloc context,
	 * however, talloc_tos() objects are going away at the end of the 
	 * current command. 
	 *
	 * In the longer term, this may actually have to be a new talloc 
	 * context. Let's see.
	 */
	write_cmd = (struct write_thread_struct *)talloc_zero(ctx,
						struct write_thread_struct);

	/*
	 * stat the file first to get some useful info ...
	 */
	SMB_VFS_STAT(fsp->conn, fsp->fsp_name);

	if (!write_cmd) {
		DEBUG(1, ("Unable to talloc_zero space for a command: %s\n",
			strerror(errno)));
		return false;
	}

	write_cmd->cmd = WRT_SEND_FILE;

	/*
	 * We add the slash to make life easier in creating a URI
	 */
	write_cmd->file_path = talloc_asprintf(write_cmd,
					       "/%s",
					       fsp->fsp_name->base_name);

	/*
	 * Now we have to generate a file name for file in the reloc dir
	 * because this file might be unlinked before the write thread gets
	 * to send it to S3 because of delete on close etc.
	 *
	 * We generate a hash from:
	 * 1. The file name and path
	 * 2. The last modify time
	 *
	 * Then link the file into the reloc dir with the name generated.
	 *
	 * We should probably also put an XATTR on the file with its details
	 * in case we crash ... this will help with recovery when we come
	 * back up.
	 *
	 * Note, that we do not store the full path because we might want
	 * to have a separate reloc dir per user in some more sophisticated
	 * version. Anyway, the write thread knows where the reloc dir is.
	 */

	if (!hash_link_file(write_cmd, fsp)) {
		DEBUG(1, ("Unable to create hash name for file: %s\n",
			strerror(errno)));
		return false;
	}

	write_cmd->file_size = fsp->fsp_name->st.st_ex_size;

	/*
	 * Now that we have the alternate name, link that name to the original
	 * file.
	 */

	alt_path = talloc_asprintf(talloc_tos(), "%s/%s",
					ctx->reloc_dir,
					write_cmd->hash_name);

	/* This does not handle alternate data streams! */
	real_path = talloc_asprintf(talloc_tos(), "%s/%s",
					fsp->conn->connectpath,
					fsp->fsp_name->base_name);

	if (!alt_path || !real_path) {
		DEBUG(1, ("Unable to allocate space for alt_path"
			" or real_path: %p, %p\n",
			alt_path,
			real_path));
		res = false;
		goto out;
	}

	DEBUG(10, ("path for file is %s, alt path: %s\n", 
		real_path,
		alt_path));

	/*
	 * We need to be root to do this ...
	 */
	become_root();
	ln_res = link(real_path, alt_path);
	unbecome_root();
	if (ln_res) {
		DEBUG(10, ("Unable to link %s to %s: %s\n",
			alt_path, 
			real_path,
			strerror(errno)));
		res = false;
		goto out;
	}

	if (!send_cmd(write_cmd)) {
		DEBUG(1, ("Unable to send command: %s\n", strerror(errno)));
		res = false;
		goto out;
	}

out:
	talloc_free(alt_path);
	talloc_free(real_path);

	return res;

}

/*
 * Connect to Amazon S3 and create our threads.
 */
static int amazon_s3_init(struct amazon_context_struct *ctx)
{
	int res = -1;
	char *host_header = NULL, *auth_header = NULL, *date_header = NULL;
	CURLcode c_res = CURLE_OK;
	struct s3_request_struct *req = NULL;

	if ((res = pthread_mutex_init(&ctx->w_mutex, NULL)) < 0) {
		DEBUG(0, ("Unable to initialize mutex: %s\n", 
			  strerror(errno)));
		return res;
	}

	if ((res = pthread_cond_init(&ctx->w_cond, NULL)) < 0) {
		DEBUG(0, ("Unable to initialize condition variable: %s\n",
			  strerror(errno)));
		return res;
	}

	ctx->c_handle = curl_easy_init(); /* Init the easy interface */

	req = create_request(HDR_GET, ctx, ctx);
	/*
	 * Now, add the required headers and then do a get on / to see
	 * if the user config is correct.
	 */
	if (!set_content_type(req, "text/plain")) {
		DEBUG(0, ("Unable to add Content-Type header (%s)\n",
			strerror(errno)));
		return -1;
	}

	if (!set_uri(req, "/")) {
		DEBUG(0, ("Unable to add URI / (%s)\n", strerror(errno)));
		return -1;
	}

	if (!add_param(req, &req->uri_params, "max-keys", "0")) {
		DEBUG(0, ("Unable to add params (%s)\n", strerror(errno)));
		return -1;
	}

	DEBUG(10, ("req->uri_params = %p\n", req->uri_params));

	/*
	 * Some more items needed, ie, the callback functions and etc
	 */
	req->recv_data = recv_data;
	req->recv_hdr  = recv_hdr;

	if (execute_request(ctx, req, ctx->c_handle)) {
		DEBUG(0, ("Unable to execute request, disabled\n"));
		ctx->enabled = false;
		curl_easy_cleanup(ctx->c_handle);
	}

	/*
	 * Free up the request because we are finished with the request
	 */
	talloc_free(req); 

	/*
	 * Initialize the semaphores. send_sem's value sets the size of
	 * the queue ... Should use variables ...
	 */
	res = sem_init(&send_sem, 0, WRITE_QUEUE_SIZE); 
	if (res) {
		DEBUG(1, ("Unable to initialize send_sem: %s\n",
			strerror(errno)));
		return res;
	}

	res = sem_init(&recv_sem, 0, 0);
	if (res) {
		DEBUG(1, ("Unable to initialize recv_sem: %s\n",
			strerror(errno)));
		return res;
	}

	res = pthread_create(&ctx->w_thread, 
			     NULL, 
			     amazon_write_thread, 
			     (void *)ctx);

	return res;
}

/*
 * Handle a connection. We create our threads and then call the NEXT fn.
 */
static int amazon_s3_connect(vfs_handle_struct *handle,
			     const char  *service,
			     const char *user)
{
	int res = 0;
	struct amazon_context_struct *ctx;
	CURLcode c_res = CURLE_OK;

	/*
	 * Do our stuff here, including creating a context and starting
	 * threads.
	 */

	/*
	 * We need to init curl, but only once for all the shares that we
	 * might be attached to.
	 */
	if (!curl_global_init_done) {
		c_res = curl_global_init(CURL_GLOBAL_ALL);
		if (c_res != CURLE_OK) {
			DEBUG(0, ("Unable to init CURL: %u\n", c_res));
			return -1;
		}
		curl_global_init_done = true;
	}

	ctx = talloc_zero(handle, struct amazon_context_struct);
	if (!ctx) {
		DEBUG(0, ("Unable to allocate memory for our context, can't proceed!\n"));
		errno = ENOMEM;
		return -1;
	}
	/*
	 * Find out if we have been configured, and if not, there is not much
	 * we can do. Just pass all ops through and keep going.
	 */
	ctx->access_key = lp_parm_const_string(SNUM(handle->conn),
					       S3_MODULE_NAME,
					       "access key",
					       NULL);

	ctx->secret_key = lp_parm_const_string(SNUM(handle->conn),
					       S3_MODULE_NAME,
					       "secret key",
					       NULL);

	ctx->bucket = lp_parm_const_string(SNUM(handle->conn),
					   S3_MODULE_NAME,
					   "bucket",
					   NULL);

	ctx->reloc_dir = lp_parm_const_string(SNUM(handle->conn),
					      S3_MODULE_NAME,
					      "reloc dir",
					      NULL);

	if (ctx->access_key && ctx->bucket && ctx->reloc_dir && ctx->secret_key)
		ctx->enabled = true;
	else {
		DEBUG(0, ("At least one of our parameters ('access key', "
			"'bucket', 'reloc dir' and 'secret key') has not "
			"been set. We cannot function!"));
		return -1;
	}

	SMB_VFS_HANDLE_SET_DATA(handle, ctx, NULL,
				struct db_context, return -1);

	res = amazon_s3_init(ctx);
	if (res < 0) {
		DEBUG(0, ("Unable to connect to Amazon S3: %s\n",
			strerror(errno)));
		/*
		 * We cannot continue, so return an error. Memory has been 
		 * allocated using talloc from the handle, so it will be
		 * cleaned up.
		 */
		return -1;
	}

	res = SMB_VFS_NEXT_CONNECT(handle, service, user);
	return res;
}

/*
 * Handle an opendir request. We might have to fiddle with files that are
 * still being copied but should have been deleted. Not sure if we need this
 * yet.
 */
static SMB_STRUCT_DIR *amazon_s3_opendir(vfs_handle_struct *handle,
					 const char *fname,
					 const char *mask,
					 uint32 attr)
{
	SMB_STRUCT_DIR *res;

	res = SMB_VFS_NEXT_OPENDIR(handle, fname, mask, attr);
	return res;
}

/*
 * Handle an FD-based opendir. Not sure if we need this yet.
 */
static SMB_STRUCT_DIR *amazon_s3_fdopendir(vfs_handle_struct *handle,
					   files_struct *fsp,
					   const char *mask,
					   uint32 attr)
{
	SMB_STRUCT_DIR *res;

	res = SMB_VFS_NEXT_FDOPENDIR(handle, fsp, mask, attr);
	return res;
}

/*
 * Handle a readdir request
 */
static SMB_STRUCT_DIRENT *amazon_s3_readdir(vfs_handle_struct *handle,
					    SMB_STRUCT_DIR *dirp,
					    SMB_STRUCT_STAT *sbuf)
{
	SMB_STRUCT_DIRENT *res;

	res = SMB_VFS_NEXT_READDIR(handle, dirp, sbuf);
	return res;
}

/*
 * Handle a seekdir
 */
static void amazon_s3_seekdir(vfs_handle_struct *handle, 
			      SMB_STRUCT_DIR *dirp,
			      long offset)
{
	SMB_VFS_NEXT_SEEKDIR(handle, dirp, offset);
}

/*
 * Handle a telldir
 */

static long amazon_s3_telldir(vfs_handle_struct *handle,
			      SMB_STRUCT_DIR *dirp)
{
	long res;

	res = SMB_VFS_NEXT_TELLDIR(handle, dirp);
	return res;
}

/*
 * Open a file and keep track of it ... in case it is changed.
 */
static int amazon_s3_open(vfs_handle_struct *handle,
			  struct smb_filename *smb_fname,
			  files_struct *fsp, 
			  int flags,
			  mode_t mode)
{
	int res = -1;
	bool file_existed = VALID_STAT(smb_fname->st);
	struct vsp_extension_struct *my_files_stuff;

	my_files_stuff = (struct vsp_extension_struct *)VFS_ADD_FSP_EXTENSION(
						handle, 
						fsp,
						struct vsp_extension_struct,
						NULL);

	if (!my_files_stuff) {
		DEBUG(1, ("Unable to allocate space for extension for "
			"file %s\n",
			smb_fname_str_dbg(smb_fname)));
		return res;
	}

	my_files_stuff->save_file = !file_existed;

	res = SMB_VFS_NEXT_OPEN(handle, smb_fname, fsp, flags, mode);

	return res;
}

/*
 * Handle a create_file request
 */
static NTSTATUS amazon_s3_create_file(vfs_handle_struct *handle,
				      struct smb_request *req,
				      uint16_t root_dir_fid,
				      struct smb_filename *smb_fname,
				      uint32_t access_mask,
				      uint32_t share_access,
				      uint32_t create_disposition,
				      uint32_t create_options,
				      uint32_t file_attributes,
				      uint32_t oplock_request,
				      uint64_t allocation_size,
				      uint32_t private_flags,
				      struct security_descriptor *sd,
				      struct ea_list *ea_list,
				      files_struct **result,
				      int *pinfo)
{
	NTSTATUS res;
	bool file_existed = VALID_STAT(smb_fname->st);
	struct vsp_extension_struct *my_files_stuff;

	res = SMB_VFS_NEXT_CREATE_FILE(handle,
				       req,
				       root_dir_fid,
				       smb_fname,
				       access_mask,
				       share_access,
				       create_disposition,
				       create_options,
				       file_attributes,
				       oplock_request,
				       allocation_size,
				       private_flags,
				       sd,
				       ea_list,
				       result,
				       pinfo);

	my_files_stuff = (struct vsp_extension_struct *)VFS_ADD_FSP_EXTENSION(
						handle, 
						*result,
						struct vsp_extension_struct,
						NULL);

	if (!NT_STATUS_IS_OK(res))
		return res;  /* Didn't get it, too bad */

	/*
	 * add our stuff
	 */
	if (!my_files_stuff) {
		DEBUG(1, ("Unable to allocate space for extension for "
			"file %s\n",
			smb_fname_str_dbg(smb_fname)));
		SMB_VFS_CLOSE(*result);  /* Can't leave this open */
		return NT_STATUS_NO_MEMORY;
	}

	my_files_stuff->save_file = !file_existed;

	return res;
}

/*
 * Handle a close ... schedule the file to be moved to S3 if it was written
 *
 * What about DELETE ON CLOSE? Do we need to save such files?
 */
static int amazon_s3_close(vfs_handle_struct *handle, files_struct *fsp)
{
	int res = -1;
	struct vsp_extension_struct *my_stuff = NULL;

	res = SMB_VFS_NEXT_CLOSE(handle, fsp);

	/*
	 * If something went wrong, don't push this file up ... is that the
	 * correct decision?
	 */
	if (res) {
		DEBUG(1, ("Closing file %s failed (%s). Not scheduling for "
			"upload!\n",
			fsp_str_dbg(fsp),
			strerror(errno)));
		goto error;
	}

	my_stuff = (struct vsp_extension_struct *)VFS_FETCH_FSP_EXTENSION(
							handle,
							fsp);

	if (my_stuff->save_file) {
		struct amazon_context_struct *ctx;

		SMB_VFS_HANDLE_GET_DATA(handle, 
					ctx, 
					struct amazon_context_struct,
					res = -1; goto error;);
		(void)send_file_to_thread(fsp, ctx);
	}

	return res;
error:
	return res;
}

/*
 * Handle a read ... need to coordinate with the background threads if this
 * file was a previous version.
 */
static ssize_t amazon_s3_read(vfs_handle_struct *handle,
			      files_struct *fsp,
			      void *data,
			      size_t n)
{
	ssize_t res = -1;

	res = SMB_VFS_NEXT_READ(handle, fsp, data, n);
	return res;
}

/*
 * Handle pread
 */
static ssize_t amazon_s3_pread(vfs_handle_struct *handle,
			       files_struct *fsp,
			       void *data,
			       size_t n,
			       SMB_OFF_T offset)
{
	ssize_t res = -1;

	res = SMB_VFS_NEXT_PREAD(handle, fsp, data, n, offset);
	return res;
}

/*
 * Handle a write
 */
static ssize_t amazon_s3_write(vfs_handle_struct *handle,
			       files_struct *fsp,
			       const void *data,
			       size_t n)
{
	ssize_t res;
	struct vsp_extension_struct *my_stuff = NULL;

	res = SMB_VFS_NEXT_WRITE(handle, fsp, data, n);

	/*
	 * If something went wrong, don't push this file up ... is that the
	 * correct decision?
	 */
	if (res < 0) {
		DEBUG(1, ("Writing file %s failed (%s). Not scheduling for "
			"upload!\n",
			fsp_str_dbg(fsp),
			strerror(errno)));
		return res;
	}

	my_stuff = (struct vsp_extension_struct *)VFS_FETCH_FSP_EXTENSION(
							handle,
							fsp);

	my_stuff->save_file = true;

	return res;
}

/*
 * Handle a pwrite
 */
static ssize_t amazon_s3_pwrite(vfs_handle_struct *handle, 
				files_struct *fsp,
				const void *data,
				size_t n,
				SMB_OFF_T offset)
{
	ssize_t res;
	struct vsp_extension_struct *my_stuff = NULL;

	res = SMB_VFS_NEXT_PWRITE(handle, fsp, data, n, offset);

	/*
	 * If something went wrong, don't push this file up ... is that the
	 * correct decision?
	 */
	if (res < 0) {
		DEBUG(1, ("pWriting file %s failed (%s). Not scheduling for "
			"upload!\n",
			fsp_str_dbg(fsp),
			strerror(errno)));
		return res;
	}

	my_stuff = (struct vsp_extension_struct *)VFS_FETCH_FSP_EXTENSION(
							handle,
							fsp);

	my_stuff->save_file = true;

	return res;
}

/*
 * Handle an lseek request ... might need to wait until enough data is down
 */
static SMB_OFF_T amazon_s3_lseek(vfs_handle_struct *handle,
				 files_struct *fsp,
				 SMB_OFF_T offset,
				 int whence)
{
	SMB_OFF_T res = 0;

	res = SMB_VFS_NEXT_LSEEK(handle, fsp, offset, whence);
	return res;
}

/*
 * Handle a sendfile request. This is a read request ...
 */
static ssize_t amazon_s3_sendfile(vfs_handle_struct *handle,
				  int tofd,
				  files_struct *fromfsp,
				  const DATA_BLOB *hdr,
				  SMB_OFF_T offset,
				  size_t n)
{
	ssize_t res = -1;

	res = SMB_VFS_NEXT_SENDFILE(handle, tofd, fromfsp, hdr, offset, n);
	return res;
}

/*
 * Handle a recvfile request. This is a write request ...
 */


static ssize_t amazon_s3_recvfile(vfs_handle_struct *handle,
				  int fromfd,
				  files_struct *tofsp,
				  SMB_OFF_T offset,
				  size_t n)
{
	ssize_t res = -1;

	res = SMB_VFS_NEXT_RECVFILE(handle, fromfd, tofsp, offset, n);
	return res;
}

/*
 * Handle an ftruncate request ...
 */
static int amazon_s3_ftruncate(vfs_handle_struct *handle,
			       files_struct *fsp,
			       SMB_OFF_T len)
{
	int res = -1;

	res = SMB_VFS_NEXT_FTRUNCATE(handle, fsp, len);
	return res;
}

/*
 * Handle an fallocate request ...
 */
static int amazon_s3_fallocate(vfs_handle_struct *handle,
			       files_struct *fsp,
			       enum vfs_fallocate_mode mode,
			       SMB_OFF_T offset,
			       SMB_OFF_T len)
{
	int res = -1;

	res = SMB_VFS_NEXT_FALLOCATE(handle, fsp, mode, offset, len);
	return res;
}

/*
 * Handle an fsctl request
 */
static NTSTATUS amazon_s3_fsctl(vfs_handle_struct *handle,
				files_struct *fsp,
				TALLOC_CTX *ctx,
				uint32_t function,
				uint16_t req_flags,
				const uint8_t *_in_data,
				uint32_t in_len,
				uint8_t **_out_data,
				uint32_t max_out_len,
				uint32_t *out_len)
{
	NTSTATUS res = NT_STATUS_INVALID_PARAMETER; /* Is this wise? */

	res = SMB_VFS_NEXT_FSCTL(handle,
				 fsp,
				 ctx,
				 function,
				 req_flags,
				 _in_data,
				 in_len,
				 _out_data,
				 max_out_len,
				 out_len);
	return res;
}

static struct vfs_fn_pointers vfs_amazon_s3_fns = {
	.connect_fn = amazon_s3_connect,
	.opendir_fn = amazon_s3_opendir,
	.fdopendir_fn = amazon_s3_fdopendir,
	.readdir_fn = amazon_s3_readdir,
	.seekdir_fn = amazon_s3_seekdir,
	.telldir_fn = amazon_s3_telldir,

	.open_fn = amazon_s3_open,
	.create_file_fn = amazon_s3_create_file,
	.close_fn = amazon_s3_close,
	.read_fn = amazon_s3_read,
	.pread_fn = amazon_s3_pread,
	.write_fn = amazon_s3_write,
	.pwrite_fn = amazon_s3_pwrite,
	.lseek_fn = amazon_s3_lseek,
	.sendfile_fn = amazon_s3_sendfile,
	.recvfile_fn = amazon_s3_recvfile,
	.ftruncate_fn = amazon_s3_ftruncate,
	.fallocate_fn = amazon_s3_fallocate,
	.fsctl_fn = amazon_s3_fsctl,
};

NTSTATUS samba_init_module(void);
NTSTATUS samba_init_module(void)
{
	return smb_register_vfs(SMB_VFS_INTERFACE_VERSION,
				S3_MODULE_NAME,
				&vfs_amazon_s3_fns);
}
