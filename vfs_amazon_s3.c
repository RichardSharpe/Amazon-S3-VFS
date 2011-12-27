/*
 * Store stuff up on Amazon's S3 service.
 *
 * Copyright (C) Richard Sharpe, 2011
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

/*
 * Maintains the context for us, and we stash it in the handle
 */
struct amazon_context_struct {
	bool enabled;
	const char *access_key;
	const char *secret_key;
	const char *bucket;
	const char *reloc_dir;
	int meta_sock;         /* Socket for metadata ops    */
	CURL *c_handle;
	pthread_t w_thread;
	pthread_mutex_t w_mutex;
	pthread_cond_t w_cond;
	int write_sock;        /* Socket for upload thread   */
	pthread_t r_thread;
	int read_sock;         /* Socket for download thread */
};

/*
 * We hold any AMZ headers and URI params in this objects ...
 */

struct key_value_pair {
	struct key_value_pair *next, *prev;
	char *key_name;
	char *key_val;
};

/*
 * We construct the request in an object like this. It is all allocated using
 * talloc. We then transform it into a curl request. This object allows us to
 * easily construct the Authentication header as we have the original data
 * from the request.
 */

struct chunk_list {
	struct chunk_list *next, *prev;
	unsigned int chunk_size;
	uint8_t *chunk;
};

struct s3_response_struct {
	char *response_code;
	struct key_value_pair *headers;
	struct chunk_list *chunks;
};

enum request_type_enum {HDR_GET = 0, HDR_POST, HDR_PUT, HDR_DELETE, HDR_HEAD};

struct s3_request_struct {
	enum request_type_enum request_type;
	char *content_md5;       /* Kept separate because included in auth */
	char *content_type;      /* hash, as is this field                 */
	char date[128];          /* and this field                         */
	bool has_x_amz_date;     /* In case we have both                   */
	char *uri;
	struct key_value_pair *uri_params;
	struct key_value_pair *amz_headers;
	struct s3_response_struct *response;
	struct amazon_context_struct *amz_ctx; /* Other stuff we need */
	void *tmp_context;       /* Used to collect together tmp memory */
};

static pthread_t w_thread;

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
 * A pair of functions to generate the hmac_sha1 hash and base64 encode it.
 * They need the request structure for the key and use it as a context for
 * talloc allocations.
 */

/*
 * Base64 encode a buffer passed in. Return a talloc allocated string.
 */
static char *base64_enc(struct s3_request_struct *req, 
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
	ret_str = talloc_strndup(req, bio_mem->data, bio_mem->length);

	BIO_free_all(b64_filter);

	return ret_str;
}

/*
 * Generate the base64 encoded sha1 hash of string str using the secret key 
 * in the amazon_context_struct pointed to in request.
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

	return base64_enc(req, hmac_sha1_buf, hmac_sha1_len);
}

/*
 * Handle the curl response data
 */
static size_t recv_data(void *data, size_t size, size_t nmemb, void *ctx)
{
	DEBUG(10, ("Received size = %zu nmemb = %zu\n", size, nmemb));

	return nmemb * size;
}

/*
 * Handle the curl response headers
 */
static size_t recv_hdr(void *data, size_t size, size_t nmemb, void *ctx)
{
	DEBUG(10, ("Received size = %zu nmemb = %zu\n", size, nmemb));
	DEBUG(10, ("Hdr: %s\n", data));

	return nmemb * size;
}

/*
 * Create a request of the appropriate type. We fill in the important fields
 * at this time, including the data field.
 */
static struct s3_request_struct *create_request(enum request_type_enum request_type,
					 struct amazon_context_struct *ctx)
{
	struct s3_request_struct *req = NULL;
	time_t sys_time;
	struct tm tm;

	req = talloc_zero(ctx, struct s3_request_struct);
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
	       struct key_value_pair *list,
	       const char *name,
	       const char *val)
{
	struct key_value_pair *kvp = talloc_zero(req, struct key_value_pair);

	kvp->key_name = talloc_strdup(kvp, name);
	kvp->key_val = talloc_strdup(kvp, val);

	DLIST_ADD_END(list, kvp, struct key_value_pair *);

	return kvp != NULL;
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
	string_to_enc = talloc_asprintf(talloc_tos(), 
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
	char *uri = talloc_strdup(talloc_tos(), req->uri);
	struct key_value_pair *uri_params = req->uri_params;

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
 * Execute an HTTP request via CURL, including handling the authorization 
 * header. We handle all the curl stuff here.
 */
int execute_request(struct amazon_context_struct *ctx, 
		    struct s3_request_struct *req)
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

	url = talloc_asprintf(talloc_tos(), "http://s3.amazonaws.com%s", uri);

	DEBUG(10, ("URL: %s\n", url));

	curl_easy_setopt(ctx->c_handle, CURLOPT_URL, url);

	/*
	 * Add headers ...
	 */
	if (req->content_type) {
		content_type = talloc_asprintf(talloc_tos(),
					       "Content-type: %s",
					       req->content_type);
		headers = curl_slist_append(headers, content_type);
	}

	host_header = talloc_asprintf(talloc_tos(), 
				      "Host: %s.s3.amazonaws.com",
				      ctx->bucket);
	if (!host_header) {
		DEBUG(10, ("Unable to allocate space for Host header\n"));
		return -1;
	}

	headers = curl_slist_append(headers, host_header);

	date_header = talloc_asprintf(talloc_tos(), "Date: %s", req->date);

	headers = curl_slist_append(headers, date_header);

	auth = get_auth_string(req);  /* We can talloc_free this later */

	DEBUG(10, ("Authorization: %s\n", auth));

	auth[strlen(auth) - 1] = 0;  /* There is a stray new-line here */

	auth_header = talloc_asprintf(talloc_tos(), 
					"Authorization: AWS %s:%s",
					ctx->access_key,
					auth);

	DEBUG(10, ("Auth hdr: %s\n", auth_header));

	headers = curl_slist_append(headers, auth_header);

	c_res = curl_easy_setopt(ctx->c_handle, CURLOPT_HTTPHEADER, headers);
	if (c_res != CURLE_OK) {
		DEBUG(0, ("Setting headers failed: %s\n", 
			curl_easy_errstr(c_res)));
		return -1;
	}

	curl_easy_setopt(ctx->c_handle, CURLOPT_NOPROGRESS, 1L);
	curl_easy_setopt(ctx->c_handle, CURLOPT_WRITEFUNCTION, recv_data);
	curl_easy_setopt(ctx->c_handle, CURLOPT_WRITEDATA, (void *)ctx);
	curl_easy_setopt(ctx->c_handle, CURLOPT_HEADERFUNCTION, recv_hdr);
	curl_easy_setopt(ctx->c_handle, CURLOPT_WRITEHEADER, (void *)ctx);

	c_res = curl_easy_perform(ctx->c_handle);
	if (c_res != CURLE_OK) {
		DEBUG(0, ("Performing request %s failed: %s\n",
			get_verb_str(req), 
			curl_easy_strerror(c_res)));
		return -1;
	}

	return res;
}

/*
 * Upload thread ...
 */
void *amazon_write_thread(void * param)
{

	return 0;
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

	req = create_request(HDR_GET, ctx);
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

	if (!add_param(req, req->uri_params, "max-keys", "0")) {
		DEBUG(0, ("Unable to add params (%s)\n", strerror(errno)));
		return -1;
	}

	if (!execute_request(ctx, req)) {

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
	return res;
}

/*
 * Handle a close ... schedule the file to be moved to S3 if it was written
 */
static int amazon_s3_close(vfs_handle_struct *handle, files_struct *fsp)
{
	int res;

	res = SMB_VFS_NEXT_CLOSE(handle, fsp);
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

	res = SMB_VFS_NEXT_WRITE(handle, fsp, data, n);
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

	res = SMB_VFS_NEXT_PWRITE(handle, fsp, data, n, offset);
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
