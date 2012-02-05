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

struct chunk_list_struct {
	struct chunk_list_struct *next, *prev;
	unsigned int chunk_size;
	uint8_t *chunk;
};

struct s3_response_struct {
	char *response_code;           /* The response as a string */
	struct key_value_pair *headers;
	struct chunk_list_struct *chunks;
	struct key_value_pair *error;  /* Might have to move       */
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
	long response_code;
	struct s3_response_struct *response;
	struct amazon_context_struct *amz_ctx; /* Other stuff we need */
	void *tmp_context;       /* Used to collect together tmp memory */
};

struct vsp_extension_struct {
	bool save_file;           /* Whether the file needs to be uploaded */
};

/*
 * We send a command to the write thread ... not many at this stage
 */

#define WRITE_QUEUE_SIZE 10

enum write_thread_enum {WRT_EXIT = 0, WRT_SEND_FILE};

struct write_thread_struct {
	enum write_thread_enum cmd;
	char *file_path;           /* The path in the share */
	char *hash_name;           /* Where we put it in the file system */
};

