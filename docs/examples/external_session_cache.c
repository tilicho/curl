/***************************************************************************
 *                                  _   _ ____  _
 *  Project                     ___| | | |  _ \| |
 *                             / __| | | | |_) | |
 *                            | (__| |_| |  _ <| |___
 *                             \___|\___/|_| \_\_____|
 *
 * Copyright (C) 1998 - 2015, Daniel Stenberg, <daniel@haxx.se>, et al.
 *
 * This software is licensed as described in the file COPYING, which
 * you should have received as part of this distribution. The terms
 * are also available at https://curl.haxx.se/docs/copyright.html.
 *
 * You may opt to use, copy, modify, merge, publish, distribute and/or sell
 * copies of the Software, and permit persons to whom the Software is
 * furnished to do so, under the terms of the COPYING file.
 *
 * This software is distributed on an "AS IS" basis, WITHOUT WARRANTY OF ANY
 * KIND, either express or implied.
 *
 ***************************************************************************/
/* <DESC>
 * CUSTOM HTTPS CERTIFICATE REVOCATION CHECK USING CRL
 * </DESC>
 */
#include <stdio.h>
#include <curl/curl.h>
#include <openssl/ssl.h>
#include <openssl/x509.h>
#include <openssl/ocsp.h>
#include <openssl/stack.h>

#define DEBUG_CURL_OUTPUT 0L

static int ssl_index = -1;

/*ssl index to store path to ssl session cache file*/
int get_ssl_index()
{
  if(ssl_index == -1)
    ssl_index =
      SSL_CTX_get_ex_new_index(0, "ctx parameter name", NULL, NULL, NULL);
  return ssl_index;
}

int save_ssl_session(const char *session_file, SSL_SESSION *session)
{
  int result = 0;
  int len;
  unsigned char *buf = NULL;
  unsigned char *temp;
  FILE *fout = NULL;
  int writed = 0;

  len = i2d_SSL_SESSION(session, NULL);
  if(len > 0) {
    temp = buf = malloc(len);
    if(!temp) {
      fprintf(stderr, "malloc %i failed\n", len);
      goto end;
    }

    i2d_SSL_SESSION(session, &temp);

    fout = fopen(session_file, "wb");
    if(!fout) {
      fprintf(stderr, "fopen %s failed\n", session_file);
      goto end;
    }

    fwrite(&len, sizeof(len), 1, fout);
    fwrite(buf, len, 1, fout);
  }

  result = 0;

end:
  if(fout)
    fclose(fout);

  if(buf)
    free(buf);

  return result;
}

int read_ssl_session(const char *session_file, SSL_SESSION **session)
{
  FILE *fin = NULL;
  int result = 0;
  int len = 0;
  unsigned char *buf = NULL;

  fin = fopen(session_file, "rb");
  if(!fin) {
    fprintf(stderr, "fopen %s failed\n", session_file);
    goto end;
  }

  int res = fread(&len, 1, sizeof(len), fin);
  if(res != sizeof(len)) {
    fprintf(stderr, "fread failed %i\n", res);
    goto end;
  }

  buf = malloc(len);
  if(!buf) {
    fprintf(stderr, "malloc %i failed\n", len);
    goto end;
  }

  if(fread(buf, 1, len, fin) != len) {
    fprintf(stderr, "fread %i failed\n", len);
    goto end;
  }

  const unsigned char *tmp_buf = buf;

  *session = d2i_SSL_SESSION(NULL, &tmp_buf, len);
  if(!*session) {
    fprintf(stderr, "d2i_SSL_SESSION failed\n");
    goto end;
  }

  result = 1;

end:
  if(buf)
    free(buf);

  if(fin)
    fclose(fin);

  return result;
}

/*callback to save new ssl session*/
int new_session_cb(SSL *ssl, SSL_SESSION *session)
{
  SSL_CTX *ctx = SSL_get_SSL_CTX(ssl);
  const char *session_file;

  session_file = (const char *)SSL_CTX_get_ex_data(ctx, get_ssl_index());

  fprintf(
    stdout, "new_session_cb - saving ssl session to file %s\n", session_file);

  save_ssl_session(session_file, session);

  return 0;
}

/*callback to print if ssl session was reused*/
void ssl_info_callback(const SSL *s, int where, int ret)
{
  int sessionWasReused;
  if(where & SSL_CB_HANDSHAKE_DONE) {
    sessionWasReused = SSL_session_reused((SSL *)s);
    fprintf(stdout, "sessionWasReused = %i\n", sessionWasReused);
  }
}

/*callback is called by curl just before establishing ssl connection. useful if
 * you want to set ssl session from file*/
static CURLcode ssl_init_function(CURL *curl, void *ssl, void *parm)
{
  const char *session_file = (const char *)parm;
  SSL *s = (SSL *)ssl;
  SSL_CTX *ctx = SSL_get_SSL_CTX(ssl);
  SSL_SESSION *session = NULL;

  fprintf(stdout,
          "ssl_init_function - reading ssl session from file %s\n",
          session_file);

  /*current proper way to make ssl session tickets work finally*/
  SSL_clear_options(s, SSL_OP_NO_TICKET);

  /*add custom data to ssl */
  SSL_CTX_set_ex_data(ctx, get_ssl_index(), (void *)session_file);

  /*set callback of new ssl session - to save new session in file*/
  SSL_CTX_sess_set_new_cb(ctx, new_session_cb);

  /*callback to check if session was reused finally*/
  SSL_CTX_set_info_callback(ctx, ssl_info_callback);

  if(!read_ssl_session(session_file, &session))
    goto end;

  if(SSL_set_session(ssl, session)) {
    fprintf(stdout, "SSL_set_session succeeded\n");
  }

end:
  if(session)
    SSL_SESSION_free(session);

  return CURLE_OK;
}

int main(int argc, char **argv)
{
  CURL *curl;
  CURLcode res;

  if(argc != 4) {
    fprintf(stderr,
            "provide options: url certificate.pem ssl_session_file_name\n");
    return -1;
  }

  curl_global_init(CURL_GLOBAL_DEFAULT);

  curl = curl_easy_init();
  if(curl) {
    fprintf(
      stdout,
      "Http GET from url %s \n certificates file %s ssl session file %s\n",
      argv[1],
      argv[2],
      argv[3]);

    curl_easy_setopt(curl, CURLOPT_URL, argv[1]);
    curl_easy_setopt(curl, CURLOPT_CAINFO, argv[2]);
    curl_easy_setopt(curl, CURLOPT_SSL_VERIFYPEER, 1L);
    curl_easy_setopt(curl, CURLOPT_SSL_VERIFYHOST, 1L);
    curl_easy_setopt(curl, CURLOPT_VERBOSE, DEBUG_CURL_OUTPUT);
    /*do not use curl internal ssl cache. because we want to use our external
     * ssl cache file.*/
    curl_easy_setopt(curl, CURLOPT_SSL_SESSIONID_CACHE, 0);
    curl_easy_setopt(curl, CURLOPT_SSL_FUNCTION, &ssl_init_function);
    /*our custom parameter is path to ssl session cache file*/
    curl_easy_setopt(curl, CURLOPT_SSL_DATA, (void *)(argv[3]));

    res = curl_easy_perform(curl);
    if(res != CURLE_OK)
      fprintf(
        stderr, "curl_easy_perform() failed: %s\n", curl_easy_strerror(res));

    curl_easy_cleanup(curl);
  }

  curl_global_cleanup();

  return 0;
}
