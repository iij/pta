/*
 *  Copyright Internet Initiative Japan Inc. 
 *
 *  The terms and conditions of the accompanying program
 *  shall be provided separately by Internet Initiative Japan Inc.
 *
 *  Any use, reproduction or distribution of the program are permitted
 *  provided that you agree to be bound to such terms and conditions.
 *
 */

#include <ngx_core.h>
#include <ngx_http.h>
#include <ngx_config.h>
#include <ngx_http_request.h>

#include <openssl/aes.h>

#include <syslog.h>

typedef struct
{
    ngx_str_t key_1st;
    ngx_str_t iv_1st;
    ngx_str_t key_2nd;
    ngx_str_t iv_2nd;
} ngx_http_pta_srv_conf_t;

typedef struct
{
    ngx_flag_t pta_onoff;
    ngx_uint_t pta_auth_method;
} ngx_http_pta_loc_conf_t;

typedef struct
{
    uint32_t crc;
    time_t deadline;
    u_char *url;
    uint8_t padding_val;
} ngx_http_pta_data_t;

typedef struct
{
    ngx_str_t encrypt_string;
    uint8_t *encrypt_data;
    size_t encrypt_data_len;
    ngx_http_pta_data_t decrypt_data;
    ngx_array_t *encrypt_data_array;
    uint16_t encrypt_data_array_idx;
    uint8_t need_fallback_cookie;
    uint8_t auth_type;
} ngx_http_pta_info_t;

#define QUERY_PARAM  "pta"

static ngx_int_t ngx_http_pta_check_crc (ngx_http_pta_info_t *);
static ngx_int_t ngx_http_pta_init (ngx_conf_t *);
static ngx_int_t ngx_http_pta_handler (ngx_http_request_t *);
static void *ngx_http_pta_create_srv_conf (ngx_conf_t *);
static void *ngx_http_pta_create_loc_conf (ngx_conf_t *);
static char *ngx_http_pta_merge_loc_conf (ngx_conf_t *, void *, void *);
static char *ngx_http_pta_set_1st_key (ngx_conf_t *, ngx_command_t *, void *);
static char *ngx_http_pta_set_1st_iv (ngx_conf_t *, ngx_command_t *, void *);
static char *ngx_http_pta_set_2nd_key (ngx_conf_t *, ngx_command_t *, void *);
static char *ngx_http_pta_set_2nd_iv (ngx_conf_t *, ngx_command_t *, void *);

#define NGX_IIJPTA_AUTH_QS          0x0002
#define NGX_IIJPTA_AUTH_COOKIE      0x0004

#define NGX_HTTP_PTA_FALLBACK  21

static ngx_conf_bitmask_t ngx_http_secure_token_iijpta_auth_method[] = {
    {ngx_string ("qs"), NGX_IIJPTA_AUTH_QS},
    {ngx_string ("cookie"), NGX_IIJPTA_AUTH_COOKIE},
    {ngx_null_string, 0}
};

static ngx_command_t ngx_http_pta_commands[] = {
    {ngx_string ("pta_1st_key"),
     NGX_HTTP_SRV_CONF | NGX_CONF_TAKE1,
     ngx_http_pta_set_1st_key,
     NGX_HTTP_SRV_CONF_OFFSET,
     0,
     NULL},
    {ngx_string ("pta_1st_iv"),
     NGX_HTTP_SRV_CONF | NGX_CONF_TAKE1,
     ngx_http_pta_set_1st_iv,
     NGX_HTTP_SRV_CONF_OFFSET,
     0,
     NULL},
    {ngx_string ("pta_2nd_key"),
     NGX_HTTP_SRV_CONF | NGX_CONF_TAKE1,
     ngx_http_pta_set_2nd_key,
     NGX_HTTP_SRV_CONF_OFFSET,
     0,
     NULL},
    {ngx_string ("pta_2nd_iv"),
     NGX_HTTP_SRV_CONF | NGX_CONF_TAKE1,
     ngx_http_pta_set_2nd_iv,
     NGX_HTTP_SRV_CONF_OFFSET,
     0,
     NULL},
    {ngx_string ("pta_enable"),
     NGX_HTTP_LOC_CONF | NGX_CONF_FLAG,
     ngx_conf_set_flag_slot,
     NGX_HTTP_LOC_CONF_OFFSET,
     offsetof (ngx_http_pta_loc_conf_t, pta_onoff),
     NULL},
    {ngx_string ("pta_auth_method"),
     NGX_HTTP_LOC_CONF | NGX_CONF_1MORE,
     ngx_conf_set_bitmask_slot,
     NGX_HTTP_LOC_CONF_OFFSET,
     offsetof (ngx_http_pta_loc_conf_t, pta_auth_method),
     &ngx_http_secure_token_iijpta_auth_method},

    ngx_null_command
};

static ngx_http_module_t ngx_http_pta_module_ctx = {
    NULL,                       /* preconfiguration */
    ngx_http_pta_init,          /* postconfiguration */

    NULL,                       /* create main configuration */
    NULL,                       /* init main configuration */

    ngx_http_pta_create_srv_conf,       /* create server configuration */
    NULL,                       /* merge server configuration */

    ngx_http_pta_create_loc_conf,       /* create location configuration */
    ngx_http_pta_merge_loc_conf /* merge location configuration */
};

ngx_module_t ngx_http_pta_module = {
    NGX_MODULE_V1,
    &ngx_http_pta_module_ctx,
    ngx_http_pta_commands,
    NGX_HTTP_MODULE,
    NULL,
    NULL,
    NULL,
    NULL,
    NULL,
    NULL,
    NULL,
    NGX_MODULE_V1_PADDING
};

ngx_int_t
ngx_http_pta_parse_cookie_header (ngx_array_t * headers, ngx_str_t * name,
                                  ngx_array_t * values)
{
    ngx_uint_t i;
    u_char *start, *last, *end, ch;
    ngx_table_elt_t **h;
    ngx_str_t *value;

    h = headers->elts;

    for (i = 0; i < headers->nelts; i++)
      {
          ngx_log_debug2 (NGX_LOG_DEBUG_HTTP, headers->pool->log, 0,
                          "parse header: \"%V: %V\"", &h[i]->key,
                          &h[i]->value);

          if (name->len > h[i]->value.len)
            {
                continue;
            }

          start = h[i]->value.data;
          end = h[i]->value.data + h[i]->value.len;

          while (start < end)
            {
                if (ngx_strncasecmp (start, name->data, name->len) != 0)
                  {
                      goto skip;
                  }

                // skip space
                for (start += name->len; start < end && *start == ' ';
                     start++)
                  {
                      /* void */
                  }

                if (start == end || *start++ != '=')
                  {
                      goto skip;
                  }

                // skip space
                while (start < end && *start == ' ')
                  {
                      start++;
                  }

                for (last = start; last < end && *last != ';'; last++)
                  {
                      /* void */
                  }

                value = ngx_array_push (values);
                value->len = last - start;
                value->data = start;

                continue;

              skip:

                while (start < end)
                  {
                      ch = *start++;
                      if (ch == ';')
                        {
                            break;
                        }
                  }

                // skip space
                while (start < end && *start == ' ')
                  {
                      start++;
                  }
            }

      }

    return i;
}

static ngx_str_t *
ngx_http_pta_qparam_cat (ngx_http_request_t * r, ngx_str_t * base,
                         ngx_str_t * new, char *delim)
{
    u_char *ptr, *qtr;
    ngx_str_t *ret;

    ret = ngx_pnalloc (r->pool, sizeof (ngx_str_t));
    if (ret == NULL)
      {
          return NULL;
      }

    ret->len = ((base == NULL) ? 0 : base->len)
        + new->len + ((base == NULL) ? 0 : 1);

    ret->data = ngx_pnalloc (r->pool, ret->len);
    if (ret->data == NULL)
      {
          return NULL;
      }

    qtr = ret->data;
    if (base != NULL)
      {
          ptr = base->data;
          while (ptr < &base->data[base->len])
            {
                *qtr++ = *ptr++;
            }
          *qtr++ = *delim;
      }

    ptr = new->data;
    while (ptr < &new->data[new->len])
      {
          *qtr++ = *ptr++;
      }

    return ret;
}

static ngx_str_t *
ngx_http_pta_delete_arg (ngx_http_request_t * r, char *arg, size_t len)
{
    ngx_str_t *base = NULL;
    ngx_str_t param;

    u_char *pos = r->args.data;;
    if (pos == NULL)
      {
          // no query string;
          return NULL;
      }
    u_char *beg = pos;

    while (pos <= &r->args.data[r->args.len])
      {
          if (*pos == '=')
            {
                ngx_http_arg (r, beg, pos - beg, &param);

                if (!ngx_strnstr (beg, arg, len) || beg[len] != '=')
                  {
                      ngx_str_t new;
                      new.len = (pos - beg) + param.len + 1;
                      /* `=' contains */ ;
                      new.data = beg;
                      base = ngx_http_pta_qparam_cat (r, base, &new, "&");
                      if (base == NULL)
                        {
                            ngx_log_error (NGX_LOG_ERR, r->connection->log, 0,
                                           "ngx_http_pta_qparam_cat() failed");
                            return NULL;
                        }
                  }

                pos++;          /* pos indicates the first char of value next to `=' */
                pos += param.len + 1;   /* `&' contains */
                beg = pos;      /* pos and beg indicates the next param */

                continue;
            }

          pos++;
      }

    return base;
}

static uint8_t
ngx_http_pta_c2i (char c)
{
    if ('0' <= c && c <= '9')
      {
          return (c - '0');
      }
    else if ('a' <= c && c <= 'f')
      {
          return (c - ('a' - 10));
      }
    else if ('A' <= c && c <= 'F')
      {
          return (c - ('A' - 10));
      }

    return 0;
}

static ngx_int_t
ngx_http_pta_hex2bin (u_char * hex, size_t len, uint8_t * bin)
{
    size_t idx;

    if (len == 0)
      {
          return 1;
      }

    for (idx = 0; idx < (len / 2); idx++)
      {
          bin[idx] = ngx_http_pta_c2i (hex[2 * idx]) << 4;
          bin[idx] |= ngx_http_pta_c2i (hex[2 * idx + 1]);
      }

    return 0;
}

static ngx_int_t
ngx_http_pta_init (ngx_conf_t * cf)
{
    ngx_http_handler_pt *h;
    ngx_http_core_main_conf_t *cmcf;

    cmcf = ngx_http_conf_get_module_main_conf (cf, ngx_http_core_module);

    h = ngx_array_push (&cmcf->phases[NGX_HTTP_REWRITE_PHASE].handlers);
    if (h == NULL)
      {
          return NGX_ERROR;
      }

    *h = ngx_http_pta_handler;

    return NGX_OK;
}

static ngx_int_t
ngx_http_pta_set_encrypt_data_array (ngx_http_request_t * r,
                                     ngx_http_pta_info_t * pta)
{
    ngx_str_t key = ngx_string ("pta");

    pta->encrypt_data_array = ngx_pcalloc (r->pool, sizeof (ngx_array_t));
    if (pta->encrypt_data_array == NULL)
      {
          ngx_log_error (NGX_LOG_ERR, r->connection->log, 0,
                         "can't allocate memory for enctypt_data_array");
          return NGX_HTTP_INTERNAL_SERVER_ERROR;
      }

    if (ngx_array_init
        (pta->encrypt_data_array, r->pool, 3, sizeof (ngx_str_t)) != NGX_OK)
      {
          ngx_log_error (NGX_LOG_ERR, r->connection->log, 0,
                         "can't init for enctypt_data_array");
          return NGX_HTTP_INTERNAL_SERVER_ERROR;
      }
    ngx_http_pta_parse_cookie_header (&r->headers_in.cookies,
                                      &key, pta->encrypt_data_array);
    if (pta->encrypt_data_array->nelts == 0)
      {
          ngx_log_error (NGX_LOG_ERR, r->connection->log, 0,
                         "pta token is not found in cookie");
          return NGX_HTTP_BAD_REQUEST;
      }

    return NGX_OK;
}

static ngx_int_t
ngx_http_pta_build_info (ngx_http_request_t * r, ngx_http_pta_info_t * pta)
{
    ngx_int_t ret = 0;

    if (pta->auth_type == NGX_IIJPTA_AUTH_QS)
      {
          pta->encrypt_data_array = NULL;
          ret =
              ngx_http_arg (r, (u_char *) QUERY_PARAM,
                            sizeof (QUERY_PARAM) - 1, &pta->encrypt_string);
          if (pta->need_fallback_cookie && ret)
            {
                return NGX_HTTP_PTA_FALLBACK;
            }
          if (ret)
            {
                ngx_log_error (NGX_LOG_ERR, r->connection->log, 0,
                               "pta token is invalid #1");
                return NGX_HTTP_BAD_REQUEST;
            }
      }
    else if (pta->auth_type == NGX_IIJPTA_AUTH_COOKIE)
      {
          if (pta->encrypt_data_array == NULL)
            {
                ret = ngx_http_pta_set_encrypt_data_array (r, pta);
                if (ret != NGX_OK)
                  {
                      return ret;
                  }
            }
          if (pta->encrypt_data_array_idx < pta->encrypt_data_array->nelts)
            {
                pta->encrypt_string.data =
                    ((ngx_str_t *) pta->encrypt_data_array->elts)[pta->
                                                                  encrypt_data_array_idx].
                    data;
                pta->encrypt_string.len =
                    ((ngx_str_t *) pta->encrypt_data_array->elts)[pta->
                                                                  encrypt_data_array_idx].
                    len;
            }
          else
            {
                ngx_log_error (NGX_LOG_ERR, r->connection->log, 0,
                               "valid pta token is not found in cookie");
                return NGX_HTTP_BAD_REQUEST;
            }
      }
    else
      {
          ngx_log_error (NGX_LOG_ERR, r->connection->log, 0,
                         "auth_type is invalid: %d", pta->auth_type);
          return NGX_HTTP_INTERNAL_SERVER_ERROR;
      }

    if ((pta->encrypt_string.len % 2) != 0)
      {
          ngx_log_error (NGX_LOG_ERR, r->connection->log, 0,
                         "pta token is invalid #2");
          return NGX_HTTP_BAD_REQUEST;
      }

    pta->encrypt_data = ngx_pcalloc (r->pool, (pta->encrypt_string.len / 2));
    if (pta->encrypt_data == NULL)
      {
          ngx_log_error (NGX_LOG_ERR, r->connection->log, 0,
                         "can't allocate memory for enctypt_data");
          return NGX_HTTP_INTERNAL_SERVER_ERROR;
      }

    ret = ngx_http_pta_hex2bin (pta->encrypt_string.data,
                                pta->encrypt_string.len, pta->encrypt_data);
    if (ret)
      {
          ngx_log_error (NGX_LOG_ERR, r->connection->log, 0,
                         "encrypt string size is invalid");
          return NGX_HTTP_BAD_REQUEST;
      }

    pta->encrypt_data_len = pta->encrypt_string.len / 2;

    ngx_log_error (NGX_LOG_INFO, r->connection->log, 0,
                   "encrypt_string: %V auth_type: %s", &pta->encrypt_string,
                   pta->auth_type ==
                   NGX_IIJPTA_AUTH_QS ? "querystring" : "cookie");
    return 0;
}

static ngx_int_t
ngx_http_pta_init_auth_type (ngx_http_request_t * r,
                             ngx_http_pta_loc_conf_t * loc,
                             ngx_http_pta_info_t * pta)
{
    switch (loc->pta_auth_method)
      {
      case NGX_IIJPTA_AUTH_QS:
          {
              pta->auth_type = NGX_IIJPTA_AUTH_QS;
              break;
          }
      case NGX_IIJPTA_AUTH_COOKIE:
          {
              pta->auth_type = NGX_IIJPTA_AUTH_COOKIE;
              break;
          }
      case NGX_IIJPTA_AUTH_QS | NGX_IIJPTA_AUTH_COOKIE:
          {
              pta->need_fallback_cookie = 1;
              pta->auth_type = NGX_IIJPTA_AUTH_QS;
              break;
          }
      default:
          {
              pta->auth_type = NGX_IIJPTA_AUTH_QS;
              break;
          }
      }

    return 0;
}

static ngx_int_t
ngx_http_pta_decrypt (ngx_http_request_t * r, ngx_http_pta_srv_conf_t * srv,
                      ngx_http_pta_info_t * pta)
{
    int idx;
    ngx_int_t ret;
    AES_KEY aeskey;
    u_char *hex;
    size_t len;
    uint8_t *out;
    uint8_t key[16];
    uint8_t iv[16];

  again:
    ret = ngx_http_pta_build_info (r, pta);
    if (ret == NGX_HTTP_PTA_FALLBACK)
      {
          pta->need_fallback_cookie = 0;
          pta->auth_type = NGX_IIJPTA_AUTH_COOKIE;
          goto again;
      }
    if (ret)
      {
          return ret;
      }

    out = ngx_pcalloc (r->pool, pta->encrypt_data_len);
    if (out == NULL)
      {
          ngx_log_error (NGX_LOG_ERR, r->connection->log, 0,
                         "can't allocate memory");
          return NGX_HTTP_INTERNAL_SERVER_ERROR;
      }

    for (idx = 0; idx < 2; idx++)
      {
          hex = (idx == 0) ? srv->key_1st.data : srv->key_2nd.data;
          len = (idx == 0) ? srv->key_1st.len : srv->key_2nd.len;
          ret = ngx_http_pta_hex2bin (hex, len, key);
          if (ret)
            {
                continue;
            }

          hex = (idx == 0) ? srv->iv_1st.data : srv->iv_2nd.data;
          len = (idx == 0) ? srv->iv_1st.len : srv->iv_2nd.len;
          ret = ngx_http_pta_hex2bin (hex, len, iv);
          if (ret)
            {
                continue;
            }

          AES_set_decrypt_key (key, 128, &aeskey);
          AES_cbc_encrypt (pta->encrypt_data, out, pta->encrypt_data_len,
                           &aeskey, iv, AES_DECRYPT);

          pta->decrypt_data.crc = be32toh (*(uint32_t *) & out[0]);
          pta->decrypt_data.deadline = *(time_t *) & out[4];
          pta->decrypt_data.url = (u_char *) & out[12];
          pta->decrypt_data.padding_val = out[pta->encrypt_data_len - 1];

          ret = ngx_http_pta_check_crc (pta);
          if (ret == 0)
            {
                return 0;
            }
      }

    if (pta->auth_type == NGX_IIJPTA_AUTH_COOKIE
        && pta->encrypt_data_array_idx < pta->encrypt_data_array->nelts)
      {
          pta->encrypt_data_array_idx++;
          ngx_log_error (NGX_LOG_ERR, r->connection->log, 0,
                         "decrypt failed so checking next pta(index: %d)",
                         pta->encrypt_data_array_idx);
          goto again;
      }

    ngx_log_error (NGX_LOG_ERR, r->connection->log, 0,
                   "decrypt failed. check key and iv");
    return 403;                 /* decrypt failed */
}

static ngx_int_t
ngx_http_pta_check_crc (ngx_http_pta_info_t * pta)
{
    uint8_t raw[8192];
    size_t url_len;
    uint32_t crc;

    if ((pta->decrypt_data.padding_val < 1)
        || (16 < pta->decrypt_data.padding_val))
      {
          return 1;
      }

    url_len = pta->encrypt_data_len
        - sizeof (pta->decrypt_data.crc)
        - sizeof (pta->decrypt_data.deadline) - pta->decrypt_data.padding_val;

    if (url_len > 8192)
      {
          return 1;
      }

    memcpy (raw, &pta->decrypt_data.deadline,
            sizeof (pta->decrypt_data.deadline));
    memcpy (raw + sizeof (pta->decrypt_data.deadline), pta->decrypt_data.url,
            url_len);

    crc = ngx_crc32_long (raw, sizeof (pta->decrypt_data.deadline) + url_len);

    if (crc != pta->decrypt_data.crc)
      {
          return 1;
      }

    return NGX_OK;
}

static ngx_int_t
ngx_http_pta_check_deadline (ngx_http_pta_info_t * pta)
{
    time_t now, deadline;

    deadline = be64toh (pta->decrypt_data.deadline);
    now = ngx_time ();

    if (now > deadline)
      {
          return 1;
      }

    return 0;
}

static ngx_int_t
ngx_http_pta_check_wildcard_url (ngx_http_request_t * r,
                                 ngx_http_pta_info_t * pta, size_t idx)
{
    size_t wdx = ++idx;
    if (pta->decrypt_data.url[idx] == pta->decrypt_data.padding_val)
      {
          return 0;
      }
    while (idx < r->uri.len && r->uri.data[idx] != pta->decrypt_data.url[wdx])
      {
          idx++;
      }
    if (idx > r->uri.len)
      {
          ngx_log_error (NGX_LOG_ERR, r->connection->log, 0,
                         "wildcard mismatch #1");
          return 1;
      }
    while (pta->decrypt_data.url[wdx] != pta->decrypt_data.padding_val)
      {
          if (r->uri.data[idx] != pta->decrypt_data.url[wdx])
            {
                ngx_log_error (NGX_LOG_ERR, r->connection->log, 0,
                               "wildcard mismatch #2");
                return 1;
            }
          wdx++;
          idx++;
      }

    if (idx != r->uri.len)
      {
          ngx_log_error (NGX_LOG_ERR, r->connection->log, 0,
                         "wildcard mismatch #3");
          return 1;
      }

    return 0;
}

static ngx_int_t
ngx_http_pta_check_url (ngx_http_request_t * r, ngx_http_pta_info_t * pta)
{
    size_t idx, wdx;
    int ast;

    if ((pta->decrypt_data.padding_val < 1)
        || (16 < pta->decrypt_data.padding_val))
      {
          return 1;
      }

    ast = 0;
    idx = 0;
    wdx = 0;
    while (pta->decrypt_data.url[wdx] != pta->decrypt_data.padding_val)
      {
          if (pta->decrypt_data.url[wdx] == '\\'
              && pta->decrypt_data.url[wdx + 1] == '*')
            {
                wdx++;
                ast = 1;
            }
          if (ast == 0 && pta->decrypt_data.url[wdx] == '*')
            {
                return ngx_http_pta_check_wildcard_url (r, pta, wdx);
            }
          if (r->uri.data[idx] != pta->decrypt_data.url[wdx])
            {
                return 1;
            }
          idx++;
          wdx++;
      }

    if (idx != r->uri.len)
      {
          return 1;
      }

    return 0;
}

static ngx_int_t
ngx_http_pta_handler (ngx_http_request_t * r)
{
    ngx_int_t ret;
    ngx_http_pta_srv_conf_t *srv;
    ngx_http_pta_loc_conf_t *loc;
    ngx_http_pta_info_t pta;

    if ((srv = ngx_http_get_module_srv_conf (r, ngx_http_pta_module)) == NULL)
      {
          return NGX_DECLINED;
      }

    if ((loc = ngx_http_get_module_loc_conf (r, ngx_http_pta_module)) == NULL)
      {
          return NGX_DECLINED;
      }

    if (!loc->pta_onoff)
      {
          return NGX_DECLINED;
      }

    if (r->internal)
      {
          return NGX_DECLINED;
      }

    ngx_memzero (&pta, sizeof (pta));
    ngx_http_pta_init_auth_type (r, loc, &pta);

  more:
    ret = ngx_http_pta_decrypt (r, srv, &pta);
    if (ret)
      {
          return ret;
      }

    ret = ngx_http_pta_check_deadline (&pta);
    if (ret)
      {
          ngx_log_error (NGX_LOG_ERR, r->connection->log, 0,
                         "request is expired");
          if (pta.auth_type == NGX_IIJPTA_AUTH_COOKIE)
            {
                pta.encrypt_data_array_idx++;
                if (pta.encrypt_data_array_idx <
                    pta.encrypt_data_array->nelts)
                  {
                      ngx_log_error (NGX_LOG_ERR, r->connection->log, 0,
                                     "checking next pta(index: %d)",
                                     pta.encrypt_data_array_idx);
                      goto more;

                  }
            }
          return 410;
      }

    ret = ngx_http_pta_check_url (r, &pta);
    if (ret)
      {
          ngx_log_error (NGX_LOG_ERR, r->connection->log, 0, "url is ivalid");
          if (pta.auth_type == NGX_IIJPTA_AUTH_COOKIE)
            {
                pta.encrypt_data_array_idx++;
                if (pta.encrypt_data_array_idx <
                    pta.encrypt_data_array->nelts)
                  {
                      ngx_log_error (NGX_LOG_ERR, r->connection->log, 0,
                                     "checking next pta(index: %d)",
                                     pta.encrypt_data_array_idx);
                      goto more;
                  }
            }
          return 403;
      }

    ngx_log_error (NGX_LOG_DEBUG, r->connection->log, 0, "successful");

    ngx_str_t *qs;
    qs = ngx_http_pta_delete_arg (r, "pta", sizeof ("pta") - 1);
    if (qs)
      {
          ngx_str_t *uri;
          uri = ngx_http_pta_qparam_cat (r, &r->uri, qs, "?");
          r->unparsed_uri = *uri;
      }
    else
      {
          r->unparsed_uri = r->uri;
      }

    return NGX_DECLINED;
}

static void *
ngx_http_pta_create_srv_conf (ngx_conf_t * cf)
{
    ngx_http_pta_srv_conf_t *conf =
        ngx_pcalloc (cf->pool, sizeof (ngx_http_pta_srv_conf_t));
    if (conf == NULL)
      {
          return NGX_CONF_ERROR;
      }

    return conf;
}

static void *
ngx_http_pta_create_loc_conf (ngx_conf_t * cf)
{
    ngx_http_pta_loc_conf_t *conf =
        ngx_pcalloc (cf->pool, sizeof (ngx_http_pta_loc_conf_t));
    if (conf == NULL)
      {
          return NGX_CONF_ERROR;
      }

    conf->pta_onoff = NGX_CONF_UNSET;

    return conf;
}

static char *
ngx_http_pta_merge_loc_conf (ngx_conf_t * cf, void *parent, void *child)
{
    ngx_http_pta_loc_conf_t *prev = parent;
    ngx_http_pta_loc_conf_t *conf = child;

    ngx_conf_merge_value (conf->pta_onoff, prev->pta_onoff, 0);
    ngx_conf_merge_uint_value (conf->pta_auth_method, prev->pta_auth_method,
                               0);

    return NGX_CONF_OK;
}

static ngx_int_t
ngx_http_pta_check_keyiv (ngx_conf_t * cf, ngx_str_t * arg)
{
    size_t idx;

    if (arg->len != 32)
      {
          ngx_conf_log_error (NGX_LOG_EMERG, cf, 0, "invalid length");
          return 1;
      }

    for (idx = 0; idx < arg->len; idx++)
      {
          if (!(arg->data[idx] == '0' ||
                arg->data[idx] == '1' ||
                arg->data[idx] == '2' ||
                arg->data[idx] == '3' ||
                arg->data[idx] == '4' ||
                arg->data[idx] == '5' ||
                arg->data[idx] == '6' ||
                arg->data[idx] == '7' ||
                arg->data[idx] == '8' ||
                arg->data[idx] == '9' ||
                arg->data[idx] == 'a' ||
                arg->data[idx] == 'b' ||
                arg->data[idx] == 'c' ||
                arg->data[idx] == 'd' ||
                arg->data[idx] == 'e' ||
                arg->data[idx] == 'f' ||
                arg->data[idx] == 'A' ||
                arg->data[idx] == 'B' ||
                arg->data[idx] == 'C' ||
                arg->data[idx] == 'D' ||
                arg->data[idx] == 'E' || arg->data[idx] == 'F'))
            {
                ngx_conf_log_error (NGX_LOG_EMERG, cf, 0,
                                    "invalid character is found");
                return 1;
            }
      }

    return 0;
}

static char *
ngx_http_pta_set_1st_key (ngx_conf_t * cf, ngx_command_t * cmd, void *conf)
{
    ngx_http_pta_srv_conf_t *srvc = conf;
    ngx_str_t *value = cf->args->elts;

    if (ngx_http_pta_check_keyiv (cf, &value[1]))
      {
          return NGX_CONF_ERROR;
      }

    srvc->key_1st.len = value[1].len;
    srvc->key_1st.data = ngx_pstrdup (cf->pool, &value[1]);

    return NGX_CONF_OK;
}

static char *
ngx_http_pta_set_1st_iv (ngx_conf_t * cf, ngx_command_t * cmd, void *conf)
{
    ngx_http_pta_srv_conf_t *srvc = conf;
    ngx_str_t *value = cf->args->elts;

    if (ngx_http_pta_check_keyiv (cf, &value[1]))
      {
          return NGX_CONF_ERROR;
      }

    srvc->iv_1st.len = value[1].len;
    srvc->iv_1st.data = ngx_pstrdup (cf->pool, &value[1]);

    return NGX_CONF_OK;
}

static char *
ngx_http_pta_set_2nd_key (ngx_conf_t * cf, ngx_command_t * cmd, void *conf)
{
    ngx_http_pta_srv_conf_t *srvc = conf;
    ngx_str_t *value = cf->args->elts;

    if (ngx_http_pta_check_keyiv (cf, &value[1]))
      {
          return NGX_CONF_ERROR;
      }

    srvc->key_2nd.len = value[1].len;
    srvc->key_2nd.data = ngx_pstrdup (cf->pool, &value[1]);

    return NGX_CONF_OK;
}

static char *
ngx_http_pta_set_2nd_iv (ngx_conf_t * cf, ngx_command_t * cmd, void *conf)
{
    ngx_http_pta_srv_conf_t *srvc = conf;
    ngx_str_t *value = cf->args->elts;

    if (ngx_http_pta_check_keyiv (cf, &value[1]))
      {
          return NGX_CONF_ERROR;
      }

    srvc->iv_2nd.len = value[1].len;
    srvc->iv_2nd.data = ngx_pstrdup (cf->pool, &value[1]);

    return NGX_CONF_OK;
}
