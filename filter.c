/* system includes */
#include <assert.h>
#include <errno.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

/* begones includes */
#include "filter.h"

//typedef enum {
//  state_none = 0,
//  state_cidr,
//  state_junk,
//  state_text,
//  state_space
//} filter_state_t;

//typedef struct {
//  filter_state_t state;
//  int require;
//  char extra[FILTER_MAX + 1];
//} filter_key_t;

#define set_state_chrs(chrs,state)            \
  do {                                        \
    switch ((state)) {                        \
      case state_none:                        \
        (chrs) = "";                          \
        break;                                \
      case state_cidr:                        \
        (chrs) = "0123456789abcdefABCDEF.:/"; \
        break;                                \
      case state_space:                       \
        (chrs) = " \t";                       \
        break;                                \
      default:                                \
        (chrs) = NULL;                        \
        break;                                \
    }                                         \
  } while (0);                                \

#define key_set(k,m,v) \
  do {                 \
    if ((k))           \
      (k)->m = v;      \
  } while (0);

#define key_set_state(k,v) \
  key_set(k,state,v)
#define key_set_require(k,v) \
  key_set(k,require,v)

size_t
filter_key (filter_key_t *key, const char *str, size_t len)
{
  char *buf;
  int i;
  int esc;
  size_t cnt, inc, max, off, pos;
  filter_state_t state;

  struct { char *name; filter_state_t state; } states[5] = {
    { "cidr",  state_cidr  },
    { "junk",  state_junk  },
    { "text",  state_text  },
    { "space", state_space },
    { "",      state_none  }
  };

  if (key)
    memset (key, '\0', sizeof (filter_key_t));
  if (!str || !len)
    return (0);
  if (*str == '%')
    off = 1;
  else
    off = 0;

  for (i = 0; states[i].state != state_none; i++) {
    max = strlen (states[i].name);
    if (max <= (len-off) && strncasecmp ((str+off), states[i].name, max) == 0)
      goto copy;
  }

  return (0);

  /* copy default value */
  /* try to include trailing % in comparison, but do not require it */
copy:
  cnt = 0;
  esc = 0;
  pos = off + max;
  if (pos < len) {
    if (str[pos] == '%') {
      key_set_state (key, states[i].state);
      key_set_require (key, 1);
      return (++pos);
    } else if (str[pos] == '?') {
      key_set_state (key, states[i].state);
      key_set_require (key, 0);

      if (! key)
        return (pos);

      buf = key->extra;

      for (++pos; pos < len; ) {
        if (str[pos] == '%') {
          inc = filter_key (NULL, str+pos, len-pos);
          if (inc) {
            if (esc) { /* terminating percent sign e.g. %text?text% */
              return (pos);
            } else { /* embedded state e.g. %text?insert%cidr%here% */
              if ((FILTER_MAX - cnt) < inc) {
                errno = ENOBUFS;
                return (0);
              }
              (void)strncpy (buf+cnt, str+pos, inc);
              cnt += inc;
              pos += inc;
            }
          } else {
            if (esc) { /* escaped percent sign e.g. %text?just%%sometext% */
              esc  = 0;
              goto copy2;
            } else { /* can be escaped or terminating percent sign */
              esc  = 1;
              pos += 1;
            }
          }
        } else {
          if (esc) /* terminating percent sign e.g. %text?text% */
            return (pos);
copy2:
          if (cnt < FILTER_MAX) {
            buf[cnt++] = str[pos++];
          } else {
            errno = ENOBUFS;
            return (0);
          }
        }
      }
      if (esc) /* terminating percent sign */
        return (pos);
    }
  } else {
    key_set_state (key, states[i].state)
    key_set_require (key, 1);
    return (pos);
  }

  errno = EINVAL;
  return (0);
}

static int
filter_recursive (filter_result_t *res,
                  filter_key_t *key,
                  const char *str, /* string */
                  size_t strn, /* string length */
                  size_t strc, /* position in string */
                  const char *ptrn, /* pattern */
                  size_t ptrnn, /* pattern length */
                  size_t ptrnc) /* position in pattern */
{
  char *buf, *chrs;
  int esc, match, req, ret;
  filter_key_t tmp_key;
  filter_state_t cur, next, prev;
  size_t bufc, bufn, inc;

  set_state_chrs (chrs, key->state);
  cur = key->state;
  req = key->require; /* recurse */

  bufc = 0;
  switch (key->state) {
    case state_cidr:
      buf = res->cidr;
      bufn = FILTER_MAX;
      break;
    case state_text:
      buf = res->text;
      bufn = FILTER_MAX;
      break;
    default:
      buf = NULL;
      bufn = 0;
      break;
  }

  for (esc = 0; strc < strn && str[strc]; ) {
    if (ptrn[ptrnc] == '%') {
      if (esc) {
        esc = 0;
        goto compare;
      } else if (! req) {
        inc = filter_key (&tmp_key, ptrn+ptrnc, ptrnn-ptrnc);
        if (inc) {
          if (buf && !bufc)
            (void)strcpy (buf, key->extra);
          ret = filter_recursive (res, &tmp_key,
                                  str, strn, strc,
                                  ptrn, ptrnn, ptrnc+inc);
          if (ret == 0)
            return (ret);
          else
            goto compare;
        } else {
          esc = 1;
        }
      } else {
        goto compare;
      }
    } else {
      if (esc) {
        if (str[strc] != '%')
          goto error_EINVAL;
        esc = 0;
      }
compare:
      match = 0;
      if (str[strc] == ptrn[ptrnc]) {
        if (buf && ! bufc) {
          (void)strcpy (buf, key->extra);
        }
        if (cur == state_none) {
          match = 2;
        } else if (! req) {
          memset (&tmp_key, '\0', sizeof (filter_key_t));
          ret = filter_recursive (res, &tmp_key,
                                  str, strn, strc,
                                  ptrn, ptrnn, ptrnc);
          if (ret == 0)
            return (0);
          match = 0;
        }
      }

      if (! match) {
        if (! chrs || (chrs && strchr (chrs, str[strc]))) {
          match = 1;
          req = 0;
          if (buf && bufc < bufn)
            buf[bufc++] = str[strc];
        } else {
          goto error_EINVAL;
        }
      }

      if (match > 1)
        ptrnc++;
      if (match > 0)
        strc++;
    }
  }

  if (str[strc] == ptrn[ptrnc])
    return (0);
error_EINVAL:
  errno = EINVAL;
  return (-1);
error_ENOBUFS:
  errno = ENOBUFS;
  return (-1);
}

filter_result_t *
filter (filter_result_t *res,
        const char *str, /* string */
        size_t strn, /* string length */
        const char *ptrn, /* pattern */
        size_t ptrnn) /* pattern length */
{
  filter_key_t key;
  int alloc;

  assert (str && strn);
  assert (ptrn && ptrnn);

  if ((res))
    alloc = 0;
  else
    alloc = 1;

  if ((alloc) && ! (res = malloc (sizeof (filter_result_t))))
    goto error;

  memset (res, '\0', sizeof (filter_result_t));
  memset (&key, '\0', sizeof (filter_key_t));

  if (filter_recursive (res, &key, str, strn, 0, ptrn, ptrnn, 0) == 0)
    return (res);

error:
  if (res) {
    memset (res, '\0', sizeof (filter_result_t));
    if (alloc)
      free (res);
  }
  return (NULL);
}























































