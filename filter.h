#ifndef FILTER_H_INCLUDED
#define FILTER_H_INCLUDED

/* use a safe margin for CIRD notation, two times the maximum size for string
   representation of IPv6 address, and 128 bytes just to be safe */
/* maximum number of bytes for text, remaining characters are truncated */
#define FILTER_MAX (1024)

typedef struct {
  char cidr[FILTER_MAX + 1]; /* +1 for null termination */
  char text[FILTER_MAX + 1]; /* +1 for null termination */
} filter_result_t;

typedef enum {
  state_none = 0,
  state_cidr,
  state_junk,
  state_text,
  state_space
} filter_state_t;

typedef struct {
  filter_state_t state;
  int require;
  char extra[FILTER_MAX + 1];
} filter_key_t;

filter_result_t *filter (filter_result_t *, const char *, size_t, const char *, size_t);

#endif

