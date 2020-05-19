#ifndef FTLS_H
#define FTLS_H
#include "picotls.h"
#include "picotls/openssl.h"
#include <netinet/in.h>
#include <sys/types.h>
#include <ev.h>

struct iocc {
    ev_io io;
    struct conn_context *cc;
};
struct conn_context {
  int sockfd;
  uint32_t exprectedlen;
  uint32_t bufsize;
  uint32_t bufptr;
  char *buffer;
  const char *server_name;
  uint32_t kind;
  void (*on_data)(struct conn_context*, uint8_t*, size_t);
  void (*on_connected)(struct conn_context*);
  void (*on_close)(struct conn_context*);
  void *handlerdata;
  struct ev_loop *loop;

  size_t early_bytes_sent;
  enum { IN_HANDSHAKE=0, IN_1RTT, IN_SHUTDOWN } state;
  struct iocc io;
  ptls_context_t tls_ctx;
  ptls_handshake_properties_t hsprop;
  ptls_t *tls;
  ptls_buffer_t readybuf, rbuf, encbuf, ptbuf;
};

int init_connection(struct conn_context *cc);
int cc_send(struct conn_context *cc, uint8_t* data, int len);

#endif

