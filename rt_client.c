#include <sys/types.h>
#include <netinet/in.h>
#include <arpa/nameser.h>
#include <resolv.h>

//#include <arpa/inet.h>
#include <assert.h>
#include <errno.h>
#include <fcntl.h>
//#include <getopt.h>
#include <inttypes.h>
#include <stdio.h>
#include <string.h>
#include <strings.h>
#include <sys/select.h>
#include <sys/socket.h>
#include <sys/stat.h>
//#include <sys/time.h>
#include <sys/types.h>
#include <unistd.h>
#include <openssl/engine.h>
#include <ev.h>
/*
#include <openssl/err.h>
#include <openssl/evp.h>
#include <openssl/pem.h>
*/
#include "picotls.h"
#include "picotls/openssl.h"
//#include "util.h"

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
  int (*handler)(char*,uint32_t,void*);
  void *handlerdata;
  struct ev_loop *loop;

  size_t early_bytes_sent;
  enum { IN_HANDSHAKE=0, IN_1RTT, IN_SHUTDOWN } state;
  struct iocc io;
  ptls_context_t *tls_ctx;
  ptls_handshake_properties_t *hsprop;
  ptls_t *tls;
  ptls_buffer_t rbuf, encbuf, ptbuf;
};

static void shift_buffer(ptls_buffer_t *buf, size_t delta) {
  if (delta != 0) {
    assert(delta <= buf->off);
    if (delta != buf->off)
      memmove(buf->base, buf->base + delta, buf->off - delta);
    buf->off -= delta;
  }
}

/*
static int init_connection(
    struct ev_loop *loop,
    int sockfd,
    ptls_context_t *ctx,
    const char *server_name,
    ptls_handshake_properties_t *hsprop,
    int request_key_update,
    int keep_sender_open) {
*/
static void handle_connection (struct ev_loop *loop, ev_io *w, int revents) {
  struct iocc *iocc=(struct iocc*)w;
  struct conn_context *cc=iocc->cc;
  int ret;

  if(revents & EV_READ){
    printf("%s:%d read\n",__FUNCTION__,__LINE__);

    char bytebuf[16384];
    size_t off = 0, leftlen;
    int ioret;
    ioret = read(cc->sockfd, bytebuf, sizeof(bytebuf));
    // ) == -1 && errno == EINTR);

    printf("ioret %d %d %s\n",ioret,errno,strerror(errno));
    if(ioret==0) {
      printf("Conn closed");
      exit(1);
    }

    printf("st %d ioret %d off %d\n",cc->state, ioret, off);
    while ((leftlen = ioret - off) != 0) {
      if (cc->state == IN_HANDSHAKE) {
        if ((ret = ptls_handshake(cc->tls, &cc->encbuf, bytebuf + off, &leftlen, cc->hsprop)) == 0) {
          printf("%s:%d %d\n",__FUNCTION__,__LINE__,ret);
          cc->state = IN_1RTT;
          assert(ptls_is_server(cc->tls) || cc->hsprop->client.early_data_acceptance != PTLS_EARLY_DATA_ACCEPTANCE_UNKNOWN);
          /* release data sent as early-data, if server accepted it */
          if (cc->hsprop->client.early_data_acceptance == PTLS_EARLY_DATA_ACCEPTED)
            shift_buffer(&cc->ptbuf, cc->early_bytes_sent);
          /*if (request_key_update)
            ptls_update_key(cc->tls, 1);
            */
        } else if (ret == PTLS_ERROR_IN_PROGRESS) {
          /* ok */
        } else {
          printf("wr1\n");
          if (cc->encbuf.off != 0)
            (void)write(cc->sockfd, cc->encbuf.base, cc->encbuf.off);
          fprintf(stderr, "ptls_handshake:%d\n", ret);
          goto Exit;
        }
      } else {
        if ((ret = ptls_receive(cc->tls, &cc->rbuf, bytebuf + off, &leftlen)) == 0) {
          printf("%s:%d %d\n",__FUNCTION__,__LINE__,ret);
          if (cc->rbuf.off != 0) {
            //data_received += cc->rbuf.off;
            printf("wr2 %d\n",cc->rbuf.off);
            write(1, cc->rbuf.base, cc->rbuf.off);
            printf(" - - - \n");
            if ((ret = ptls_buffer_reserve(&cc->ptbuf, cc->rbuf.off)) != 0)
              goto Exit;
            memcpy(cc->ptbuf.base + cc->ptbuf.off,cc->rbuf.base, cc->rbuf.off);
            cc->ptbuf.off=cc->rbuf.off;


            cc->rbuf.off = 0;
          }
        } else if (ret == PTLS_ERROR_IN_PROGRESS) {
          /* ok */
        } else {
          fprintf(stderr, "ptls_receive:%d\n", ret);
          goto Exit;
        }
      }
      off += leftlen;
    }
  }

  //encrypt
  if (cc->ptbuf.off != 0) {
    printf("Need encrypt\n");
    if (cc->state == IN_HANDSHAKE) {
      size_t send_amount = 0;
      if (cc->server_name != NULL && cc->hsprop->client.max_early_data_size != NULL) {
        size_t max_can_be_sent = *cc->hsprop->client.max_early_data_size;
        if (max_can_be_sent > cc->ptbuf.off)
          max_can_be_sent = cc->ptbuf.off;
        send_amount = max_can_be_sent - cc->early_bytes_sent;
      }
      if (send_amount != 0) {
        if ((ret = ptls_send(cc->tls, &cc->encbuf, cc->ptbuf.base, send_amount)) != 0) {
          fprintf(stderr, "ptls_send(early_data):%d\n", ret);
          goto Exit;
        }
        cc->early_bytes_sent += send_amount;
      }
    } else {
      printf("Need payload encrypt\n");
      if ((ret = ptls_send(cc->tls, &cc->encbuf, cc->ptbuf.base, cc->ptbuf.off)) != 0) {
        fprintf(stderr, "ptls_send(1rtt):%d\n", ret);
        goto Exit;
      }
      cc->ptbuf.off = 0;
    }
  }

  if(revents & EV_WRITE) {
    printf("%s:%d write\n",__FUNCTION__,__LINE__);
    int ioret;
    if (cc->encbuf.off != 0) {
      ioret = write(cc->sockfd, cc->encbuf.base, cc->encbuf.off);
      printf("%d bytes written\n",ioret);
      if (ioret == -1 && (errno == EWOULDBLOCK || errno == EAGAIN)) {
        /* no data */
      } else if (ioret <= 0) {
        goto Exit;
      } else {
        shift_buffer(&cc->encbuf, ioret);
      }
    }
  }

  //is write needed?
  if (cc->encbuf.off == 0) {
    ev_io_init (&cc->io.io, handle_connection, cc->sockfd, EV_READ);
  }else{
    ev_io_init (&cc->io.io, handle_connection, cc->sockfd, EV_READ|EV_WRITE);
  }

#if 0
  /* check if data is available */
  fd_set readfds, writefds, exceptfds;
  int maxfd = 0;
  struct timeval timeout;
  do {
    FD_ZERO(&readfds);
    FD_ZERO(&writefds);
    FD_ZERO(&exceptfds);
    FD_SET(cc->sockfd, &readfds);
    FD_SET(cc->sockfd, &exceptfds);
    maxfd = cc->sockfd + 1;
    if (inputfd >= 0) {
      FD_SET(inputfd, &readfds);
      FD_SET(inputfd, &exceptfds);
      if (maxfd <= inputfd)
        maxfd = inputfd + 1;
    }
    timeout.tv_sec = cc->encbuf.off != 0 ? 0 : 3600;
    timeout.tv_usec = 0;
  } while (select(maxfd, &readfds, &writefds, &exceptfds, &timeout) == -1);

  /* consume incoming messages */
  if (FD_ISSET(cc->sockfd, &readfds) || FD_ISSET(cc->sockfd, &exceptfds)) {
    char bytebuf[16384];
    size_t off = 0, leftlen;
    while ((ioret = read(cc->sockfd, bytebuf, sizeof(bytebuf))) == -1 && errno == EINTR)
      ;
    if (ioret == -1 && (errno == EWOULDBLOCK || errno == EAGAIN)) {
      /* no data */
      ioret = 0;
    } else if (ioret <= 0) {
      goto Exit;
    }
    while ((leftlen = ioret - off) != 0) {
      if (cc->state == IN_HANDSHAKE) {
        if ((ret = ptls_handshake(cc->tls, &cc->encbuf, bytebuf + off, &leftlen, cc->hsprop)) == 0) {
          cc->state = IN_1RTT;
          assert(ptls_is_server(cc->tls) || cc->hsprop->client.early_data_acceptance != PTLS_EARLY_DATA_ACCEPTANCE_UNKNOWN);
          /* release data sent as early-data, if server accepted it */
          if (cc->hsprop->client.early_data_acceptance == PTLS_EARLY_DATA_ACCEPTED)
            shift_buffer(&cc->ptbuf, early_bytes_sent);
          /*if (request_key_update)
            ptls_update_key(cc->tls, 1);
            */
        } else if (ret == PTLS_ERROR_IN_PROGRESS) {
          /* ok */
        } else {
          if (cc->encbuf.off != 0)
            (void)write(cc->sockfd, cc->encbuf.base, cc->encbuf.off);
          fprintf(stderr, "ptls_handshake:%d\n", ret);
          goto Exit;
        }
      } else {
        if ((ret = ptls_receive(cc->tls, &cc->rbuf, bytebuf + off, &leftlen)) == 0) {
          if (cc->rbuf.off != 0) {
            data_received += cc->rbuf.off;
            write(1, cc->rbuf.base, cc->rbuf.off);
            cc->rbuf.off = 0;
          }
        } else if (ret == PTLS_ERROR_IN_PROGRESS) {
          /* ok */
        } else {
          fprintf(stderr, "ptls_receive:%d\n", ret);
          goto Exit;
        }
      }
      off += leftlen;
    }
  }

  /* encrypt data to send, if any is available */
  if (cc->encbuf.off == 0 || cc->state == IN_HANDSHAKE) {
    static const size_t block_size = 16384;
    if (inputfd >= 0 && (FD_ISSET(inputfd, &readfds) || FD_ISSET(inputfd, &exceptfds))) {
      if ((ret = ptls_buffer_reserve(&cc->ptbuf, block_size)) != 0)
        goto Exit;
      while ((ioret = read(inputfd, cc->ptbuf.base + cc->ptbuf.off, block_size)) == -1 && errno == EINTR)
        ;
      if (ioret > 0) {
        cc->ptbuf.off += ioret;
      } else if (ioret == 0) {
        /* closed */
        /*
           if (input_file != NULL)
           close(inputfd);
           */
        inputfd = -1;
      }
    }
  }
  /*
     if (ptbuf.off != 0) {
     if (cc->state == IN_HANDSHAKE) {
     size_t send_amount = 0;
     if (server_name != NULL && hsprop->client.max_early_data_size != NULL) {
     size_t max_can_be_sent = *hsprop->client.max_early_data_size;
     if (max_can_be_sent > ptbuf.off)
     max_can_be_sent = ptbuf.off;
     send_amount = max_can_be_sent - early_bytes_sent;
     }
     if (send_amount != 0) {
     if ((ret = ptls_send(cc->tls, &encbuf, ptbuf.base, send_amount)) != 0) {
     fprintf(stderr, "ptls_send(early_data):%d\n", ret);
     goto Exit;
     }
     early_bytes_sent += send_amount;
     }
     } else {
     if ((ret = ptls_send(cc->tls, &encbuf, ptbuf.base, ptbuf.off)) != 0) {
     fprintf(stderr, "ptls_send(1rtt):%d\n", ret);
     goto Exit;
     }
     ptbuf.off = 0;
     }
     }
     */

  /* send any data */
  if (cc->encbuf.off != 0) {
    while ((ioret = write(cc->sockfd, cc->encbuf.base, cc->encbuf.off)) == -1 && errno == EINTR)
      ;
    if (ioret == -1 && (errno == EWOULDBLOCK || errno == EAGAIN)) {
      /* no data */
    } else if (ioret <= 0) {
      goto Exit;
    } else {
      shift_buffer(&cc->encbuf, ioret);
    }
  }

  /* close the sender side when necessary */
  if (cc->state == IN_1RTT && inputfd == -1) {
    //if (!keep_sender_open) {
    ptls_buffer_t wbuf;
    uint8_t wbuf_small[32];
    ptls_buffer_init(&wbuf, wbuf_small, sizeof(wbuf_small));
    if ((ret = ptls_send_alert(cc->tls, &wbuf, PTLS_ALERT_LEVEL_WARNING, PTLS_ALERT_CLOSE_NOTIFY)) != 0) {
      fprintf(stderr, "ptls_send_alert:%d\n", ret);
    }
    if (wbuf.off != 0)
      (void)write(cc->sockfd, wbuf.base, wbuf.off);
    ptls_buffer_dispose(&wbuf);
    shutdown(cc->sockfd, SHUT_WR);
    //}
    cc->state = IN_SHUTDOWN;
  }

  /*
Exit:
if (cc->sockfd != -1)
close(cc->sockfd);
ptls_buffer_dispose(&cc->rbuf);
ptls_buffer_dispose(&cc->encbuf);
ptls_buffer_dispose(&cc->ptbuf);
ptls_free(cc->tls);

return ret != 0;
*/
#endif

  return;

Exit:
  if (cc->sockfd != -1)
    close(cc->sockfd);
}

static int init_connection(struct conn_context *cc) {
  cc->tls = ptls_new(cc->tls_ctx, cc->server_name == NULL);
  int inputfd = 0, ret = 0;
  uint64_t data_received = 0;
  ssize_t ioret;

  uint64_t start_at = cc->tls_ctx->get_time->cb(cc->tls_ctx->get_time);

  ptls_buffer_init(&cc->rbuf, "", 0);
  ptls_buffer_init(&cc->encbuf, "", 0);
  ptls_buffer_init(&cc->ptbuf, "", 0);

  fcntl(cc->sockfd, F_SETFL, O_NONBLOCK);
  cc->state = IN_HANDSHAKE;
  cc->early_bytes_sent = 0;

  if (cc->server_name != NULL) {
    ptls_set_server_name(cc->tls, cc->server_name, 0);
    if ((ret = ptls_handshake(cc->tls, &cc->encbuf, NULL, NULL, cc->hsprop)) != PTLS_ERROR_IN_PROGRESS) {
      fprintf(stderr, "ptls_handshake:%d\n", ret);
      return 1;
    }else{
      printf("sn ok\n");
    }
  }
  printf("init ok\n");

  ev_io_init (&cc->io.io, handle_connection, cc->sockfd, EV_READ|EV_WRITE);
  ev_io_start (cc->loop, &cc->io.io);
  return 0;
}

/*
static int run_server(
    struct ev_loop *loop,
    struct sockaddr *sa,
    socklen_t salen,
    ptls_context_t *ctx,
    ptls_handshake_properties_t *hsprop,
    int request_key_update) {
  int listen_fd, conn_fd, on = 1;

  if ((listen_fd = socket(sa->sa_family, SOCK_STREAM, 0)) == -1) {
    perror("socket(2) failed");
    return 1;
  }
  if (setsockopt(listen_fd, SOL_SOCKET, SO_REUSEADDR, &on, sizeof(on)) != 0) {
    perror("setsockopt(SO_REUSEADDR) failed");
    return 1;
  }
  if (bind(listen_fd, sa, salen) != 0) {
    perror("bind(2) failed");
    return 1;
  }
  if (listen(listen_fd, SOMAXCONN) != 0) {
    perror("listen(2) failed");
    return 1;
  }

  fprintf(stderr, "server started on port %d\n", ntohs(((struct sockaddr_in *)sa)->sin_port));
  while (1) {
    fprintf(stderr, "waiting for connections\n");
    if ((conn_fd = accept(listen_fd, NULL, 0)) != -1)
      init_connection(loop, conn_fd, ctx, NULL, hsprop, request_key_update, 0);
  }

  return 0;
}
*/

static int run_client(struct ev_loop *loop,
    struct sockaddr *sa,
    socklen_t salen,
    ptls_context_t *ctx,
    const char *server_name,
    ptls_handshake_properties_t *hsprop,
    int request_key_update,
    int keep_sender_open) {
  int fd;

  //hsprop->client.esni_keys = resolve_esni_keys(server_name);

  if ((fd = socket(sa->sa_family, SOCK_STREAM, 0)) == 1) {
    perror("socket(2) failed");
    return 1;
  }
  if (connect(fd, sa, salen) != 0) {
    perror("connect(2) failed");
    return 1;
  }

  struct conn_context *cc=calloc(sizeof(struct conn_context),1);
  cc->loop=loop;
  cc->sockfd=fd;
  cc->tls_ctx=ctx;
  cc->server_name=server_name;
  cc->hsprop=hsprop;
  cc->io.cc=cc;

  int ret = init_connection(cc);
  //fd, ctx, server_name, hsprop, request_key_update, keep_sender_open);
  free(hsprop->client.esni_keys.base);
  return ret;
}

int main(int argc, char **argv) {
  ERR_load_crypto_strings();
  OpenSSL_add_all_algorithms();
#if !defined(OPENSSL_NO_ENGINE)
  /* Load all compiled-in ENGINEs */
  ENGINE_load_builtin_engines();
  ENGINE_register_all_ciphers();
  ENGINE_register_all_digests();
#endif

  res_init();

  ptls_key_exchange_algorithm_t *key_exchanges[128] = {NULL};
  ptls_cipher_suite_t *cipher_suites[128] = {NULL};
  ptls_context_t ctx = {ptls_openssl_random_bytes, &ptls_get_time, key_exchanges, cipher_suites};

  ptls_handshake_properties_t hsprop = {{{{NULL}}}};
  /*
  const char *input_file = NULL;
  struct {
    ptls_key_exchange_context_t *elements[16];
    size_t count;
  } esni_key_exchanges;
  */
  int is_server = 0, use_early_data = 0, request_key_update = 0, keep_sender_open = 0, ch;
  struct sockaddr_in sa;

  ctx.require_client_authentication = 0;
  keep_sender_open = 1;

  key_exchanges[0] = &ptls_openssl_secp256r1;
  size_t i;
  for (i = 0; ptls_openssl_cipher_suites[i] != NULL; ++i)
    cipher_suites[i] = ptls_openssl_cipher_suites[i];


  char * host = "127.0.0.1";
  /*
     if (resolve_address((struct sockaddr *)&sa, &salen, host, port, family, SOCK_STREAM, IPPROTO_TCP) != 0)
     exit(1);
     */
  sa.sin_family=AF_INET;
  sa.sin_addr.s_addr=htonl(0x7f000001);
  sa.sin_port=htons(5659);

  struct ev_loop *loop = EV_DEFAULT;
  run_client(loop, (struct sockaddr *)&sa, sizeof(struct sockaddr_in), &ctx, host, &hsprop, request_key_update, keep_sender_open);

  ev_run (loop, 0);
  return 0;
}
