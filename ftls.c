#include <assert.h>
#include <errno.h>
#include <fcntl.h>
#include <inttypes.h>
#include <sys/socket.h>
#include <sys/types.h>
#include <unistd.h>
#include "ftls.h"

static void shift_buffer(ptls_buffer_t *buf, size_t delta) {
  if (delta != 0) {
    assert(delta <= buf->off);
    if (delta != buf->off)
      memmove(buf->base, buf->base + delta, buf->off - delta);
    buf->off -= delta;
  }
}
void handle_connection (struct ev_loop *loop, ev_io *w, int revents);

static void do_enable_wr(struct conn_context *cc){
  if (cc->encbuf.off == 0) {
    ev_io_init (&cc->io.io, handle_connection, cc->sockfd, EV_READ);
  }else{
    ev_io_init (&cc->io.io, handle_connection, cc->sockfd, EV_READ|EV_WRITE);
  }
}

void do_close(struct conn_context *cc, char* reason){
  if (cc->sockfd != -1)
    close(cc->sockfd);
  if(cc->on_close)
    cc->on_close(cc);

  printf("DO Close %s\n",reason);
}

static void do_enc(struct conn_context *cc){
  if (cc->ptbuf.off != 0) {
    printf("Need payload encrypt\n");
    int ret;
    if ((ret = ptls_send(cc->tls, &cc->encbuf, cc->ptbuf.base, cc->ptbuf.off)) != 0) {
      fprintf(stderr, "ptls_send(1rtt):%d\n", ret);
      do_close(cc,"ptls_send(1rtt)");
    }
    cc->ptbuf.off = 0;
  }
}

int cc_send(struct conn_context *cc, uint8_t* data, int len){
  int ret;
  ret = ptls_buffer_reserve(&cc->ptbuf, len + 4 + cc->ptbuf.off);
  if (ret != 0) return -1;
  uint32_t ulen=htonl(len);
  memcpy(cc->ptbuf.base + cc->ptbuf.off,&ulen, 4);
  printf("wr len %d\n", htonl( *((uint32_t*)(cc->ptbuf.base+cc->ptbuf.off))));
  memcpy(cc->ptbuf.base + cc->ptbuf.off+4,data, len);
  cc->ptbuf.off+=len+4;
  printf("Send %d bytes\n",len);

  do_enc(cc);
  do_enable_wr(cc);
  return 0;
}

void handle_connection (struct ev_loop *loop, ev_io *w, int revents) {
  struct iocc *iocc=(struct iocc*)w;
  struct conn_context *cc=iocc->cc;
  int ret;

  if(revents & EV_READ){
    char bytebuf[16384];
    size_t off = 0, leftlen;
    int ioret;
    ioret = read(cc->sockfd, bytebuf, sizeof(bytebuf));

    printf(":. ioret %d %d %s\n",ioret,errno,strerror(errno));
    if(ioret==0) {
      return do_close(cc,"remote_closed");
    }

    while ((leftlen = ioret - off) != 0) {
      if (cc->state == IN_HANDSHAKE) {
        if ((ret = ptls_handshake(cc->tls, &cc->encbuf, bytebuf + off, &leftlen, &cc->hsprop)) == 0) {
          printf("NEG %s:%d %d\n",__FUNCTION__,__LINE__,ret);
          cc->state = IN_1RTT;
          assert(ptls_is_server(cc->tls) || cc->hsprop.client.early_data_acceptance != PTLS_EARLY_DATA_ACCEPTANCE_UNKNOWN);
          /* release data sent as early-data, if server accepted it */
          if (cc->hsprop.client.early_data_acceptance == PTLS_EARLY_DATA_ACCEPTED)
            shift_buffer(&cc->ptbuf, cc->early_bytes_sent);
          /*if (request_key_update)
            ptls_update_key(cc->tls, 1);
            */
          if(cc->on_connected)
            cc->on_connected(cc);
        } else if (ret == PTLS_ERROR_IN_PROGRESS) {
          /* ok */
        } else {
          printf("wr1\n");
          if (cc->encbuf.off != 0)
            (void)write(cc->sockfd, cc->encbuf.base, cc->encbuf.off);
          fprintf(stderr, "ptls_handshake:%d\n", ret);
          return do_close(cc,"ptls_handshake");
          //goto Exit;
        }
      } else {
        if ((ret = ptls_receive(cc->tls, &cc->rbuf, bytebuf + off, &leftlen)) == 0) {
          printf("DAT %s:%d %d\n",__FUNCTION__,__LINE__,ret);
          while (cc->rbuf.off > 0) {
            uint32_t exp=htonl(*((uint32_t*)cc->rbuf.base));
            if(cc->rbuf.off>=exp){
              if(cc->on_data)
                cc->on_data(cc,cc->rbuf.base+4,exp);
              shift_buffer(&cc->rbuf, exp+4);
            }else
              break;
          }
        } else if (ret == PTLS_ERROR_IN_PROGRESS) {
          /* ok */
        } else {
          fprintf(stderr, "ptls_receive:%d\n", ret);
          return do_close(cc,"ptls_receive");
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
      if (cc->server_name != NULL && cc->hsprop.client.max_early_data_size != NULL) {
        size_t max_can_be_sent = *cc->hsprop.client.max_early_data_size;
        if (max_can_be_sent > cc->ptbuf.off)
          max_can_be_sent = cc->ptbuf.off;
        send_amount = max_can_be_sent - cc->early_bytes_sent;
      }
      if (send_amount != 0) {
        if ((ret = ptls_send(cc->tls, &cc->encbuf, cc->ptbuf.base, send_amount)) != 0) {
          fprintf(stderr, "ptls_send(early_data):%d\n", ret);
          return do_close(cc,"ptls_send(early_data)");
        }
        cc->early_bytes_sent += send_amount;
      }
    } else {
      do_enc(cc);
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
        return do_close(cc,"write");
      } else {
        shift_buffer(&cc->encbuf, ioret);
      }
    }
  }

  //is write needed?
  do_enable_wr(cc);

  return;
}

int init_connection(struct conn_context *cc) {
  cc->tls = ptls_new(&cc->tls_ctx, cc->server_name == NULL);
  int inputfd = 0, ret = 0;
  uint64_t data_received = 0;
  ssize_t ioret;

  uint64_t start_at = cc->tls_ctx.get_time->cb(cc->tls_ctx.get_time);

  ptls_buffer_init(&cc->rbuf, "", 0);
  ptls_buffer_init(&cc->encbuf, "", 0);
  ptls_buffer_init(&cc->ptbuf, "", 0);

  fcntl(cc->sockfd, F_SETFL, O_NONBLOCK);
  cc->state = IN_HANDSHAKE;
  cc->early_bytes_sent = 0;

  if (cc->server_name != NULL) {
    ptls_set_server_name(cc->tls, cc->server_name, 0);
    if ((ret = ptls_handshake(cc->tls, &cc->encbuf, NULL, NULL, &cc->hsprop)) != PTLS_ERROR_IN_PROGRESS) {
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
