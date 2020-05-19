#include <sys/socket.h>
#include <netinet/in.h>
#include <resolv.h>

#include "ftls.h"
#include "picotls.h"
#include "picotls/openssl.h"

#include <sys/types.h>
#include <arpa/nameser.h>
#include <unistd.h>

#include <msgpack.h>

msgpack_sbuffer* buffer;
msgpack_packer* pk;

static void handle_data(struct conn_context *cc, uint8_t* data, size_t length){
  data[length]=0;
  printf("Got %ld bytes %d\n",length,data[0]);
//  cc_send(cc,data,length);

  msgpack_unpacked msg;
  msgpack_unpacked_init(&msg);
  size_t off=0;
  msgpack_unpack_return ret = msgpack_unpack_next(&msg, (char*)data, length, &off );
  printf("ret %d off %ld\n",ret, off);

  /* prints the deserialized object. */
  msgpack_object obj = msg.data;
  printf("obj type %d\n",obj.type);
  msgpack_object_print(stderr, obj);  /*=> ["Hello", "MessagePack"] */
  printf("\n");
}

static void connected(struct conn_context *cc) {
  printf("Connected\n");
  /*
  msgpack_pack_map(pk, 2);

  msgpack_pack_str(pk, 5);
  msgpack_pack_str_body(pk, "Hello", 5);
  msgpack_pack_str(pk, 11);
  msgpack_pack_str_body(pk, "MessagePack", 11);

  msgpack_pack_bin(pk, 11);
  msgpack_pack_str_body(pk, "MessagePack", 11);
  */
  struct msgpack_object_kv kvs[2]={
    {.key={.type=MSGPACK_OBJECT_BIN, .via.bin={.ptr="preved", .size=6}},
      .val={.type=MSGPACK_OBJECT_BIN, .via.bin={.ptr="medved", .size=6}}
    },
    {.key={.type=MSGPACK_OBJECT_BIN, .via.bin={.ptr="ololo", .size=5}},
      .val={.type=MSGPACK_OBJECT_POSITIVE_INTEGER, .via.i64=12481632}
    }
  };
  msgpack_object obj={.type=MSGPACK_OBJECT_MAP, .via.map={.size=2,.ptr=(struct msgpack_object_kv *)&kvs}};
  msgpack_pack_object(pk, obj);
  cc_send(cc,(uint8_t*)buffer->data,buffer->size);
}

static int run_client(struct ev_loop *loop,
    struct sockaddr *sa,
    socklen_t salen,
    const char *server_name,
    char *protocol) {
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

  ptls_key_exchange_algorithm_t *key_exchanges[2] = {&ptls_openssl_secp256r1, NULL};
  ptls_context_t ctx = {ptls_openssl_random_bytes, &ptls_get_time, key_exchanges, ptls_openssl_cipher_suites};

  ptls_handshake_properties_t hsprop = {{{{NULL}}}};
  ctx.require_client_authentication = 0;
  if(protocol){
    ptls_iovec_t *alpn=calloc(sizeof(ptls_iovec_t),1);
    alpn[0].len=strlen(protocol);
    alpn[0].base=(uint8_t*)strdup(protocol);
    hsprop.client.negotiated_protocols.count=1;
    hsprop.client.negotiated_protocols.list=alpn;
  }

  
  /*
  const char *input_file = NULL;
  struct {
    ptls_key_exchange_context_t *elements[16];
    size_t count;
  } esni_key_exchanges;
  */


  struct conn_context *cc=calloc(sizeof(struct conn_context),1);
  cc->loop=loop;
  cc->sockfd=fd;
  cc->tls_ctx=ctx;

  cc->server_name=server_name;
  cc->hsprop=hsprop;
  cc->io.cc=cc;
  cc->on_connected=connected;
  cc->on_data=handle_data;

  int ret = init_connection(cc);
  //fd, ctx, server_name, hsprop, request_key_update, keep_sender_open);
  free(hsprop.client.esni_keys.base);
  return ret;
}

int main(int argc, char **argv) {
  //ERR_load_crypto_strings();
  //OpenSSL_add_all_algorithms();

  res_init();

  /* creates buffer and serializer instance. */
  buffer = msgpack_sbuffer_new();
  pk = msgpack_packer_new(buffer, msgpack_sbuffer_write);

  struct sockaddr_in sa;

  char * host = "127.0.0.1";
  /*
     if (resolve_address((struct sockaddr *)&sa, &salen, host, port, family, SOCK_STREAM, IPPROTO_TCP) != 0)
     exit(1);
     */
  sa.sin_family=AF_INET;
  sa.sin_addr.s_addr=htonl(0x7f000001);
  sa.sin_port=htons(5658);

  struct ev_loop *loop = EV_DEFAULT;
  run_client(loop, (struct sockaddr *)&sa, sizeof(struct sockaddr_in), host, "xxxcast");

  ev_run (loop, 0);
  return 0;
}
