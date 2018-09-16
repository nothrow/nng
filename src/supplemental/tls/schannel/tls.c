//
// Copyright 2018 Staysail Systems, Inc. <info@staysail.tech>
// Copyright 2018 Capitar IT Group BV <info@capitar.com>
// Copyright 2018 Vit Tauer <t@uer.cz>
//
// This software is supplied under the terms of the MIT License, a
// copy of which should be located in the distribution where this
// file was obtained (LICENSE.txt).  A copy of the license may also be
// found online at https://opensource.org/licenses/MIT.
//

#include <stdbool.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include "core/nng_impl.h"

#include "supplemental/tls/tls.h"
#include "supplemental/tls/tls_api.h"

#define SECURITY_WIN32
#include <schannel.h>
#include <security.h>

#define SSPI_FLAGS                                         \
	(ISC_REQ_ALLOCATE_MEMORY | ISC_REQ_REPLAY_DETECT | \
	    ISC_REQ_CONFIDENTIALITY | ISC_REQ_STREAM |     \
	    ISC_REQ_SEQUENCE_DETECT)

#define SEC_VALID(Handle) ((Handle).dwLower != 0 || (Handle).dwUpper != 0)
// resharper has some hints that goes against the code style
// ReSharper disable CppJoinDeclarationAndAssignment

// Implementation note.  This implementation buffers data between the TLS
// encryption layer (schannel) and the underlying TCP socket.  As a result,
// there may be some additional latency caused by buffer draining and
// refilling.  In the future we might want to investigate some kind of
// double buffer policy to allow data to flow without entering a true
// empty state.

// NNG_TLS_MAX_BUFFER_SIZE limits the amount of data we will buffer for both
// sending and receiving, exerting backpressure if this size is exceeded.  The
// 16K is aligned to the maximum TLS record size.
#ifndef NNG_TLS_MAX_BUFFER_SIZE
#define NNG_TLS_MAX_BUFFER_SIZE 16384
#endif

typedef enum schannel_internal_error_codes {
	SCHANNEL_OUT_OF_MEMORY	   = -6,
	SCHANNEL_OTHER_ERROR       = -5,
	SCHANNEL_SECURITY_ERROR    = -4,
	SCHANNEL_WRITE_PENDING     = -2,
	SCHANNEL_READ_PENDING      = -3,
	SCHANNEL_CONNECTION_CLOSED = -1,
	SCHANNEL_OK                = 0
} schannel_internal_error_codes;

typedef struct nni_tls_certkey {
	// mbedtls_x509_crt   crt;
	// mbedtls_pk_context key;
	nni_list_node node;
} nni_tls_certkey;

struct nni_tls {
	nni_tcp_conn *tcp;

	CtxtHandle                ssl_context;
	SecPkgContext_StreamSizes stream_sizes;

	nng_tls_config *cfg; // kept so we can release it
	nni_mtx         lk;
	nni_aio *       tcp_send;
	nni_aio *       tcp_recv;
	bool            sending;
	bool            recving;
	bool            closed;
	bool            hsdone;
	bool            tls_closed; // upper TLS layer closed
	bool            tcp_closed; // underlying TCP buffer closed
	uint8_t *       sendbuf;    // send buffer
	size_t          sendlen;    // amount of data in send buffer
	size_t          sendoff;    // offset of start of send data
	uint8_t *       recvbuf;    // recv buffer
	size_t          recvlen;    // amount of data in recv buffer
	size_t          recvoff;    // offset of start of recv data
	nni_list        sends;      // upper side sends
	nni_list        recvs;      // upper recv aios
	nni_aio *       handshake;  // handshake aio (upper)

	char ciphersuite_name_buffer[255]; // buffer for holding return value
	                                   // of nni_tls_ciphersuite_name
};

struct nng_tls_config {
	// mbedtls_ssl_config cfg_ctx;
	nni_mtx lk;
	bool    active;
	char *  server_name;
	// mbedtls_x509_crt ca_certs;
	// mbedtls_x509_crl crl;

	int refcnt; // servers increment the reference

	nni_list     certkeys;
	nng_tls_mode mode;
	CredHandle   credentials;
};

static void nni_tls_send_cb(void *);
static void nni_tls_recv_cb(void *);
static void nni_tls_recv_start(nni_tls *);

static void nni_tls_do_send(nni_tls *);
static void nni_tls_do_recv(nni_tls *);
static void nni_tls_do_handshake(nni_tls *);
static int  nni_tls_start_handshake(nni_tls *);

static schannel_internal_error_codes nni_tls_net_send(
    nni_tls *, const unsigned char *, size_t);
static schannel_internal_error_codes nni_tls_net_recv(
    nni_tls *, unsigned char *, size_t);

static int             schannel_client_create_credentials(nng_tls_config *cfg);
static SECURITY_STATUS schannel_client_handshake(nni_tls *tp);
static schannel_internal_error_codes schannel_client_handshake_cb(nni_tls *tp);

static schannel_internal_error_codes schannel_ssl_write(
    nni_tls *, void *, size_t);

static schannel_internal_error_codes schannel_ssl_read(
    nni_tls *, void *, size_t);

static int
nni_tls_get_entropy(void *arg, unsigned char *buf, size_t len)
{
	// todo: use crypto system calls
	NNI_ARG_UNUSED(arg);
	while (len) {
		uint32_t x = nni_random();
		size_t   n;

		n = len < sizeof(x) ? len : sizeof(x);
		memcpy(buf, &x, n);
		len -= n;
		buf += n;
	}
	return (0);
}

static int
nni_tls_random(void *arg, unsigned char *buf, size_t sz)
{
	// todo: use crypto system calls
	return (nni_tls_get_entropy(arg, buf, sz));
}

void
nni_tls_config_fini(nng_tls_config *cfg)
{
	nni_tls_certkey *ck;

	nni_mtx_lock(&cfg->lk);
	cfg->refcnt--;
	if (cfg->refcnt != 0) {
		nni_mtx_unlock(&cfg->lk);
		return;
	}
	nni_mtx_unlock(&cfg->lk);

	// mbedtls_ssl_config_free(&cfg->cfg_ctx);
	// mbedtls_x509_crt_free(&cfg->ca_certs);
	// mbedtls_x509_crl_free(&cfg->crl);
	if (cfg->server_name) {
		nni_strfree(cfg->server_name);
	}
	while ((ck = nni_list_first(&cfg->certkeys))) {
		nni_list_remove(&cfg->certkeys, ck);
		// mbedtls_x509_crt_free(&ck->crt);
		// mbedtls_pk_free(&ck->key);

		NNI_FREE_STRUCT(ck);
	}

	if (SEC_VALID(cfg->credentials)) {
		FreeCredentialsHandle(&cfg->credentials);
	}

	nni_mtx_fini(&cfg->lk);
	NNI_FREE_STRUCT(cfg);
}

int
nni_tls_config_init(nng_tls_config **cpp, enum nng_tls_mode mode)
{
	nng_tls_config *cfg;
	int             rv = 0;

	if ((cfg = NNI_ALLOC_STRUCT(cfg)) == NULL) {
		return (NNG_ENOMEM);
	}
	cfg->mode   = mode;
	cfg->refcnt = 1;
	nni_mtx_init(&cfg->lk);

	NNI_LIST_INIT(&cfg->certkeys, nni_tls_certkey, node);
	// mbedtls_ssl_config_init(&cfg->cfg_ctx);
	// mbedtls_x509_crt_init(&cfg->ca_certs);
	// mbedtls_x509_crl_init(&cfg->crl);
	//
	// rv = mbedtls_ssl_config_defaults(&cfg->cfg_ctx, sslmode,
	//    MBEDTLS_SSL_TRANSPORT_STREAM, MBEDTLS_SSL_PRESET_DEFAULT);
	if (rv != 0) {
		nni_tls_config_fini(cfg);
		return (rv);
	}

	// mbedtls_ssl_conf_authmode(&cfg->cfg_ctx, authmode);

	// We *require* TLS v1.2 or newer, which is also known as SSL v3.3.
	// mbedtls_ssl_conf_min_version(&cfg->cfg_ctx,
	//     MBEDTLS_SSL_MAJOR_VERSION_3, MBEDTLS_SSL_MINOR_VERSION_3);

	// mbedtls_ssl_conf_rng(&cfg->cfg_ctx, nni_tls_random, cfg);
	//
	// mbedtls_ssl_conf_dbg(&cfg->cfg_ctx, nni_tls_dbg, cfg);

	if (mode == NNG_TLS_MODE_CLIENT) {
		rv = schannel_client_create_credentials(cfg);
		if (rv != 0) {
			nni_tls_config_fini(cfg);
			return (rv);
		}
	}

	*cpp = cfg;
	return (0);
}

void
nni_tls_config_hold(nng_tls_config *cfg)
{
	nni_mtx_lock(&cfg->lk);
	cfg->refcnt++;
	nni_mtx_unlock(&cfg->lk);
}

void
nni_tls_fini(nni_tls *tp)
{
	// Shut it all down first.
	if (tp->tcp) {
		nni_tcp_conn_close(tp->tcp);
	}
	nni_aio_stop(tp->tcp_send);
	nni_aio_stop(tp->tcp_recv);

	// And finalize / free everything.
	if (tp->tcp) {
		nni_tcp_conn_fini(tp->tcp);
	}
	nni_aio_fini(tp->tcp_send);
	nni_aio_fini(tp->tcp_recv);
	// mbedtls_ssl_free(&tp->ctx);
	nni_mtx_fini(&tp->lk);
	nni_free(tp->recvbuf, NNG_TLS_MAX_BUFFER_SIZE);
	nni_free(tp->sendbuf, NNG_TLS_MAX_BUFFER_SIZE);
	if (tp->cfg != NULL) {
		// release the hold we got on it
		nni_tls_config_fini(tp->cfg);
	}
	NNI_FREE_STRUCT(tp);
}

static int nni_tls_mkerr2(schannel_internal_error_codes ec)
{
	switch (ec)
	{
	case SCHANNEL_OUT_OF_MEMORY:
		return NNG_ENOMEM;
	case SCHANNEL_OTHER_ERROR:
		return NNG_EINVAL;
	case SCHANNEL_SECURITY_ERROR:
		return NNG_EPEERAUTH;
	case SCHANNEL_WRITE_PENDING: 
	case SCHANNEL_READ_PENDING: 
	case SCHANNEL_OK:
		return 0;

	case SCHANNEL_CONNECTION_CLOSED:
		return NNG_ECLOSED;
	}
	return NNG_EINTERNAL;
}

static int
nni_tls_mkerr(SECURITY_STATUS ss)
{
	return (NNG_ECRYPTO);
}

int
nni_tls_init(nni_tls **tpp, nng_tls_config *cfg, nni_tcp_conn *tcp)
{
	nni_tls *tp;
	int      rv;

	// During the handshake, disable Nagle to shorten the
	// negotiation.  Once things are set up the caller can
	// re-enable Nagle if so desired.
	(void) nni_tcp_conn_set_nodelay(tcp, true);

	if ((tp = NNI_ALLOC_STRUCT(tp)) == NULL) {
		return (NNG_ENOMEM);
	}
	if ((tp->recvbuf = nni_zalloc(NNG_TLS_MAX_BUFFER_SIZE)) == NULL) {
		NNI_FREE_STRUCT(tp);
		return (NNG_ENOMEM);
	}
	if ((tp->sendbuf = nni_zalloc(NNG_TLS_MAX_BUFFER_SIZE)) == NULL) {
		nni_free(tp->sendbuf, NNG_TLS_MAX_BUFFER_SIZE);
		NNI_FREE_STRUCT(tp);
		return (NNG_ENOMEM);
	}

	nni_mtx_lock(&cfg->lk);
	// No more changes allowed to config.
	cfg->active = true;
	cfg->refcnt++;
	tp->cfg = cfg;
	nni_mtx_unlock(&cfg->lk);

	nni_aio_list_init(&tp->sends);
	nni_aio_list_init(&tp->recvs);
	nni_mtx_init(&tp->lk);
	//	mbedtls_ssl_init(&tp->ctx);
	//	mbedtls_ssl_set_bio(
	//	    &tp->ctx, tp, nni_tls_net_send, nni_tls_net_recv, NULL);
	//
	//	if ((rv = mbedtls_ssl_setup(&tp->ctx, &cfg->cfg_ctx)) != 0) {
	//		rv = nni_tls_mkerr(rv);
	//		nni_tls_fini(tp);
	//		return (rv);
	//	}
	//
	//	if (cfg->server_name) {
	//		mbedtls_ssl_set_hostname(&tp->ctx, cfg->server_name);
	//	}

	tp->tcp = tcp;

	if (((rv = nni_aio_init(&tp->tcp_send, nni_tls_send_cb, tp)) != 0) ||
	    ((rv = nni_aio_init(&tp->tcp_recv, nni_tls_recv_cb, tp)) != 0)) {
		nni_tls_fini(tp);
		return (rv);
	}

	nni_mtx_lock(&tp->lk);
	// Kick off a handshake operation.
	if ((rv = nni_tls_start_handshake(tp)) != 0) {
		nni_tls_fini(tp);
		return (rv);
	}

	nni_mtx_unlock(&tp->lk);

	*tpp = tp;
	return (0);
}

static int
nni_tls_start_handshake(nni_tls *tp)
{
	SECURITY_STATUS ss = 0;

	if (tp->cfg->mode == NNG_TLS_MODE_CLIENT) {
		ss = schannel_client_handshake(tp);
	} else { //
		NNI_ASSERT(0);
	}

	nni_tls_recv_start(tp);

	if (FAILED(ss))
		return (nni_tls_mkerr(ss));

	return (0);
}

static void
nni_tls_cancel(nni_aio *aio, void *arg, int rv)
{
	nni_tls *tp = arg;
	nni_mtx_lock(&tp->lk);
	if (nni_aio_list_active(aio)) {
		nni_aio_list_remove(aio);
		nni_aio_finish_error(aio, rv);
	}
	nni_mtx_unlock(&tp->lk);
}

static void
nni_tls_fail(nni_tls *tp, int rv)
{
	nni_aio *aio;
	tp->tls_closed = true;
	nni_tcp_conn_close(tp->tcp);
	tp->tcp_closed = true;
	while ((aio = nni_list_first(&tp->recvs)) != NULL) {
		nni_list_remove(&tp->recvs, aio);
		nni_aio_finish_error(aio, rv);
	}
	while ((aio = nni_list_first(&tp->sends)) != NULL) {
		nni_list_remove(&tp->recvs, aio);
		nni_aio_finish_error(aio, rv);
	}
}

// nni_tls_send_cb is called when the underlying TCP send completes.
static void
nni_tls_send_cb(void *ctx)
{
	nni_tls *tp  = ctx;
	nni_aio *aio = tp->tcp_send;

	nni_mtx_lock(&tp->lk);
	if (nni_aio_result(aio) != 0) {
		nni_tcp_conn_close(tp->tcp);
		tp->tcp_closed = true;
	} else {
		const size_t n = nni_aio_count(aio);
		NNI_ASSERT(tp->sendlen <= n);
		tp->sendlen -= n;
		if (tp->sendlen) {
			nni_iov iov;
			tp->sendoff += n;
			iov.iov_buf = tp->sendbuf + tp->sendoff;
			iov.iov_len = tp->sendlen;
			nni_aio_set_iov(aio, 1, &iov);
			nni_aio_set_timeout(aio, NNG_DURATION_INFINITE);
			nni_tcp_conn_send(tp->tcp, aio);
			nni_mtx_unlock(&tp->lk);
			return;
		}
		tp->sendoff = 0;
		tp->sending = false;
	}
	if (!tp->hsdone) {
		nni_tls_do_handshake(tp);
	}
	if (tp->hsdone) {
		nni_tls_do_send(tp);
		nni_tls_do_recv(tp);
	}
	nni_mtx_unlock(&tp->lk);
}

static void
nni_tls_recv_start(nni_tls *tp)
{
	nni_aio *aio;
	nni_iov  iov;

	if (tp->recving || tp->tcp_closed) {
		return;
	}
	// If we already have data, wait for that to be consumed before
	// doing another read.
	if (tp->recvlen != 0) {
		return;
	}

	tp->recving = true;
	tp->recvoff = 0;
	aio         = tp->tcp_recv;
	iov.iov_buf = tp->recvbuf;
	iov.iov_len = NNG_TLS_MAX_BUFFER_SIZE;
	nni_aio_set_iov(aio, 1, &iov);
	nni_aio_set_timeout(tp->tcp_recv, NNG_DURATION_INFINITE);
	nni_tcp_conn_recv(tp->tcp, aio);
}

static void
nni_tls_recv_cb(void *ctx)
{
	nni_tls *tp  = ctx;
	nni_aio *aio = tp->tcp_recv;

	nni_mtx_lock(&tp->lk);
	tp->recving = false;
	if (nni_aio_result(aio) != 0) {
		// Close the underlying TCP channel, but permit data we
		// already received to continue to be received.
		nni_tcp_conn_close(tp->tcp);
		tp->tcp_closed = true;
	} else {
		NNI_ASSERT(tp->recvlen == 0);
		NNI_ASSERT(tp->recvoff == 0);
		tp->recvlen = nni_aio_count(aio);
	}

	// If we were closed (above), the upper layer will detect and
	// react properly.  Otherwise the upper layer will consume
	// data.
	if (!tp->hsdone) {
		nni_tls_do_handshake(tp);
	}
	if (tp->hsdone) {
		nni_tls_do_recv(tp);
		nni_tls_do_send(tp);
	}

	nni_mtx_unlock(&tp->lk);
}

// This handles the bottom half send (i.e. sending over TCP).
// We always accept a chunk of data, to a limit, if the bottom
// sender is not busy.  Then we handle that in the background.
// If the sender *is* busy, we return MBEDTLS_ERR_SSL_WANT_WRITE.
// The chunk size we accept is 64k at a time, which prevents
// ridiculous over queueing.  This is always called with the pipe
// lock held, and never blocks.
static schannel_internal_error_codes
nni_tls_net_send(nni_tls *tp, const unsigned char *buf, size_t len)
{
	nni_iov iov;

	if (len > NNG_TLS_MAX_BUFFER_SIZE) {
		len = NNG_TLS_MAX_BUFFER_SIZE;
	}

	// We should already be running with the pipe lock held,
	// as we are running in that context.

	if (tp->sending) {
		return SCHANNEL_WRITE_PENDING;
	}
	if (tp->tcp_closed) {
		return SCHANNEL_CONNECTION_CLOSED;
	}

	tp->sending = 1;
	tp->sendlen = len;
	tp->sendoff = 0;
	memcpy(tp->sendbuf, buf, len);
	iov.iov_buf = tp->sendbuf;
	iov.iov_len = len;
	nni_aio_set_iov(tp->tcp_send, 1, &iov);
	nni_aio_set_timeout(tp->tcp_send, NNG_DURATION_INFINITE);
	nni_tcp_conn_send(tp->tcp, tp->tcp_send);
	return SCHANNEL_OK;
}

static schannel_internal_error_codes
nni_tls_net_recv(nni_tls *tp, unsigned char *buf, size_t len)
{
	// We should already be running with the pipe lock held,
	// as we are running in that context.
	if (tp->tcp_closed && tp->recvlen == 0) {
		return SCHANNEL_CONNECTION_CLOSED;
	}

	if (tp->recvlen == 0) {
		return SCHANNEL_READ_PENDING;
	} else {
		if (len > tp->recvlen) {
			len = tp->recvlen;
		}
		memcpy(buf, tp->recvbuf + tp->recvoff, len);
		tp->recvoff += len;
		tp->recvlen -= len;
	}

	nni_tls_recv_start(tp);
	return ((int) len);
}

// nni_tls_send is the exported send function.  It has a similar
// calling convention as the platform TCP pipe.
void
nni_tls_send(nni_tls *tp, nni_aio *aio)
{
	int rv;

	if (nni_aio_begin(aio) != 0) {
		return;
	}
	nni_mtx_lock(&tp->lk);
	if (tp->tls_closed) {
		nni_mtx_unlock(&tp->lk);
		nni_aio_finish_error(aio, NNG_ECLOSED);
		return;
	}
	if ((rv = nni_aio_schedule(aio, nni_tls_cancel, tp)) != 0) {
		nni_mtx_unlock(&tp->lk);
		nni_aio_finish_error(aio, rv);
		return;
	}
	nni_list_append(&tp->sends, aio);
	nni_tls_do_send(tp);
	nni_mtx_unlock(&tp->lk);
}

void
nni_tls_recv(nni_tls *tp, nni_aio *aio)
{
	int rv;

	if (nni_aio_begin(aio) != 0) {
		return;
	}
	nni_mtx_lock(&tp->lk);
	if (tp->tls_closed) {
		nni_mtx_unlock(&tp->lk);
		nni_aio_finish_error(aio, NNG_ECLOSED);
		return;
	}
	if ((rv = nni_aio_schedule(aio, nni_tls_cancel, tp)) != 0) {
		nni_mtx_unlock(&tp->lk);
		nni_aio_finish_error(aio, rv);
		return;
	}

	nni_list_append(&tp->recvs, aio);
	nni_tls_do_recv(tp);
	nni_mtx_unlock(&tp->lk);
}

int
nni_tls_peername(nni_tls *tp, nni_sockaddr *sa)
{
	return (nni_tcp_conn_peername(tp->tcp, sa));
}

int
nni_tls_sockname(nni_tls *tp, nni_sockaddr *sa)
{
	return (nni_tcp_conn_sockname(tp->tcp, sa));
}

int
nni_tls_set_nodelay(nni_tls *tp, bool val)
{
	return (nni_tcp_conn_set_nodelay(tp->tcp, val));
}

int
nni_tls_set_keepalive(nni_tls *tp, bool val)
{
	return (nni_tcp_conn_set_keepalive(tp->tcp, val));
}

static void
nni_tls_do_handshake(nni_tls *tp)
{
	int rv = -1;

	if (tp->tls_closed) {
		return;
	}

	if (tp->cfg->mode == NNG_TLS_MODE_CLIENT) {
		rv = schannel_client_handshake_cb(tp);
	} else {
		NNI_ASSERT(0);
	}

	//	rv = mbedtls_ssl_handshake(&tp->ctx);
	switch (rv) {
	case SCHANNEL_WRITE_PENDING:
	case SCHANNEL_READ_PENDING:
		// We have underlying I/O to complete first.  We will
		// be called again by a callback later.
		return;
	case 0:
		// The handshake is done, yay!

		// fill info about buffers.
		if (FAILED(QueryContextAttributesA(&tp->ssl_context,
		        SECPKG_ATTR_STREAM_SIZES, &tp->stream_sizes))) {

			nni_tls_fail(tp, NNG_EINVAL);
			return;
		}

		tp->hsdone = true;
		return;

	default:
		// some other error occurred, this causes us to tear it
		// down
		nni_tls_fail(tp, nni_tls_mkerr2(rv));
	}
}

// nni_tls_do_send is called to try to send more data if we have not
// yet completed the I/O.  It also completes any transactions that
// *have* completed.  It must be called with the lock held.
static void
nni_tls_do_send(nni_tls *tp)
{
	nni_aio *aio;

	if (!tp->hsdone)
		return;

	while ((aio = nni_list_first(&tp->sends)) != NULL) {
		int      n;
		uint8_t *buf = NULL;
		size_t   len = 0;
		nni_iov *iov;
		unsigned niov;

		nni_aio_get_iov(aio, &niov, &iov);

		for (unsigned i = 0; i < niov; i++) {
			if (iov[i].iov_len != 0) {
				buf = iov[i].iov_buf;
				len = iov[i].iov_len;
				break;
			}
		}
		if (len == 0 || buf == NULL) {
			nni_aio_list_remove(aio);
			nni_aio_finish_error(aio, NNG_EINVAL);
			continue;
		}

		n = schannel_ssl_write(tp, buf, len);
		if (n == SCHANNEL_READ_PENDING ||
		    n == SCHANNEL_WRITE_PENDING) {
			// cannot send anything more, wait for callback
			return;
		}

		// Some other error occurred... this is not good.
		// Want better diagnostics.
		nni_aio_list_remove(aio);
		if (n < 0) {
			nni_aio_finish_error(aio, nni_tls_mkerr2(n));
		} else {
			nni_aio_finish(aio, 0, n);
		}
	}
}

static void
nni_tls_do_recv(nni_tls *tp)
{
	nni_aio *aio;

	while ((aio = nni_list_first(&tp->recvs)) != NULL) {
		int      n;
		uint8_t *buf = NULL;
		size_t   len = 0;
		nni_iov *iov;
		unsigned niov;

		nni_aio_get_iov(aio, &niov, &iov);

		for (unsigned i = 0; i < niov; i++) {
			if (iov[i].iov_len != 0) {
				buf = iov[i].iov_buf;
				len = iov[i].iov_len;
				break;
			}
		}
		if (len == 0 || buf == NULL) {
			nni_aio_list_remove(aio);
			nni_aio_finish_error(aio, NNG_EINVAL);
			continue;
		}

		n = schannel_ssl_read(tp, buf, len);

		if ((n == SCHANNEL_WRITE_PENDING) ||
		    (n == SCHANNEL_READ_PENDING)) {
			// Cannot receive any more data right now, wait
			// for callback.
			return;
		}

		nni_aio_list_remove(aio);

		if (n < 0) {
			nni_aio_finish_error(aio, nni_tls_mkerr(n));
		} else {
			nni_aio_finish(aio, 0, n);
		}
	}
}

void
nni_tls_close(nni_tls *tp)
{
	nni_aio *aio;

	nni_aio_close(tp->tcp_send);
	nni_aio_close(tp->tcp_recv);

	nni_mtx_lock(&tp->lk);
	tp->tls_closed = true;

	while ((aio = nni_list_first(&tp->sends)) != NULL) {
		nni_aio_list_remove(aio);
		nni_aio_finish_error(aio, NNG_ECLOSED);
	}

	while ((aio = nni_list_first(&tp->recvs)) != NULL) {
		nni_aio_list_remove(aio);
		nni_aio_finish_error(aio, NNG_ECLOSED);
	}

	if (tp->hsdone) {
		// This may succeed, or it may fail.  Either way we
		// don't care. Implementations that depend on
		// close-notify to mean anything are broken by design,
		// just like RFC.  Note that we do *NOT* close the TCP
		// connection at this point.
		//		(void) mbedtls_ssl_close_notify(&tp->ctx);
	} else {
		nni_tcp_conn_close(tp->tcp);
	}
	nni_mtx_unlock(&tp->lk);
}

static const char *
nni_tls_conninfo_protocol(DWORD protocol)
{
	static char unknown_buffer[16]; // not thread safe. who cares.
	switch (protocol) {
	case SP_PROT_TLS1_CLIENT:
	case SP_PROT_TLS1_SERVER:
		return "TLS1.0";

	case SP_PROT_TLS1_1_CLIENT:
	case SP_PROT_TLS1_1_SERVER:
		return "TLS1.1";

	case SP_PROT_TLS1_2_CLIENT:
	case SP_PROT_TLS1_2_SERVER:
		return "TLS1.2";

	case SP_PROT_TLS1_3_CLIENT:
	case SP_PROT_TLS1_3_SERVER:
		return "TLS1.3";

	case SP_PROT_SSL3_CLIENT:
	case SP_PROT_SSL3_SERVER:
		return "SSL3";

	case SP_PROT_PCT1_CLIENT:
	case SP_PROT_PCT1_SERVER:
		return "PCT";

	case SP_PROT_SSL2_CLIENT:
	case SP_PROT_SSL2_SERVER:
		return "SSL2";

	default:
		snprintf(unknown_buffer, 16, "p: 0x%lu", protocol);
		return unknown_buffer;
	}
}

static const char *
nni_tls_conninfo_cipher(DWORD cipher)
{
	static char unknown_buffer[16]; // not thread safe. who cares.
	switch (cipher) {
	case CALG_RC4:
		return "RC4";

	case CALG_3DES:
		return "TripeDES";
	case CALG_AES_128:
		return "AES128";
	case CALG_AES_192:
		return "AES192";
	case CALG_AES_256:
		return "AES256";
	case CALG_AES:
		return "AES";

	case CALG_RC2:
		return "RC2";

	case CALG_DES:
	case CALG_CYLINK_MEK:
		return "DES";

	case CALG_SKIPJACK:
		return "Skipjack";

	default:
		snprintf(unknown_buffer, 16, "c: 0x%lu", cipher);
		return unknown_buffer;
	}
}

const char *
nni_tls_conninfo_hash(DWORD hash)
{
	static char unknown_buffer[16]; // not thread safe. who cares.
	switch (hash) {
	case CALG_MD5:
		return "MD5";

	case CALG_SHA:
		return "SHA";
	case CALG_SHA_256:
		return "SHA256";
	case CALG_SHA_512:
		return "SHA512";

	default:
		snprintf(unknown_buffer, 16, "h: 0x%lu", hash);
		return unknown_buffer;
	}
}

const char *
nni_tls_ciphersuite_name(nni_tls *tp)
{
	SECURITY_STATUS              ss;
	SecPkgContext_ConnectionInfo ci;

	ss = QueryContextAttributes(
	    &tp->ssl_context, SECPKG_ATTR_CONNECTION_INFO, (PVOID) &ci);

	if (FAILED(ss)) {
		return "?";
	}

	snprintf(tp->ciphersuite_name_buffer,
	    sizeof(tp->ciphersuite_name_buffer), "%s %s %s",
	    nni_tls_conninfo_protocol(ci.dwProtocol),
	    nni_tls_conninfo_cipher(ci.aiCipher),
	    nni_tls_conninfo_hash(ci.aiHash));

	return tp->ciphersuite_name_buffer;
}

bool
nni_tls_verified(nni_tls *tp)
{
	return true; // todo: how to get this?
	             //	return (mbedtls_ssl_get_verify_result(&tp->ctx)
	             //== 0);
}

int
nng_tls_config_server_name(nng_tls_config *cfg, const char *name)
{
	int rv;
	nni_mtx_lock(&cfg->lk);
	if (cfg->active) {
		nni_mtx_unlock(&cfg->lk);
		return (NNG_ESTATE);
	}
	if (cfg->server_name) {
		nni_strfree(cfg->server_name);
	}
	cfg->server_name = nni_strdup(name);
	rv               = cfg->server_name == NULL ? NNG_ENOMEM : 0;
	nni_mtx_unlock(&cfg->lk);
	return (rv);
}

int
nng_tls_config_auth_mode(nng_tls_config *cfg, nng_tls_auth_mode mode)
{
	nni_mtx_lock(&cfg->lk);
	if (cfg->active) {
		nni_mtx_unlock(&cfg->lk);
		return (NNG_ESTATE);
	}
	switch (mode) {
		// todo: how to support modes?
	default:
		nni_mtx_unlock(&cfg->lk);
		return (NNG_EINVAL);
	}
	nni_mtx_unlock(&cfg->lk);
	return (0);
}

int
nng_tls_config_ca_chain(
    nng_tls_config *cfg, const char *certs, const char *crl)
{
	size_t         len;
	const uint8_t *pem;
	int            rv;

	// Certs and CRL are in PEM data, with terminating NUL byte.
	nni_mtx_lock(&cfg->lk);
	if (cfg->active) {
		rv = NNG_ESTATE;
		goto err;
	}
	pem = (const uint8_t *) certs;
	len = strlen(certs) + 1;
	//	if ((rv = mbedtls_x509_crt_parse(&cfg->ca_certs, pem,
	// len)) !=
	// 0) { 		rv = nni_tls_mkerr(rv);
	// goto err;
	//	}
	//	if (crl != NULL) {
	//		pem = (const uint8_t *) crl;
	//		len = strlen(crl) + 1;
	//		if ((rv = mbedtls_x509_crl_parse(&cfg->crl,
	// pem, len))
	//!=
	// 0) { 			rv = nni_tls_mkerr(rv);
	// goto err;
	//		}
	//	}
	//
	//	mbedtls_ssl_conf_ca_chain(&cfg->cfg_ctx,
	//&cfg->ca_certs, &cfg->crl);

err:
	nni_mtx_unlock(&cfg->lk);
	return (rv);
}

int
nng_tls_config_own_cert(
    nng_tls_config *cfg, const char *cert, const char *key, const char *pass)
{
	size_t           len;
	const uint8_t *  pem;
	nni_tls_certkey *ck;
	int              rv;

	if ((ck = NNI_ALLOC_STRUCT(ck)) == NULL) {
		return (NNG_ENOMEM);
	}
	//	mbedtls_x509_crt_init(&ck->crt);
	//	mbedtls_pk_init(&ck->key);
	//
	//	pem = (const uint8_t *) cert;
	//	len = strlen(cert) + 1;
	//	if ((rv = mbedtls_x509_crt_parse(&ck->crt, pem, len))
	//!= 0) { 		rv = nni_tls_mkerr(rv);
	//! goto err;
	//	}

	pem = (const uint8_t *) key;
	len = strlen(key) + 1;
	//	rv  = mbedtls_pk_parse_key(&ck->key, pem, len, (const
	// uint8_t
	//*) pass,
	//            pass != NULL ? strlen(pass) : 0);
	if (rv != 0) {
		rv = nni_tls_mkerr(rv);
		goto err;
	}

	nni_mtx_lock(&cfg->lk);
	if (cfg->active) {
		nni_mtx_unlock(&cfg->lk);
		rv = NNG_ESTATE;
		goto err;
	}
	//	rv = mbedtls_ssl_conf_own_cert(&cfg->cfg_ctx, &ck->crt,
	//&ck->key);
	if (rv != 0) {
		nni_mtx_unlock(&cfg->lk);
		rv = nni_tls_mkerr(rv);
		goto err;
	}

	// Save this structure so we can free it with the context.
	nni_list_append(&cfg->certkeys, ck);
	nni_mtx_unlock(&cfg->lk);
	return (0);

err:
	//	mbedtls_x509_crt_free(&ck->crt);
	//	mbedtls_pk_free(&ck->key);
	NNI_FREE_STRUCT(ck);
	return (rv);
}

int
nng_tls_config_ca_file(nng_tls_config *cfg, const char *path)
{
	int    rv;
	void * fdata;
	size_t fsize;
	char * pem;
	// Note that while mbedTLS supports its own file methods, we
	// want to avoid depending on that because it might not have
	// been included, so we use our own.  We have to read the file,
	// and then allocate a buffer that has an extra byte so we can
	// ensure NUL termination.  The file named by path may contain
	// both a ca chain, and crl chain, or just a ca chain.
	if ((rv = nni_file_get(path, &fdata, &fsize)) != 0) {
		return (rv);
	}
	if ((pem = nni_zalloc(fsize + 1)) == NULL) {
		nni_free(fdata, fsize);
		return (NNG_ENOMEM);
	}
	memcpy(pem, fdata, fsize);
	nni_free(fdata, fsize);
	if (strstr(pem, "-----BEGIN X509 CRL-----") != NULL) {
		rv = nng_tls_config_ca_chain(cfg, pem, pem);
	} else {
		rv = nng_tls_config_ca_chain(cfg, pem, NULL);
	}
	nni_free(pem, fsize + 1);
	return (rv);
}

int
nng_tls_config_cert_key_file(
    nng_tls_config *cfg, const char *path, const char *pass)
{
	int    rv;
	void * fdata;
	size_t fsize;
	char * pem;

	// Note that while mbedTLS supports its own file methods, we
	// want to avoid depending on that because it might not have
	// been included, so we use our own.  We have to read the file,
	// and then allocate a buffer that has an extra byte so we can
	// ensure NUL termination.  The file named by path must contain
	// both our certificate, and our private key.  The password
	// may be NULL if the key is not encrypted.
	if ((rv = nni_file_get(path, &fdata, &fsize)) != 0) {
		return (rv);
	}
	if ((pem = nni_zalloc(fsize + 1)) == NULL) {
		nni_free(fdata, fsize);
		return (NNG_ENOMEM);
	}
	memcpy(pem, fdata, fsize);
	nni_free(fdata, fsize);
	rv = nng_tls_config_own_cert(cfg, pem, pem, pass);
	nni_free(pem, fsize + 1);
	return (rv);
}

int
nng_tls_config_alloc(nng_tls_config **cfgp, nng_tls_mode mode)
{
	return (nni_tls_config_init(cfgp, mode));
}

void
nng_tls_config_free(nng_tls_config *cfg)
{
	nni_tls_config_fini(cfg);
}

static int
schannel_client_create_credentials(nng_tls_config *cfg)
{
	SCHANNEL_CRED   schannel_cred = { 0 };
	SECURITY_STATUS ss;
	TimeStamp       expires;

	schannel_cred.dwVersion = SCHANNEL_CRED_VERSION;
	schannel_cred.dwFlags   = SCH_CRED_NO_DEFAULT_CREDS |
	    SCH_CRED_NO_SYSTEM_MAPPER | SCH_CRED_REVOCATION_CHECK_CHAIN;

	// enforce at leastls1_2
	schannel_cred.grbitEnabledProtocols =
	    SP_PROT_TLS1_2 | SP_PROT_TLS1_3 | SP_PROT_TLS1_3PLUS;

	ss = AcquireCredentialsHandleA(NULL, (LPSTR) UNISP_NAME_A,
	    SECPKG_CRED_OUTBOUND, NULL, &schannel_cred, NULL, NULL,
	    &cfg->credentials, &expires);

	// todo: check expiration?
	if (FAILED(ss)) {
		return (nni_tls_mkerr(ss));
	}

	return 0;
}

static SECURITY_STATUS
schannel_client_handshake(nni_tls *tp)
{
	SECURITY_STATUS ss;
	SecBuffer       out_buffers[1];
	SecBufferDesc   out_buffer;
	DWORD           out_flags;
	TimeStamp       expires;
	int             rv;

	out_buffer.ulVersion = SECBUFFER_VERSION;
	out_buffer.cBuffers  = 1;
	out_buffer.pBuffers  = out_buffers;

	out_buffers[0].BufferType = SECBUFFER_TOKEN;
	out_buffers[0].cbBuffer   = 0;
	out_buffers[0].pvBuffer   = NULL;

	ss = InitializeSecurityContext(&tp->cfg->credentials, NULL,
	    tp->cfg->server_name, SSPI_FLAGS, 0, SECURITY_NATIVE_DREP, NULL, 0,
	    &tp->ssl_context, &out_buffer, &out_flags, &expires);

	// todo: check expiration?

	if (ss != SEC_I_CONTINUE_NEEDED) {
		return (ss);
	}

	if (out_buffers[0].cbBuffer > 0 && out_buffers[0].pvBuffer != NULL) {

		if (nni_tls_net_send(tp, out_buffers[0].pvBuffer,
		        out_buffers[0].cbBuffer) < 0) {
			FreeContextBuffer(out_buffers[0].pvBuffer);
			return (NNG_ETRANERR);
		}

		FreeContextBuffer(out_buffers[0].pvBuffer);
	}
	return (ss);
}

static schannel_internal_error_codes
schannel_client_handshake_cb(nni_tls *tp)
{
	SECURITY_STATUS ss;
	DWORD           out_flags;
	TimeStamp       expires;
	SecBufferDesc   out_buffer, in_buffer;
	SecBuffer       in_buffers[2], out_buffers[1];
	unsigned char   buffer[NNG_TLS_MAX_BUFFER_SIZE];

	schannel_internal_error_codes buffer_len = 0;

	buffer_len = nni_tls_net_recv(tp, buffer, NNG_TLS_MAX_BUFFER_SIZE);

	if (buffer_len < 0) {
		return buffer_len;
	}

	// Set up the input buffers. Buffer 0 is used to pass in data
	// received from the server. Schannel will consume some or all
	// of this. Leftover data (if any) will be placed in buffer 1
	// and given a buffer type of SECBUFFER_EXTRA.
	in_buffers[0].pvBuffer   = buffer;
	in_buffers[0].cbBuffer   = buffer_len;
	in_buffers[0].BufferType = SECBUFFER_TOKEN;

	in_buffers[1].pvBuffer   = NULL;
	in_buffers[1].cbBuffer   = 0;
	in_buffers[1].BufferType = SECBUFFER_EMPTY;

	in_buffer.cBuffers  = 2;
	in_buffer.pBuffers  = in_buffers;
	in_buffer.ulVersion = SECBUFFER_VERSION;

	// Set up the output buffers. These are initialized to NULL
	// so as to make it less likely we'll attempt to free random
	// garbage later.
	out_buffers[0].pvBuffer   = NULL;
	out_buffers[0].BufferType = SECBUFFER_TOKEN;
	out_buffers[0].cbBuffer   = 0;

	out_buffer.cBuffers  = 1;
	out_buffer.pBuffers  = out_buffers;
	out_buffer.ulVersion = SECBUFFER_VERSION;

	// Call InitializeSecurityContext.
	ss = InitializeSecurityContextA(&tp->cfg->credentials,
	    &tp->ssl_context, NULL, SSPI_FLAGS | ISC_RET_EXTENDED_ERROR, 0,
	    SECURITY_NATIVE_DREP, &in_buffer, 0, NULL, &out_buffer, &out_flags,
	    &expires);

	if (ss == SEC_E_OK || ss == SEC_I_CONTINUE_NEEDED) {
		if (out_buffers[0].cbBuffer > 0 &&
		    out_buffers[0].pvBuffer != NULL) {

			if (nni_tls_net_send(tp, out_buffers[0].pvBuffer,
			        out_buffers[0].cbBuffer) < 0) {
				FreeContextBuffer(out_buffers[0].pvBuffer);
				return (NNG_ETRANERR);
			}

			FreeContextBuffer(out_buffers[0].pvBuffer);
		}
	}

	// If InitializeSecurityContext returned
	// SEC_E_INCOMPLETE_MESSAGE, then we need to read more data
	// from the server and try again.
	if (ss == SEC_E_INCOMPLETE_MESSAGE)
		return (SCHANNEL_READ_PENDING);

	if (ss == SEC_E_OK) {
		// If the "extra" buffer contains data, this is
		// encrypted application protocol layer stuff. It needs
		// to be saved. The application layer will later
		// decrypt it with DecryptMessage.
		if (in_buffers[1].BufferType == SECBUFFER_EXTRA) {
			NNI_ASSERT(0 && "to be implemented");
		}
	}

	if (FAILED(ss)) {
		return (SCHANNEL_SECURITY_ERROR);
	}

	if (ss == SEC_I_CONTINUE_NEEDED) {
		return (SCHANNEL_WRITE_PENDING);
	}

	return (0);
}

static schannel_internal_error_codes
schannel_ssl_write(nni_tls *tp, void *buffer, size_t len)
{
	SECURITY_STATUS ss;
	SecBufferDesc   msg;
	SecBuffer       buffers[4];

	unsigned char *data = nni_alloc(
	    tp->stream_sizes.cbHeader + tp->stream_sizes.cbTrailer + len);

	if (data == NULL) {
		return (SCHANNEL_OUT_OF_MEMORY);
	}

	memcpy(data + tp->stream_sizes.cbHeader, buffer, len);

	// EncryptMessage requires 4 buffers. [0] and [2] does not need
	// any initialization. Encrypted message is always larger.

	buffers[0].pvBuffer   = data;
	buffers[0].cbBuffer   = tp->stream_sizes.cbHeader;
	buffers[0].BufferType = SECBUFFER_STREAM_HEADER;

	buffers[1].pvBuffer   = data + tp->stream_sizes.cbHeader;
	buffers[1].cbBuffer   = len;
	buffers[1].BufferType = SECBUFFER_DATA;

	buffers[2].pvBuffer   = data + len + tp->stream_sizes.cbHeader;
	buffers[2].cbBuffer   = tp->stream_sizes.cbTrailer;
	buffers[2].BufferType = SECBUFFER_STREAM_TRAILER;

	buffers[3].pvBuffer   = SECBUFFER_EMPTY;
	buffers[3].cbBuffer   = SECBUFFER_EMPTY;
	buffers[3].BufferType = SECBUFFER_EMPTY;

	msg.ulVersion = SECBUFFER_VERSION;
	msg.cBuffers  = 4;
	msg.pBuffers  = buffers;

	ss = EncryptMessage(&tp->ssl_context, 0, &msg, 0);

	if (FAILED(ss)) {
		nni_free(data,
		    tp->stream_sizes.cbHeader + tp->stream_sizes.cbTrailer);

		return (SCHANNEL_SECURITY_ERROR);
	}

	nni_tls_net_send(tp, data,
	    tp->stream_sizes.cbHeader + tp->stream_sizes.cbTrailer + len);

	nni_free(data, tp->stream_sizes.cbHeader + tp->stream_sizes.cbTrailer);
	return (len);
}

static schannel_internal_error_codes
schannel_ssl_read(nni_tls *tp, void *buffer, size_t len)
{
	SECURITY_STATUS ss;
	SecBufferDesc   msg;
	SecBuffer       buffers[4];
	SecBuffer *     dataBuffer = NULL;
	// EncryptMessage requires 4 buffers. [0] and [2] does not need
	// any initialization.

	int            readed;
	unsigned char *read_buffer = nni_alloc(len);

	if (read_buffer == NULL)
		return (SCHANNEL_OUT_OF_MEMORY);

	readed = nni_tls_net_recv(tp, read_buffer, len);
	if (readed < 0)
		return readed;

	buffers[0].pvBuffer   = read_buffer;
	buffers[0].cbBuffer   = readed;
	buffers[0].BufferType = SECBUFFER_DATA;

	buffers[1].BufferType = SECBUFFER_EMPTY;
	buffers[2].BufferType = SECBUFFER_EMPTY;
	buffers[3].BufferType = SECBUFFER_EMPTY;

	msg.ulVersion = SECBUFFER_VERSION;
	msg.cBuffers  = 4;
	msg.pBuffers  = buffers;

	ss = DecryptMessage(&tp->ssl_context, &msg, 0, NULL);

	if (FAILED(ss)) {
		nni_free(read_buffer, len);
		return (SCHANNEL_SECURITY_ERROR);
	}

	// other buffers contain bogus data
	for (int i = 0; i < 4; i++) {
		if (buffers[i].BufferType == SECBUFFER_DATA) {
			dataBuffer = &buffers[i];
			break;
		}
	}

	if (dataBuffer == NULL) {
		nni_free(read_buffer, len);
		return (SCHANNEL_SECURITY_ERROR);
	}

	memcpy(buffer, dataBuffer->pvBuffer, dataBuffer->cbBuffer);

	nni_free(read_buffer, len);
	return (dataBuffer->cbBuffer);
}