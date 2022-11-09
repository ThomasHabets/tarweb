#include "tls.h"

#include <openssl/ssl.h>
#include <memory>

TLSConnection::TLSConnection(SSL_CTX* ctx)
{
    if (ssl_ = SSL_new(ctx); !ssl_) {
        throw std::runtime_error("KTLS: failed to create SSL object");
    }
}

TLSConnection::~TLSConnection()
{
    if (ssl_) {
        SSL_free(ssl_);
    }
}

TLS::TLS(const std::string& cert, const std::string& priv)
{
    if (ctx_ = SSL_CTX_new(TLS_server_method()); !ctx_) {
        throw std::runtime_error("KTLS: failed create CTX");
    }

    // Enable KTLS.
    SSL_CTX_set_options(ctx_, SSL_OP_ENABLE_KTLS);

    // OpenSSL doesn't yet support TLS_RX on TLS 1.3.
    if (!SSL_CTX_set_min_proto_version(ctx_, TLS1_2_VERSION)) {
        throw std::runtime_error("KTLS: failed to set min version to 1.2");
    }
    if (!SSL_CTX_set_max_proto_version(ctx_, TLS1_2_VERSION)) {
        throw std::runtime_error("KTLS: failed to set max version to 1.2");
    }

    // Load my cert.
    if (SSL_CTX_use_certificate_chain_file(ctx_, cert.c_str()) != 1) {
        throw std::runtime_error("KTLS: failed load cert");
    }

    // Load my key.
    if (SSL_CTX_use_PrivateKey_file(ctx_, priv.c_str(), SSL_FILETYPE_PEM) !=
        1) {
        throw std::runtime_error("KTLS: failed load privkey");
    }
}

TLS::~TLS()
{
    if (ctx_) {
        SSL_CTX_free(ctx_);
    }
}

std::unique_ptr<TLSConnection> TLS::enable_ktls(int fd, bool server)
{
    auto tls = std::make_unique<TLSConnection>(ctx_);

    if (int err = SSL_set_fd(tls->ssl(), fd); err != 1) {
        throw std::runtime_error("KTLS: failed to set fd for SSL object");
    }

    if (const int handshake =
            [&tls, server] {
                if (server) {
                    return SSL_accept(tls->ssl());
                }
                return SSL_connect(tls->ssl());
            }();
        handshake != 1) {
        throw std::runtime_error("KTLS: failed to handshake");
    }

    if (!BIO_get_ktls_send(SSL_get_wbio(tls->ssl()))) {
        throw std::runtime_error("KTLS not enabled for send");
    }
    if (!BIO_get_ktls_recv(SSL_get_rbio(tls->ssl()))) {
        throw std::runtime_error("KTLS not enabled for receive");
    }
    return tls;
}
