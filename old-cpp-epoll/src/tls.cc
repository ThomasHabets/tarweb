#include "tls.h"

#include <linux/tls.h>
#include <openssl/ssl.h>
#include <sys/socket.h>
#include <sys/types.h>
#include <iostream>
#include <memory>

TLSConnection::TLSConnection(SSL_CTX* ctx, int fd)
{
    if (ssl_ = SSL_new(ctx); !ssl_) {
        throw std::runtime_error("KTLS: failed to create SSL object");
    }
    if (int err = SSL_set_fd(ssl_, fd); err != 1) {
        SSL_free(ssl_);
        throw std::runtime_error("KTLS: failed to set fd for SSL object");
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

/*
 https://patchwork.kernel.org/project/linux-crypto/patch/20180320175434.GA23938@davejwatson-mba.local/
*/
int TLS::get_error(int fd)
{
    char buffer[128];
    char cmsgspace[CMSG_SPACE(sizeof(unsigned char))];
    struct msghdr msg {
    };
    msg.msg_control = cmsgspace;
    msg.msg_controllen = sizeof(cmsgspace);

    struct iovec msg_iov;
    msg_iov.iov_base = buffer;
    msg_iov.iov_len = sizeof(buffer);

    msg.msg_iov = &msg_iov;
    msg.msg_iovlen = 1;

    const auto ret = recvmsg(fd, &msg, 0);
    if (-1 == ret) {
        std::cerr << "recvmsg(): " << strerror(errno) << "\n";
        return errno;
    }
    for (struct cmsghdr* cmsg = CMSG_FIRSTHDR(&msg); cmsg != nullptr;
         cmsg = CMSG_NXTHDR(&msg, cmsg)) {
        if (cmsg->cmsg_level == SOL_TLS &&
            cmsg->cmsg_type == TLS_GET_RECORD_TYPE) {
            int record_type = *((unsigned char*)CMSG_DATA(cmsg));
            switch (record_type) {
            case 21: // TLS_RECORD_TYPE_ALERT
                return ENOTCONN;
            case 22: // Handshake.
            case 23: // Application data.
            default:
                std::cerr << "Unknown KTLS record type " << record_type << "\n";
            }
        } else {
            std::cerr << "TLS application data??? Should not be\n";
            // Buffer contains application data.
        }
    }
    return 0;
}

std::unique_ptr<TLSConnection> TLS::enable_ktls(int fd)
{
    return std::make_unique<TLSConnection>(ctx_, fd);
}
