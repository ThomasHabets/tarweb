#include "handshaker.h"
#include "tls.h"
namespace Handshaker {
class TLSImpl : public TLS
{
public:
    TLSImpl(std::unique_ptr<TLSConnection>&& tls) : tls_(std::move(tls)) {}
    Status handshake() override;

    static std::unique_ptr<Base> make(std::unique_ptr<TLSConnection>&& tls)
    {
        return std::unique_ptr<TLS>(new TLSImpl(std::move(tls)));
    }

private:
    std::unique_ptr<TLSConnection> tls_;
};

std::unique_ptr<Base> Base::make(std::unique_ptr<TLSConnection>&& tls)
{
    if (tls) {
        return TLSImpl::make(std::move(tls));
    }
    return std::make_unique<Plain>();
}

Status TLSImpl::handshake()
{
    if (done_) {
        return { true, false, false };
    }
    const int rc = SSL_accept(tls_->ssl());
    if (rc == 1) {
        if (!BIO_get_ktls_send(SSL_get_wbio(tls_->ssl()))) {
            throw std::runtime_error("KTLS not enabled for send");
        }
        if (!BIO_get_ktls_recv(SSL_get_rbio(tls_->ssl()))) {
            throw std::runtime_error("KTLS not enabled for receive");
        }
        done_ = true;
        return { true, false, false };
    }
    const auto rc_err = SSL_get_error(tls_->ssl(), rc);
    if (rc_err == SSL_ERROR_WANT_READ) {
        return { false, true, false };
    }
    if (rc_err == SSL_ERROR_WANT_WRITE) {
        return { false, false, true };
    }
    throw std::runtime_error("SSL_accept() unknown error");
}
} // namespace Handshaker
