#include <openssl/ssl.h>
#include <memory>

class TLSConnection
{
public:
    TLSConnection(SSL_CTX*);
    ~TLSConnection();
    SSL* ssl() { return ssl_; }

private:
    SSL* ssl_;
};


class TLS
{
public:
    TLS(const std::string& cert, const std::string& priv);
    ~TLS();

    std::unique_ptr<TLSConnection> enable_ktls(int fd, bool server);
    static int get_error(int fd);

private:
    SSL_CTX* ctx_;
};