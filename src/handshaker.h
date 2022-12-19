#include <memory>
#include <utility>

class TLSConnection;

namespace Handshaker {

struct Status {
    bool done;
    bool want_read;
    bool want_write;
};

class Base
{
public:
    virtual ~Base(){};

    bool done() const { return done_; }

    static std::unique_ptr<Base> make(std::unique_ptr<TLSConnection>&&);

    virtual Status handshake() = 0;

protected:
    bool done_ = false;
};

class TLS : public Base
{
public:
    TLS() = default;

private:
    friend Base;
};

class Plain : public Base
{
public:
    Plain() { done_ = true; }
    Status handshake() override { return { true, false, false }; };
};

} // namespace Handshaker
