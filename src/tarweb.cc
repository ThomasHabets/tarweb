#include "cast.h"
#include "handshaker.h"
#include "tls.h"
#include "writer.h"

#include <fcntl.h>
#include <netinet/in.h>
#include <netinet/tcp.h>
#include <poll.h>
#include <pthread.h>
#include <signal.h>
#include <unistd.h>

#include <sys/epoll.h>
#include <sys/mman.h>
#include <sys/resource.h>
#include <sys/signalfd.h>
#include <sys/socket.h>
#include <sys/socket.h>
#include <sys/stat.h>
#include <sys/time.h>
#include <sys/times.h>
#include <sys/types.h>
#include <sys/uio.h>

#include <algorithm>
#include <cassert>
#include <cstring>
#include <deque>
#include <iostream>
#include <map>
#include <memory_resource>
#include <optional>
#include <regex>
#include <set>
#include <span>
#include <stack>
#include <system_error>
#include <thread>
#include <vector>

namespace {

constexpr bool debug_alloc = false;

std::optional<size_t> parse_size(std::string_view in)
{
    if (in.empty()) {
        return {};
    }

    size_t ret = 0;
    for (const auto ch : in) {
        if (!isdigit(ch)) {
            return {};
        }
        const auto newret = ret * 10 + (ch - '0');
        if (newret < ret) {
            return {};
        }
        ret = newret;
    }
    return ret;
}

template <typename T>
void append(std::pmr::string& buf, const T& i)
{
    if constexpr (std::is_arithmetic_v<T>) {
        // TODO: This may or may not allocate, due to small string
        // optimization. But it's a very brief allocation, so it's fine?
        buf.append(std::to_string(i));
    } else {
        buf.append(i);
    }
}

} // namespace

constexpr int chunk_size = 4096;
constexpr int max_connection_memory_use = chunk_size * 2;
std::string tls_cert = "";
std::string tls_priv = "";
const std::regex rangeRE(" bytes=(\\d+)-(\\d+)");

size_t sendfile_min_size = 4096; // TODO: tune this.

namespace encodings {
constexpr uint8_t uncompressed = 0;
constexpr uint8_t gzip = 1;
constexpr uint8_t zstd = 2;
constexpr uint8_t deflate = 3;
constexpr uint8_t br = 4;

constexpr int count = 5;

const std::string_view name_gzip = "gzip";
const std::string_view name_br = "br";
const std::string_view name_deflate = "deflate";
const std::string_view name_zstd = "zstd";

const std::string header[] = {
    "",
    "Content-Encoding: gzip\r\n",
    "Content-Encoding: zstd\r\n",
    "Content-Encoding: deflate\r\n",
    "Content-Encoding: br\r\n",
};
} // namespace encodings

const std::string_view connection_close = "Connection: close\r\n";
constexpr std::string_view content_length = "Content-Length: ";
constexpr std::string_view crnl_content_range_bytes =
    "\r\nContent-Range: bytes ";

struct Error {
    Error(const std::string& err)
        : response("HTTP/1.1 " + err + "\r\nContent-Length: " +
                   std::to_string(err.size() + 1) + "\r\n\r\n" + err + "\n")
    {
    }
    const std::string response;
};

const Error page400("400 Bad Request");
const Error page404("404 Not found");
const Error page405("405 Method Not Allowed");
const std::string status200("HTTP/1.1 200 OK\r\n");

struct File {
    File(std::span<const char> sp, size_t offset)
        : offset(offset),
          content(sp),
          headers("Content-Length: " + std::to_string(content.size()) +
                  "\r\n\r\n"),
          enc({ this })
    {
    }

    const size_t offset;
    const std::span<const char> content;
    const std::string headers;

    std::array<File*, encodings::count> enc{};

    // No copy or move. Implied by the const member variables though.
    File(const File&) = delete;
    File(File&&) = delete;
    File& operator=(const File&) = delete;
    File& operator=(File&&) = delete;
};

class FD
{
public:
    FD(int fd) : fd_(fd) {}
    ~FD() { close(); }
    void close()
    {
        if (fd_ < 0) {
            return;
        }
        ::close(fd_);
        fd_ = -1;
    }
    operator int() const { return fd_; }
    // No copy or move.
    FD(const FD&) = delete;
    FD(FD&&) = delete;
    FD& operator=(const FD&) = delete;
    FD& operator=(FD&) = delete;

private:
    int fd_;
};

class Site
{
public:
    Site(const char*);
    ~Site();

    // No copy or move.
    Site(const Site&) = delete;
    Site(Site&&) = delete;
    Site& operator=(const Site&) = delete;
    Site& operator=(Site&&) = delete;

    std::optional<const File*> get_file(std::string_view fn) const
    {
        const auto itr = files_.find(std::string(fn));
        if (itr == files_.end()) {
            return {};
        }
        return &itr->second;
    }

    int fd() const { return fd_; }

private:
    FD fd_;

    // TODO: create perfect hashing.
    std::map<std::string, File> files_;
    std::span<char> site_;
};

class PoolAllocator : public std::pmr::memory_resource
{
public:
    PoolAllocator(size_t max) : max_(max) {}
    ~PoolAllocator();

private:
    void* do_allocate(std::size_t bytes, std::size_t alignment) override;
    void
    do_deallocate(void* p, std::size_t bytes, std::size_t alignment) override;
    bool do_is_equal(const memory_resource& other) const noexcept override
    {
        return &other == this;
    }
    size_t current_ = 0;
    size_t total_ = 0;
    size_t count_ = 0;
    const size_t max_;
};

PoolAllocator::~PoolAllocator()
{
    if constexpr (debug_alloc) {
        std::cerr << "Allocated total of " << total_ << " bytes in " << count_
                  << " allocations\n";
    }
    if (current_) {
        std::cerr << "ERROR: Allocator destroyed with non-zero balance of "
                  << current_ << " bytes\n";
    }
}

void* PoolAllocator::do_allocate(std::size_t bytes, std::size_t alignment)
{
    if constexpr (debug_alloc) {
        std::cerr << "Allocating " << bytes << "\n";
    }
    current_ += bytes;
    total_ += bytes;
    count_++;
    if (current_ > max_) {
        throw std::bad_alloc();
    }
    return std::pmr::get_default_resource()->allocate(bytes, alignment);
}

void PoolAllocator::do_deallocate(void* p,
                                  std::size_t bytes,
                                  std::size_t alignment)
{
    if constexpr (debug_alloc) {
        std::cerr << "Deallocating " << bytes << "\n";
    }
    std::pmr::get_default_resource()->deallocate(p, bytes, alignment);
    current_ -= bytes;
}

class Request
{
public:
    bool bad() const { return !bad_request_.empty(); }
    void clear()
    {
        bad_request_ = std::span<char>();
        method_ = "";
        file_ = nullptr;
        encoding_ = encoding_t{};
        keepalive_ = false;
    }

    using encoding_t = std::array<uint8_t, encodings::count>;

    std::span<const char> bad_request_;
    std::string_view method_;
    const File* file_ = nullptr;
    encoding_t encoding_{};
    bool keepalive_ = false;
    std::pair<size_t, size_t> range_{ 1, 0 }; // Default to invalid range.
};

class Connection
{
public:
    Connection(const Site& site,
               int fd,
               std::unique_ptr<TLSConnection>&& tls = {})
        : site_(site),
          fd_(fd),
          pool_(max_connection_memory_use),
          buf_(&pool_),
          oqueue_(&pool_),
          handshaker_(Handshaker::Base::make(std::move(tls)))
    {
    }

    // No copy.
    Connection(const Connection&) = delete;
    Connection& operator=(const Connection&) = delete;

    // No move.
    Connection(Connection&&) = delete;
    Connection& operator=(Connection&&) = delete;

    // Read buffer.
    std::span<char> getbuf();

    // There is `size` more data in the buffer. Parse and handle.
    void incremental_parse(size_t size);

    int fd() const { return fd_; }

    bool handshaking() const { return !handshaker_->done(); }
    Handshaker::Status handshake() { return handshaker_->handshake(); }
    OQueue& oqueue() noexcept { return oqueue_; }

private:
    void reset_buffer(size_t size);

    const Site& site_;
    int fd_;
    PoolAllocator pool_;

    // Buffer for reading from socket.
    std::pmr::vector<char> buf_;

    // Output queue.
    OQueue oqueue_;

    std::span<char> readable_ = std::span(buf_.begin(), buf_.begin());
    std::span<char> writable_ = std::span(buf_.begin(), buf_.end());

    // Request under construction.
    Request request_;

    std::unique_ptr<Handshaker::Base> handshaker_;
};

void Connection::reset_buffer(size_t size)
{
    auto r = &readable_[0] - &buf_[0];
    auto w = &writable_[0] - &buf_[0];
    buf_.resize(size);
    readable_ = std::span(buf_.begin(), r);
    writable_ = std::span(buf_.begin() + w, buf_.end());
}

void nonblock(int fd)
{
    int flags = fcntl(fd, F_GETFL, 0);
    if (flags == -1) {
        throw std::system_error(
            errno, std::generic_category(), "fcntl(F_GETFL)");
    }
    if (-1 == fcntl(fd, F_SETFL, flags | O_NONBLOCK)) {
        throw std::system_error(
            errno, std::generic_category(), "fcntl(F_SETFL)");
    }
}

std::span<char> Connection::getbuf()
{
    if (writable_.empty()) {
        reset_buffer(buf_.size() + chunk_size);
    }
    return writable_;
}

void Connection::incremental_parse(size_t bytes)
{
    readable_ = std::span(readable_.begin(), readable_.end() + bytes);
    writable_ = std::span(writable_.begin() + bytes, writable_.end());
    for (;;) {
        const auto eol = std::find(readable_.begin(), readable_.end(), '\n');
        if (eol == readable_.end()) {
            return;
        }
        auto line = std::span(readable_.begin(), eol);
        readable_ = std::span(eol + 1, readable_.end());
        if (!line.empty() && line.back() == '\r') {
            line = line.subspan(0, line.size() - 1);
        }
        if (false) {
            std::cout << ">> Line <" << std::string(line.begin(), line.end())
                      << ">\n";
        }
        if (line.empty()) {
            if (request_.bad()) {
                std::cout << "Bad request\n";
                oqueue_.add(ViewBuf(request_.bad_request_));
                request_.clear();
                continue;
            }

            oqueue_.add(ViewBuf(std::span(status200)));
            if (request_.keepalive_) {
                oqueue_.add(ViewBuf{ connection_close });
            }
            for (const auto enc : request_.encoding_) {
                if (auto file2 = request_.file_->enc[enc]; file2) {
                    if (enc) {
                        request_.file_ = file2;
                        oqueue_.add(ViewBuf(std::span(encodings::header[enc])));
                    }
                    break;
                }
            }

            const auto full_content_size = request_.file_->content.size();
            auto& range = request_.range_;

            // Set range if not already set.
            if (range.first > range.second) {
                range = { 0, full_content_size - 1 };

            } else if (range.second >= full_content_size) {
                // Cap range.
                // TODO: is this correct, or should it be a 4xx?
                range = { 0, full_content_size - 1 };
            }

            // Set actual content size.
            const auto content_size = range.second - range.first + 1;

            if (full_content_size == content_size) {
                oqueue_.add(ViewBuf(std::span(request_.file_->headers)));
            } else {
                // Maybe there's a cleaner way to avoid non-pool allocs.
                std::pmr::string buf(&pool_);
                buf.reserve(content_length.size() + 10 +
                            crnl_content_range_bytes.size() + 10 + 10 + 10 + 4);
                append(buf, content_length);
                append(buf, content_size);
                append(buf, crnl_content_range_bytes);
                append(buf, range.first);
                buf.append("-");
                append(buf, range.second);
                buf.append("/");
                append(buf, full_content_size);
                append(buf, "\r\n\r\n");
                oqueue_.add(Buf(std::move(buf)));
            }

            if (content_size > sendfile_min_size) {
                oqueue_.add(FileBuf(site_.fd(),
                                    request_.file_->offset + range.first,
                                    content_size));
            } else {
                oqueue_.add(ViewBuf(request_.file_->content.subspan(
                    range.first, content_size)));
            }
            request_.clear();
            continue;
        }

        // If bad request already set then don't bother parsing more.
        if (request_.bad()) {
            continue;
        }

        // First line.
        if (request_.method_.empty()) {
            auto itr1 = std::find(line.begin(), line.end(), ' ');
            if (itr1 == line.end()) {
                std::cerr << "Bad first line: "
                          << std::string(line.begin(), line.end()) << "\n";
                request_.bad_request_ = std::span(page400.response);
                continue;
            }
            request_.method_ = std::string_view(line.begin(), itr1);
            itr1++;

            if (request_.method_ != "GET" && request_.method_ != "HEAD") {
                std::cout << "Setting Bad request 405\n";
                request_.bad_request_ = std::span(page405.response);
                continue;
            }

            auto itr2 = std::find(itr1, line.end(), ' ');
            if (itr2 == line.end()) {
                std::cerr << "No space in line: "
                          << std::string(line.begin(), line.end()) << "\n";
                request_.bad_request_ = std::span(page400.response);
                continue;
            }

            const auto url = std::string_view(itr1, itr2);
            if (url.empty()) {
                std::cerr << "Bad url in line: "
                          << std::string(line.begin(), line.end()) << "\n";
                request_.bad_request_ = std::span(page400.response);
            }

            // Get base file. May be replaced later due to compression.
            request_.file_ = site_.get_file(url.substr(1)).value_or(nullptr);
            if (!request_.file_) {
                std::cout << "Setting Bad request 404\n";
                request_.bad_request_ = std::span(page404.response);
            }
            continue;
        }

        // Parse headers.
        {
            auto itrc = std::find(line.begin(), line.end(), ':');
            if (itrc == line.end()) {
                std::cerr << "Header has no colon: "
                          << std::string(line.begin(), line.end()) << "\n";
                request_.bad_request_ = std::span(page400.response);
                continue;
            }
            std::span<char> name(line.begin(), itrc);
            const std::string_view names(name.begin(), name.end());
            const std::string_view value(itrc + 1, line.end());

            // std::cerr << "Header <" << name << "> = <" << value << ">\n";
            std::ranges::transform(name, name.begin(), [](unsigned char c) {
                return std::tolower(c);
            });
            if (names == "accept-encoding") {
                // TODO: this is a bit unclean, with substring
                // matching. Check around results that it's comma break.
                int n = 0;
                for (auto [name, val] :
                     { std::make_pair(encodings::name_zstd, encodings::zstd),
                       { encodings::name_gzip, encodings::gzip },
                       { encodings::name_deflate, encodings::deflate },
                       { encodings::name_br, encodings::br } }) {
                    const auto m = std::ranges::search(value, name);
                    if (m) {
                        request_.encoding_[n++] = val;
                    }
                }
            }
            if (names == "range") {
                std::pmr::match_results<std::string_view::const_iterator> m(
                    &pool_);
                const bool ok =
                    std::regex_match(value.begin(), value.end(), m, rangeRE);
                if (ok) {
                    const auto a = parse_size({ m[1].first, m[1].second });
                    const auto b = parse_size({ m[2].first, m[2].second });
                    if (a && b) {
                        request_.range_ = { a.value(), b.value() };
                    }
                }
            }
            if (names == "connection") {
                const auto m =
                    std::ranges::search(value, std::string_view("keep-alive"));
                if (m) {
                    // TODO: spaces etc.
                    request_.keepalive_ = true;
                }
            }
        }
    }
}

/*
 * TODO: This class isn't great. It confuses MOD and ADD.
 */
class EPollPoller
{
public:
    static constexpr int epoll_et_ = 0;
    EPollPoller();
    void add_read(Connection* fd);
    void add_write(Connection* fd);
    void remove_read(int fd);
    void remove_write(Connection* ptr);
    void remove(int fd);
    void poll(std::vector<Connection*>&, std::vector<Connection*>&);

private:
    int fd_;
};

EPollPoller::EPollPoller() : fd_(epoll_create1(0))
{
    if (fd_ == -1) {
        throw std::system_error(
            errno, std::generic_category(), "epoll_create()");
    }
}

void EPollPoller::add_read(Connection* ptr)
{
    struct epoll_event ev;
    ev.events = EPOLLIN | epoll_et_;
    ev.data.ptr = reinterpret_cast<void*>(ptr);
    const auto rc = epoll_ctl(fd_, EPOLL_CTL_ADD, ptr->fd(), &ev);
    if (rc == 0) {
        return;
    }
    if (errno == EEXIST) {
        return;
    }
    throw std::system_error(
        errno, std::generic_category(), "epoll_ctl(add read)");
}

void EPollPoller::add_write(Connection* ptr)
{
    struct epoll_event ev;
    ev.events = EPOLLIN | EPOLLOUT | epoll_et_;
    ev.data.ptr = reinterpret_cast<void*>(ptr);
    if (epoll_ctl(fd_, EPOLL_CTL_MOD, ptr->fd(), &ev)) {
        throw std::system_error(
            errno, std::generic_category(), "epoll_ctl(mod write)");
    }
}

void EPollPoller::remove_read(int fd)
{
    struct epoll_event ev;
    ev.events = 0;
    if (epoll_ctl(fd_, EPOLL_CTL_MOD, fd, &ev)) {
        throw std::system_error(
            errno, std::generic_category(), "epoll_ctl(mod nothing)");
    }
}

void EPollPoller::remove(int fd)
{
    struct epoll_event ev;
    if (epoll_ctl(fd_, EPOLL_CTL_DEL, fd, &ev)) {
        throw std::system_error(
            errno, std::generic_category(), "epoll_ctl(DEL)");
    }
}

void EPollPoller::remove_write(Connection* ptr)
{
    struct epoll_event ev;
    ev.events = EPOLLIN | epoll_et_;
    ev.data.ptr = reinterpret_cast<void*>(ptr);
    if (epoll_ctl(fd_, EPOLL_CTL_MOD, ptr->fd(), &ev)) {
        throw std::system_error(
            errno, std::generic_category(), "epoll_ctl(MOD read only)");
    }
}

void EPollPoller::poll(std::vector<Connection*>& retr,
                       std::vector<Connection*>& retw)
{
    retr.clear();
    retw.clear();
    std::array<struct epoll_event, 1000> events;
    const auto rc = epoll_wait(fd_, events.data(), events.size(), -1);
    if (-1 == rc) {
        throw std::system_error(errno, std::generic_category(), "epoll_wait()");
    }
    for (int c = 0; c < rc; c++) {
        if (events[c].events & EPOLLIN) {
            retr.push_back(reinterpret_cast<Connection*>(events[c].data.ptr));
        }
        if (events[c].events & EPOLLOUT) {
            retw.push_back(reinterpret_cast<Connection*>(events[c].data.ptr));
        }
    }
}

// UVector is a pool of preallocated object spaces used to efficiently
// construct objects.
template <typename T>
class UVector
{
public:
    UVector(size_t n) : size_(n), buf_(sizeof(T) * n)
    {
        auto ptr = reinterpret_cast<T*>(buf_.data());
        for (size_t c = n; c; c--) {
            free_.push(ptr + (c - 1));
        }
    }
    template <typename... Args>
    T* alloc(Args&&... args)
    {
        if (free_.empty()) {
            throw std::bad_alloc();
        }
        auto ptr = free_.top();
        new (ptr) T(std::forward<Args>(args)...);
        free_.pop();
        // std::cerr << "Allocating " << (void*)ptr << "\n";
        return ptr;
    }
    void free(T* ptr)
    {
        // std::cerr << "Destroying " << (void*)ptr << "\n";
        ptr->~T();
        free_.push(ptr);
    }
    ~UVector()
    {
        // TODO: just delete all the remaining ones, instead?
        if (free_.size() != size_) {
            std::cerr << "Memory leak: UVector is missing calls to free()\n";
            // std::terminate();
        }
    }

private:
    const size_t size_;
    std::stack<T*> free_;
    std::vector<char> buf_;
};

class Measure
{
public:
    using clock_t = std::chrono::steady_clock;

    Measure() : st_(clock_t::now()) {}
    ~Measure()
    {
        std::cerr << "Measured: " << (clock_t::now() - st_).count() << "\n";
    }

private:
    clock_t::time_point st_;
};

class LatencyTracker
{
public:
    using buckets_t = std::array<uint64_t, 64>;

    void add(const uint64_t ns)
    {
        count_++;
        total_ += ns;
        // std::cerr << "Loop time in ns: " << ns << "\n";
        buckets_[bucket(ns)]++;
    }

    const buckets_t& buckets() const { return buckets_; }
    uint64_t avg() const { return total_ / count_; }
    void print() const
    {
        std::cerr << "============= Stats ==============\n";
        std::cerr << "Avg: " << (total_ / count_) << "\n";
        const auto mx = *std::max_element(buckets_.begin(), buckets_.end());
        for (const auto us : buckets_) {
            std::cerr << std::string((us * 80) / mx, '#') << "\n";
        }
    }

private:
    int bucket(const uint64_t ns)
    {
        const auto us = ns / 1000;
        return safe_int_cast<int>(std::min(us, buckets_.size() - 1));
    }

    uint64_t count_ = 0;
    uint64_t total_ = 0;

    buckets_t buckets_{};
};

void main_loop(int fd, const Site& site)
{
    auto tls = [] {
        if (tls_cert.empty()) {
            return std::unique_ptr<TLS>();
        }
        return std::make_unique<TLS>(tls_cert, tls_priv);
    }();
    UVector<Connection> cons(1000);

    Connection accept_connection(site, fd);
    // PollPoller poller;
    EPollPoller poller;
    LatencyTracker latency;
    poller.add_read(&accept_connection);

    sigset_t mask;
    sigemptyset(&mask);
    sigaddset(&mask, SIGINT);
    int sigfd = signalfd(-1, &mask, SFD_NONBLOCK);
    Connection sigcon(site, sigfd);
    poller.add_read(&sigcon);
    sigprocmask(SIG_BLOCK, &mask, nullptr);

    std::vector<char> buffer(10240000);
    std::pmr::monotonic_buffer_resource pool{
        std::data(buffer), std::size(buffer), std::pmr::null_memory_resource()
    };

    std::set<Connection*> cleared;
    std::vector<Connection*> fdrs;
    std::vector<Connection*> fdws;
    fdrs.reserve(1000);
    fdws.reserve(1000);

    using clock = std::chrono::steady_clock;
    std::chrono::time_point<std::chrono::steady_clock> st;
    bool first = true;
    st = clock::now();

    static_assert(std::chrono::steady_clock::period::num == 1);
    static_assert(std::chrono::steady_clock::period::den == 1000000000);
    for (;;) {
        cleared.clear();
        if (first) [[unlikely]] {
            first = false;
        } else {
            const auto now = clock::now();
            latency.add((now - st).count());
            // latency.print();
        }
        poller.poll(fdrs, fdws);
        st = std::chrono::steady_clock::now();
        for (const auto fdr : fdrs) {
            if (fdr == &sigcon) [[unlikely]] {
                struct signalfd_siginfo info {
                };
                const auto rc = read(sigfd, &info, sizeof(info));
                if (rc <= 0) {
                    throw std::system_error(
                        errno, std::generic_category(), "read(sigfd)");
                }
                std::cerr << "Exiting because SIG"
                          << sigabbrev_np(info.ssi_signo) << " \n";
                return;
            }
            if (fdr == &accept_connection) [[unlikely]] {
                for (;;) {
                    struct sockaddr_in6 sa;
                    socklen_t len = sizeof(sa);

                    int cli = accept4(fd, (sockaddr*)&sa, &len, SOCK_NONBLOCK);
                    if (-1 == cli) [[unlikely]] {
                        if (errno == EAGAIN) [[likely]] {
                            // No more pending connections.
                            break;
                        }
                        throw std::system_error(
                            errno, std::generic_category(), "accept()");
                    }
                    {
                        int on = 1;
                        if (setsockopt(
                                cli, SOL_TCP, TCP_NODELAY, &on, sizeof(on))) {
                            throw std::system_error(errno,
                                                    std::generic_category(),
                                                    "setsockopt(TCP_NODELAY)");
                        }
                    }
                    // TODO: maybe data is usually available
                    // immediately, so perform read here too?
                    //
                    // We can't add it to fdrs here, though, since
                    // we're currently iterating over it.
                    std::unique_ptr<TLSConnection> tlscon;
                    if (tls) {
                        tlscon = tls->enable_ktls(cli);
                    }
                    auto newcon = cons.alloc(site, cli, std::move(tlscon));
                    const auto st = newcon->handshake();
                    if (st.want_read || st.done) {
                        poller.add_read(newcon);
                    }
                    if (st.want_write) {
                        poller.add_write(newcon);
                    }
                    break;
                }

                // Don't actually try to read from the listening socket.
                continue;
            }

            /*
             * Handshaker waiting to read.
             */
            auto& con = *fdr;
            if (con.handshaking()) {
                const auto hs = con.handshake();
                if (hs.done) {
                    poller.add_read(&con);
                    poller.remove_write(&con);
                } else {
                    if (hs.want_read) {
                        poller.add_read(&con);
                    }
                    if (hs.want_write) {
                        // TODO: remove read.
                        // First need to clean up the EPoller
                        poller.add_write(&con);
                    }
                }
                continue;
            }

            /*
             * Connection waiting to read normal data.
             */
            for (bool finished = false; !finished;) {
                auto buf = con.getbuf();
                const auto rc = read(con.fd(), buf.data(), buf.size());
                bool should_close = false;
                if (rc == -1) [[unlikely]] {
                    if (errno == EAGAIN) {
                        // No more to read for now.
                        break;
                    }
                    if (tls) {
                        const int err = tls->get_error(con.fd());
                        if (err != ENOTCONN) {
                            std::cerr << "TLS error: " << strerror(err) << "\n";
                        }
                    } else {
                        std::cerr << "Reading from socket: " << strerror(errno)
                                  << "\n";
                    }
                    should_close = true;
                }
                if (rc == 0) {
                    should_close = true;
                }
                if (should_close) {
                    poller.remove(con.fd());
                    close(con.fd());
                    cleared.insert(&con);
                    cons.free(&con);
                    break;
                }
                if (rc != safe_int_cast<ssize_t>(buf.size())) {
                    finished = true;
                }
                {
                    con.incremental_parse(rc);
                }
                if (!con.oqueue().empty()) {
                    {
                        // Measure m;
                        con.oqueue().write(con.fd());
                    }
                    if (!con.oqueue().empty()) {
                        poller.add_write(&con);
                    }
                }
            }
        }

        for (const auto fdw : fdws) {
            if (cleared.count(fdw)) {
                // Connection was destroyed while reading.
                continue;
            }
            auto& con = *fdw;

            const auto hs = con.handshake();
            if (hs.done || hs.want_read) {
                poller.add_read(&con);
            }
            if (!hs.want_write) {
                poller.remove_write(&con);
            }

            if (hs.done) {
                if (!con.oqueue().empty()) {
                    con.oqueue().write(con.fd());
                }
                if (con.oqueue().empty()) {
                    poller.remove_write(&con);
                }
            }
        }
    }
}

struct posix_header {   /* byte offset */
    char name[100];     /*   0 */
    char mode[8];       /* 100 */
    char uid[8];        /* 108 */
    char gid[8];        /* 116 */
    char size[12];      /* 124 */
    char mtime[12];     /* 136 */
    char chksum[8];     /* 148 */
    char typeflag;      /* 156 */
    char linkname[100]; /* 157 */
    char magic[6];      /* 257 */
    char version[2];    /* 263 */
    char uname[32];     /* 265 */
    char gname[32];     /* 297 */
    char devmajor[8];   /* 329 */
    char devminor[8];   /* 337 */
    char prefix[155];   /* 345 */
                        /* 500 */
};


Site::~Site()
{
    if (-1 == munmap(site_.data(), site_.size())) {
        std::cerr << "munmap(): " << strerror(errno) << "\n";
        std::terminate();
    }
}

Site::Site(const char* sitefn) : fd_(open(sitefn, O_RDONLY))
{
    if (fd_ == -1) {
        throw std::system_error(errno, std::generic_category(), "open()");
    }
    struct stat st;
    if (-1 == fstat(fd_, &st)) {
        throw std::system_error(errno, std::generic_category(), "fstat()");
    }

    auto ptr = (char*)mmap(
        nullptr, st.st_size, PROT_READ, MAP_PRIVATE, fd_, 0); // MAP_HUGE*?
    if (ptr == nullptr) {
        throw std::system_error(errno, std::generic_category(), "mmap()");
    }
    site_ = std::span(ptr, ptr + st.st_size);

    std::cout << sizeof(posix_header) << "\n";
    for (size_t ofs = 0;
         ofs + sizeof(posix_header) < safe_int_cast<size_t>(st.st_size);) {
        posix_header* head = (posix_header*)(site_.data() + ofs);
        if (!memcmp(head->magic, "\x00\x00\x00\x00\x00\x00", 6)) {
            break;
        }
        assert(!memcmp(head->magic, "ustar ", 6));
        char* end;
        const auto size = strtoul(head->size, &end, 8);
        // std::cout << "<" << size << ">\n";

        ofs += sizeof(posix_header);
        // Round up.
        if (ofs & 0x1ff) {
            ofs = (ofs | 0x1ff) + 1;
        }

        std::span<char> sp = site_.subspan(ofs, size);
        std::cout << "<" << head->name << "> @ " << ofs << " size " << sp.size()
                  << "\n";
        files_.emplace(std::piecewise_construct,
                       std::forward_as_tuple(head->name),
                       std::forward_as_tuple(sp, ofs));

        ofs += size;
        // Round up.
        if (ofs & 0x1ff) {
            ofs = (ofs | 0x1ff) + 1;
        }
    }

    for (auto& f : files_) {
        auto comp = files_.find(f.first + ".gz");
        if (comp != files_.end()) {
            f.second.enc[encodings::gzip] = &comp->second;
        }

        comp = files_.find(f.first + ".zstd");
        if (comp != files_.end()) {
            f.second.enc[encodings::zstd] = &comp->second;
        }
    }
    if (auto f = files_.find("index.html"); f != files_.end()) {
        auto [file, ok] = files_.emplace(
            std::piecewise_construct,
            std::forward_as_tuple(""),
            std::forward_as_tuple(f->second.content, f->second.offset));
        file->second.enc = f->second.enc;
    }
}

[[noreturn]] void usage(const char* av0, int err)
{
    std::ostream* o = &std::cout;
    if (err) {
        o = &std::cerr;
    }
    *o << "Usage: " << av0 << " [ -S <sendfile threshold> ]\n";
    exit(err);
}

double tvsub(const struct timeval& a, const struct timeval& b)
{
    double ret = static_cast<double>(a.tv_sec) - static_cast<double>(b.tv_sec);
    double d = static_cast<double>(a.tv_usec) - static_cast<double>(b.tv_usec);
    if (a.tv_usec > b.tv_usec) {
        ret -= 1;
        d += 1000000.0;
    }
    return ret + d / 1000000.0;
}

int mainwrap(int argc, char** argv)
{
    uint16_t port = 8787;
    const char* sitefn = "site.tar";
    {
        int opt;
        while ((opt = getopt(argc, argv, "f:hp:S:C:")) != -1) {
            switch (opt) {
            case 'f':
                sitefn = optarg;
                break;
            case 'h':
                usage(argv[0], EXIT_SUCCESS);
            case 'p':
                // TODO: must_parse()
                port = safe_int_cast<uint16_t>(strtoul(optarg, nullptr, 0));
                break;
            case 'S':
                // TODO: must_parse()
                sendfile_min_size = strtoul(optarg, nullptr, 0);
                break;
            case 'C':
                tls_priv = tls_cert = optarg;
                break;
            default:
                usage(argv[0], EXIT_FAILURE);
            }
        }
    }
    if (optind != argc) {
        std::cerr << "Extra args on command line\n";
        exit(1);
    }
    Site site(sitefn);

    int sock = socket(AF_INET6, SOCK_STREAM, 0);
    if (-1 == sock) {
        throw std::system_error(errno, std::generic_category(), "socket()");
    }
    {
        const int on = 1;
        if (setsockopt(sock, SOL_SOCKET, SO_REUSEADDR, &on, sizeof(on)) < 0) {
            throw std::system_error(
                errno, std::generic_category(), "setsockopt(SO_REUSEADDR)");
        }
    }
    struct sockaddr_in6 sa {
    };
    sa.sin6_family = AF_INET6;
    sa.sin6_port = htons(port);
    if (-1 == bind(sock, (struct sockaddr*)&sa, sizeof(sa))) {
        throw std::system_error(errno, std::generic_category(), "bind()");
    }
    if (-1 == listen(sock, 5)) {
        throw std::system_error(errno, std::generic_category(), "listen()");
    }
    nonblock(sock);
    std::vector<std::jthread> threads;
    if (false) {
        const auto cpus = std::thread::hardware_concurrency();
        for (unsigned int i = 0; i < cpus; i++) {
            std::jthread th([sock, &site, i] {
                cpu_set_t cpuset;
                CPU_ZERO(&cpuset);
                CPU_SET(i, &cpuset);
                if (-1 ==
                    sched_setaffinity(safe_int_cast<pid_t>(pthread_self()),
                                      sizeof(cpuset),
                                      &cpuset)) {
                    throw std::system_error(
                        errno, std::generic_category(), "sched_cpuset()");
                }
                main_loop(sock, site);
            });
            threads.push_back(std::move(th));
        }
        std::cerr << "All threads running\n";
    } else {
        std::cerr << "Running single threaded\n";
        struct rusage stu;
        if (getrusage(RUSAGE_SELF, &stu)) {
            throw std::system_error(errno, std::generic_category(), "rusage()");
        }
        main_loop(sock, site);
        struct rusage nowu;
        if (getrusage(RUSAGE_SELF, &nowu)) {
            throw std::system_error(errno, std::generic_category(), "rusage()");
        }
        std::cerr << "User time:    " << tvsub(nowu.ru_utime, stu.ru_utime)
                  << "\n";
        std::cerr << "System time:  " << tvsub(nowu.ru_stime, stu.ru_stime)
                  << "\n";
    }
    return 0;
}
