#include <fcntl.h>
#include <memory_resource>
#include <netinet/in.h>
#include <poll.h>
#include <pthread.h>
#include <sys/epoll.h>
#include <sys/mman.h>
#include <sys/socket.h>
#include <sys/stat.h>
#include <sys/uio.h>
#include <system_error>
#include <unistd.h>
#include <algorithm>
#include <cassert>
#include <cstring>
#include <deque>
#include <iostream>
#include <map>
#include <optional>
#include <set>
#include <span>
#include <stack>
#include <thread>
#include <vector>

constexpr int chunk_size = 4096;
constexpr int max_connection_memory_use = chunk_size * 2;

namespace encodings {
constexpr int uncompressed = 0;
constexpr int gzip = 1;
constexpr int zstd = 2;
constexpr int deflate = 3;
constexpr int br = 4;

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
    File(std::span<const char> sp)
        : content(sp),
          headers("Content-Length: " + std::to_string(content.size()) +
                  "\r\n\r\n"),
          enc({ this })
    {
    }

    const std::span<const char> content;
    const std::string headers;

    std::array<File*, encodings::count> enc{};

    // No copy or move. Implied by the const member variables though.
    File(const File&) = delete;
    File(File&&) = delete;
    File& operator=(const File&) = delete;
    File& operator=(File&&) = delete;
};

class Site
{
public:
    Site();
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

private:
    // TODO: create perfect hashing.
    std::map<std::string, File> files_;
    std::span<char> site_;
};

class OutBuf
{
public:
    // no regular strings.
    OutBuf(const std::string&) = delete;

    // No copy.
    OutBuf(const OutBuf&) = delete;
    OutBuf& operator=(const OutBuf&) = delete;

    // Construct from PMR string or span.
    explicit OutBuf(std::pmr::string&& str)
        : str_(std::move(str)), sp_(str_.begin(), str_.end())
    {
    }
    explicit OutBuf(std::span<const char> sp) : sp_(sp) {}

    std::span<const char> getbuf() const { return sp_; }

    size_t advance(size_t size)
    {
        const auto n = std::min(size, sp_.size());
        sp_ = sp_.subspan(n);
        return n;
    }

    bool empty() const { return sp_.empty(); }

private:
    const std::pmr::string str_;
    std::span<const char> sp_;
};

class Connection
{
public:
    Connection(const Site& site, int fd)
        : site_(site),
          fd_(fd),
          pool_(std::data(pool_buffer_),
                std::size(pool_buffer_),
                std::pmr::null_memory_resource()),
          buf_(&pool_)
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

    // `size` bytes from obuf have been written to the socket.
    void write_advance(size_t size)
    {
        while (size > 0) {
            auto& obuf = obuf_.front();
            size -= obuf.advance(size);
            if (obuf.empty()) {
                obuf_.pop_front();
            }
        }
    }

    using obufs_t = std::pmr::deque<OutBuf>;
    const obufs_t& get_obufs() const { return obuf_; }
    int fd() const { return fd_; }

private:
    void reset_buffer(int size);

    const Site& site_;
    int fd_;
    std::array<char, max_connection_memory_use> pool_buffer_;
    std::pmr::monotonic_buffer_resource pool_;

    // Buffer for reading from socket.
    std::pmr::vector<char> buf_;
    std::span<char> readable_ = std::span(buf_.begin(), buf_.begin());
    std::span<char> writable_ = std::span(buf_.begin(), buf_.end());

    // Parsed request information.
    void clear_request()
    {
        bad_request_ = std::span<char>();
        method_ = "";
        file_ = nullptr;
        encoding_ = encoding_t{};
        protocol_ = std::string_view();
        keepalive_ = false;
    }
    std::span<const char> bad_request_;
    std::string_view method_;
    const File* file_ = nullptr;
    using encoding_t = std::array<uint8_t, encodings::count>;
    encoding_t encoding_{};
    std::string_view protocol_;
    bool keepalive_ = false;

    // When request is finished this is the output buffers.
    //
    // Note: since the deque nodes are from the memory pool they're not
    // actually freed as they are completed. Maybe just use vector?
    obufs_t obuf_ = std::pmr::deque<OutBuf>(&pool_);
};

void Connection::reset_buffer(int size)
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
        // std::cout << ">> Line <" << std::string(line.begin(), line.end()) <<
        // ">\n";
        if (line.empty()) {
            if (bad_request_.size()) {
                obuf_.emplace_back(bad_request_);
                continue;
            }

            obuf_.emplace_back(std::span(status200));
            if (keepalive_) {
                obuf_.emplace_back(std::span(connection_close));
            }
            for (const auto enc : encoding_) {
                if (auto file2 = file_->enc[enc]; file2) {
                    if (enc) {
                        file_ = file2;
                        obuf_.emplace_back(std::span(encodings::header[enc]));
                    }
                    break;
                }
            }
            obuf_.emplace_back(std::span(file_->headers));
            obuf_.emplace_back(file_->content);
            clear_request();
            continue;
        }

        // If bad request already set then don't bother parsing more.
        if (!bad_request_.empty()) {
            continue;
        }

        // First line.
        if (method_.empty()) {
            auto itr1 = std::find(line.begin(), line.end(), ' ');
            if (itr1 == line.end()) {
                std::cerr << "Bad first line: "
                          << std::string(line.begin(), line.end()) << "\n";
                bad_request_ = std::span(page400.response);
                continue;
            }
            method_ = std::string_view(line.begin(), itr1);
            itr1++;

            if (method_ != "GET" && method_ != "HEAD") {
                bad_request_ = std::span(page405.response);
                continue;
            }

            auto itr2 = std::find(itr1, line.end(), ' ');
            if (itr2 == line.end()) {
                std::cerr << "No space in line: "
                          << std::string(line.begin(), line.end()) << "\n";
                bad_request_ = std::span(page400.response);
                continue;
            }

            const auto url = std::string_view(itr1, itr2);
            if (url.empty()) {
                std::cerr << "Bad url in line: "
                          << std::string(line.begin(), line.end()) << "\n";
                bad_request_ = std::span(page400.response);
            }

            // Get base file. May be replaced later due to compression.
            file_ = site_.get_file(url.substr(1)).value_or(nullptr);
            if (!file_) {
                bad_request_ = std::span(page404.response);
            }
            continue;
        }

        // Parse headers.
        {
            auto itrc = std::find(line.begin(), line.end(), ':');
            if (itrc == line.end()) {
                std::cerr << "Header has no colon: "
                          << std::string(line.begin(), line.end()) << "\n";
                bad_request_ = std::span(page400.response);
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
                        encoding_[n++] = val;
                    }
                }
            }
            if (names == "connection") {
                const auto m =
                    std::ranges::search(value, std::string_view("keep-alive"));
                if (m) {
                    // TODO: spaces etc.
                    keepalive_ = true;
                }
            }
        }
    }
}

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
    if (epoll_ctl(fd_, EPOLL_CTL_ADD, ptr->fd(), &ev)) {
        throw std::system_error(
            errno, std::generic_category(), "epoll_ctl(add read)");
    }
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

template <typename T>
class UVector
{
public:
    UVector(size_t n) : size_(n), buf_(sizeof(T) * n)
    {
        auto ptr = reinterpret_cast<T*>(buf_.data());
        for (int c = n; c; c--) {
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
            std::terminate();
        }
    }

private:
    const size_t size_;
    std::stack<T*> free_;
    std::vector<char> buf_;
};

void do_write(std::pmr::monotonic_buffer_resource& pool, Connection& con)
{
    auto& bufs = con.get_obufs();

    std::pmr::vector<struct iovec> wv(bufs.size(), &pool);
    for (int i = 0; i < bufs.size(); i++) {
        auto buf = bufs[i].getbuf();
        wv[i].iov_base = const_cast<char*>(buf.data());
        wv[i].iov_len = buf.size();
    }
    // TODO: because of the mmap, writes may actually block.
    const auto rc = writev(con.fd(), &wv[0], wv.size());
    if (rc == -1) {
        throw std::system_error(errno, std::generic_category(), "writev()");
    }
    con.write_advance(rc);
}

void main_loop(int fd, const Site& site)
{
    UVector<Connection> cons(1000);

    Connection accept_connection(site, fd);
    // PollPoller poller;
    EPollPoller poller;
    poller.add_read(&accept_connection);

    std::vector<char> buffer(10240000);
    std::pmr::monotonic_buffer_resource pool{
        std::data(buffer), std::size(buffer), std::pmr::null_memory_resource()
    };

    std::set<Connection*> cleared;
    std::vector<Connection*> fdrs;
    std::vector<Connection*> fdws;
    for (;;) {
        cleared.clear();
        poller.poll(fdrs, fdws);
        for (const auto fdr : fdrs) {
            if (fdr == &accept_connection) {
                for (;;) {
                    struct sockaddr_in6 sa;
                    socklen_t len = sizeof(sa);
                    int cli = accept(fd, (sockaddr*)&sa, &len);
                    if (-1 == cli) {
                        if (errno == EAGAIN) {
                            break;
                        }
                        throw std::system_error(
                            errno, std::generic_category(), "accept()");
                    }
                    nonblock(cli);
                    // TODO: maybe data is usually available
                    // immediately, so add it to the fdrs set too?
                    poller.add_read(cons.alloc(site, cli));
                    break;
                }
                continue;
            }

            auto& con = *fdr;
            for (bool finished = false; !finished;) {
                auto buf = con.getbuf();
                const auto rc = read(con.fd(), buf.data(), buf.size());
                if (rc == -1) {
                    if (errno == EAGAIN) {
                        sleep(1);
                        break;
                    }
                    std::cerr << strerror(errno) << "\n";
                    poller.remove(con.fd());
                    close(con.fd());
                    cleared.insert(&con);
                    cons.free(&con);
                    break;
                }
                if (rc == 0) {
                    poller.remove(con.fd());
                    close(con.fd());
                    cleared.insert(&con);
                    cons.free(&con);
                    break;
                }
                if (rc != buf.size()) {
                    finished = true;
                }
                con.incremental_parse(rc);
                if (!con.get_obufs().empty()) {
                    do_write(pool, con);
                    if (!con.get_obufs().empty()) {
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
            if (!con.get_obufs().empty()) {
                do_write(pool, con);
            }
            if (con.get_obufs().empty()) {
                poller.remove_write(&con);
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

Site::Site()
{
    const int fd = open("site.tar", O_RDONLY);
    if (fd == -1) {
        throw std::system_error(errno, std::generic_category(), "open()");
    }
    struct stat st;
    if (-1 == fstat(fd, &st)) {
        close(fd);
        throw std::system_error(errno, std::generic_category(), "fstat()");
    }

    auto ptr = (char*)mmap(
        nullptr, st.st_size, PROT_READ, MAP_PRIVATE, fd, 0); // MAP_HUGE*?
    close(fd);
    if (ptr == nullptr) {
        throw std::system_error(errno, std::generic_category(), "mmap()");
    }
    site_ = std::span(ptr, ptr + st.st_size);

    std::cout << sizeof(posix_header) << "\n";
    for (auto ofs = 0; ofs + sizeof(posix_header) < st.st_size;) {
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
                       std::forward_as_tuple(sp));

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
        auto [file, ok] =
            files_.emplace(std::piecewise_construct,
                           std::forward_as_tuple(""),
                           std::forward_as_tuple(f->second.content));
        file->second.enc = f->second.enc;
    }
}

int main()
{
    Site site;

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
    sa.sin6_port = htons(8787);
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
        for (int i = 0; i < cpus; i++) {
            std::jthread th([sock, &site, i] {
                cpu_set_t cpuset;
                CPU_ZERO(&cpuset);
                CPU_SET(i, &cpuset);
                if (-1 ==
                    sched_setaffinity(gettid(), sizeof(cpuset), &cpuset)) {
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
        main_loop(sock, site);
    }
}
