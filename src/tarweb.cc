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
#include <cassert>
#include <cstring>
#include <deque>
#include <iostream>
#include <map>
#include <map>
#include <optional>
#include <set>
#include <span>
#include <thread>
#include <vector>

constexpr int chunk_size = 4096;

const std::string page404content = "File not found\n";
const std::string page404 = "HTTP/1.1 404 Not Found\r\nContent-Length: " +
                            std::to_string(page404content.size()) + "\r\n\r\n" +
                            page404content;

struct File {
    File(std::span<const char> sp)
        : content(sp),
          headers("Content-Length: " + std::to_string(content.size()) +
                  "\r\n\r\n")
    {
    }

    const std::span<const char> content;
    const std::string headers;

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
          pool_buffer_(4096),
          pool_(std::data(pool_buffer_), std::size(pool_buffer_)),
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
    std::vector<char> pool_buffer_;
    std::pmr::monotonic_buffer_resource pool_;

    // Buffer for reading from socket.
    std::pmr::vector<char> buf_;
    std::span<char> readable_ = std::span(buf_.begin(), buf_.begin());
    std::span<char> writable_ = std::span(buf_.begin(), buf_.end());

    // Parsed headers. TODO: also add the Method line.
    std::pmr::vector<std::map<std::pmr::string, std::pmr::string>> headers_;

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
    auto status200 = std::pmr::string("HTTP/1.1 200 OK\r\n", &pool_);
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
            // const auto fn = "rand.bin";
            const auto fn = "index.html";
            const auto file = site_.get_file(fn).value_or(nullptr);
            if (!file) {
                obuf_.emplace_back(std::span(page404));
                continue;
            }
            obuf_.emplace_back(status200);
            obuf_.emplace_back(std::span(file->headers));
            obuf_.emplace_back(file->content);
	    continue;
        }

	// TODO: Parse method and header lines.
    }
}

class Poller
{
public:
    virtual void add_read(int) = 0;
    virtual void add_write(int) = 0;
    virtual void remove_read(int) = 0;
    virtual void remove_write(int) = 0;
    virtual void remove(int) = 0;
    virtual std::tuple<std::vector<int>, std::vector<int>> poll() = 0;
};

class PollPoller : public Poller
{
public:
    void add_read(int fd) override { fdrs_.insert(fd); }
    void add_write(int fd) override { fdws_.insert(fd); }
    void remove_read(int fd) override;
    void remove_write(int fd) override;
    void remove(int fd)
    {
        remove_read(fd);
        remove_write(fd);
    }
    std::tuple<std::vector<int>, std::vector<int>> poll() override;

private:
    std::set<int> fdrs_;
    std::set<int> fdws_;
};

void PollPoller::remove_read(int fd) { fdrs_.erase(fd); }
void PollPoller::remove_write(int fd) { fdws_.erase(fd); }

class EPollPoller : public Poller
{
public:
    static constexpr int epoll_et_ = 0;
    EPollPoller();
    void add_read(int fd) override;
    void add_write(int fd) override;
    void remove_read(int fd) override;
    void remove_write(int fd) override;
    void remove(int fd);
    std::tuple<std::vector<int>, std::vector<int>> poll() override;

private:
    int fd_;
    std::set<int> fdrs_;
    std::set<int> fdws_;
};

EPollPoller::EPollPoller() : fd_(epoll_create1(0))
{
    if (fd_ == -1) {
        throw std::system_error(
            errno, std::generic_category(), "epoll_create()");
    }
}

void EPollPoller::add_read(int fd)
{
    struct epoll_event ev;
    ev.events = EPOLLIN | epoll_et_;
    ev.data.fd = fd;
    if (epoll_ctl(fd_, EPOLL_CTL_ADD, fd, &ev)) {
        throw std::system_error(
            errno, std::generic_category(), "epoll_ctl(add read)");
    }
}

void EPollPoller::add_write(int fd)
{
    struct epoll_event ev;
    ev.events = EPOLLIN | EPOLLOUT | epoll_et_;
    ev.data.fd = fd;
    if (epoll_ctl(fd_, EPOLL_CTL_MOD, fd, &ev)) {
        throw std::system_error(
            errno, std::generic_category(), "epoll_ctl(mod write)");
    }
}

void EPollPoller::remove_read(int fd)
{
    struct epoll_event ev;
    ev.events = 0;
    ev.data.fd = fd;
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

void EPollPoller::remove_write(int fd)
{
    struct epoll_event ev;
    ev.events = EPOLLIN | epoll_et_;
    ev.data.fd = fd;
    if (epoll_ctl(fd_, EPOLL_CTL_MOD, fd, &ev)) {
        throw std::system_error(
            errno, std::generic_category(), "epoll_ctl(MOD read only)");
    }
}

std::tuple<std::vector<int>, std::vector<int>> EPollPoller::poll()
{
    std::array<struct epoll_event, 10> events;
    const auto rc = epoll_wait(fd_, events.data(), events.size(), -1);
    if (-1 == rc) {
        throw std::system_error(errno, std::generic_category(), "epoll_wait()");
    }
    std::vector<int> retr;
    std::vector<int> retw;
    for (int c = 0; c < rc; c++) {
        if (events[c].events & EPOLLIN) {
            retr.push_back(events[c].data.fd);
        }
        if (events[c].events & EPOLLOUT) {
            retw.push_back(events[c].data.fd);
        }
    }
    return { retr, retw };
}

std::tuple<std::vector<int>, std::vector<int>> PollPoller::poll()
{
    const auto rlen = fdrs_.size();
    const auto wlen = fdws_.size();
    const auto len = rlen + wlen;
    std::vector<struct pollfd> pr;
    for (const auto fd : fdrs_) {
        pr.push_back(pollfd{
            fd : fd,
            events : POLLIN,
        });
    }
    for (const auto fd : fdws_) {
        pr.push_back(pollfd{
            fd : fd,
            events : POLLOUT,
        });
    }
    const auto rc = ::poll(pr.data(), len, -1);
    if (rc == -1) {
        throw std::system_error(errno, std::generic_category(), "poll()");
    }
    std::vector<int> retr;
    retr.reserve(rc);
    std::vector<int> retw;
    retw.reserve(rc);
    for (const auto p : pr) {
        if (p.revents & POLLIN) {
            retr.push_back(p.fd);
        }
        if (p.revents & POLLOUT) {
            retw.push_back(p.fd);
        }
    }
    return { retr, retw };
}

void main_loop(int fd, const Site& site)
{
    std::map<int, Connection> cons;

    // PollPoller poller;
    EPollPoller poller;
    poller.add_read(fd);

    std::vector<char> buffer(102400);
    std::pmr::monotonic_buffer_resource pool{ std::data(buffer),
                                              std::size(buffer) };

    for (;;) {
        const auto [fdrs, fdws] = poller.poll();
        for (const auto fdr : fdrs) {
            if (fdr == fd) {
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

                    cons.emplace(std::piecewise_construct,
                                 std::forward_as_tuple(cli),
                                 std::forward_as_tuple(site, cli));

                    poller.add_read(cli);
                }
                continue;
            }

            auto& con = cons.at(fdr);
            for (bool finished = false; !finished;) {
                auto buf = con.getbuf();
                const auto rc = read(fdr, buf.data(), buf.size());
                if (rc == -1) {
                    if (errno == EAGAIN) {
                        break;
                    }
                    poller.remove(fdr);
                    cons.erase(fdr);
                    close(fdr);
                    std::cerr << strerror(errno) << "\n";
                    break;
                }
                if (rc == 0) {
                    poller.remove(fdr);
                    cons.erase(fdr);
                    close(fdr);
                    break;
                }
                if (rc != buf.size()) {
                    finished = true;
                }
                con.incremental_parse(rc);
                if (!con.get_obufs().empty()) {
                    poller.add_write(con.fd());
                }
            }
        }
        for (const auto fdw : fdws) {
            auto conf = cons.find(fdw);
            if (conf == cons.end()) {
                // Connection was destroyed while reading.
                continue;
            }
            auto& con = conf->second;
            auto& bufs = con.get_obufs();

            std::pmr::vector<struct iovec> wv(bufs.size(), &pool);
            for (int i = 0; i < bufs.size(); i++) {
                auto buf = bufs[i].getbuf();
                wv[i].iov_base = const_cast<char*>(buf.data());
                wv[i].iov_len = buf.size();
            }
            // TODO: because of the mmap, writes may actually block.
            const auto rc = writev(fdw, &wv[0], wv.size());
            if (rc == -1) {
                throw std::system_error(
                    errno, std::generic_category(), "writev()");
            }
            con.write_advance(rc);
            if (con.get_obufs().empty()) {
                poller.remove_write(con.fd());
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
