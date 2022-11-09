#include <string_view>
#include <sys/uio.h>
#include <iostream>
#include <memory>
#include <optional>
#include <span>
#include <string>
#include <vector>

#include <fcntl.h>
#include <sys/sendfile.h>
#include <sys/stat.h>
#include <sys/types.h>
#include <unistd.h>

class BufBase
{
public:
    BufBase() {}
    ~BufBase() {}

    // No copy, only move.
    BufBase(const BufBase&) = delete;
    BufBase& operator=(const BufBase&) = delete;
    BufBase(BufBase&&) = default;
    BufBase& operator=(BufBase&&) = default;

    virtual size_t advance(size_t bytes) = 0;
    virtual size_t write(int fd) = 0;
    virtual bool empty() const = 0;

    // Return empty if N/A.
    virtual std::optional<std::span<const char>> buf() { return {}; };
};

class FileBuf : public BufBase
{
public:
    FileBuf(int fd, size_t ofs, size_t size) : fd_(fd), ofs_(ofs), size_(size)
    {
    }

    size_t advance(size_t bytes) override
    {
        ofs_ += bytes;
        size_ -= bytes;
        return size_;
    }
    size_t write(int fd) override
    {
        off_t ofs = ofs_;
        const auto rc = sendfile(fd, fd_, &ofs, size_);
        if (rc < 0) {
            throw std::system_error(
                errno, std::generic_category(), "sendfile()");
        }
        return rc;
    }
    bool empty() const override { return size_ == 0; }

private:
    int fd_;
    off_t ofs_;
    size_t size_;
};

class ViewBuf : public BufBase
{
public:
    ViewBuf(std::span<const char> sv) : sv_(sv) {}
    ViewBuf(std::string_view sv) : sv_(sv) {}
    size_t advance(size_t bytes) override
    {
        const auto take = std::min(sv_.size(), bytes);
        sv_ = sv_.subspan(take);
        return bytes - take;
    }
    size_t write(int fd) override
    {
        const auto rc = ::write(fd, sv_.data(), sv_.size());
        if (rc < 0) {
            throw std::runtime_error("writev()");
        }
        return rc;
    }
    std::optional<std::span<const char>> buf() override { return sv_; }

    bool empty() const override { return sv_.empty(); }

protected:
    ViewBuf() {}
    std::span<const char> sv_;
};

class Buf : public ViewBuf
{
public:
    Buf(std::string buf) : buf_(std::move(buf)) { sv_ = buf_; }
    Buf(const Buf&) = delete;
    Buf& operator=(const Buf&) = delete;

    Buf(Buf&& rhs) : buf_(std::move(rhs.buf_)) { sv_ = buf_; }
    Buf& operator=(Buf&& rhs)
    {
        buf_ = std::move(rhs.buf_);
        sv_ = buf_;
        return *this;
    }

private:
    std::string buf_;
};


class OQueue
{
public:
    template <typename T>
    void add(T&& buf)
    {
        bufs_.push_back(std::make_unique<T>(std::move(buf)));
    }

    bool empty() const { return bufs_.empty(); }

    void write(int fd)
    {
        std::vector<struct iovec> iov;
        for (auto& buf : bufs_) {
            const auto maybe = buf->buf();
            if (!maybe) {
                break;
            }
            const auto b = maybe.value();
            iov.push_back(iovec{
                .iov_base = (void*)b.data(),
                .iov_len = b.size(),
            });
        }
        if (!iov.empty()) {
            // TODO: set TCP_CORK if iov.size() < bufs_.size() ?
            auto rc = ::writev(fd, iov.data(), (int)iov.size());
            if (rc < 0) {
                throw std::runtime_error("writev()");
            }
            size_t skip = 0;
            for (auto& buf : bufs_) {
                rc = buf->advance(rc);
                if (buf->empty()) {
                    skip++;
                }
                if (rc == 0) {
                    break;
                }
            }
            bufs_.erase(bufs_.begin(), bufs_.begin() + skip);
            return;
        }
        if (!bufs_.empty()) {
            auto& buf = *bufs_[0];
            const auto rc = buf.write(fd);
            buf.advance(rc);
            if (buf.empty()) {
                bufs_.erase(bufs_.begin(), bufs_.begin() + 1);
            }
        }
        return;
    }

private:
    // TODO: turn into a circular buffer.
    std::vector<std::unique_ptr<BufBase>> bufs_;
};
#if 0
int main()
{
  int fd = open("README.md", O_RDONLY);
  OQueue q;
  q.add(Buf{"hello\n"});
  q.add(Buf{"world\n"});
  q.add(FileBuf{fd, 0, 100});
  while (!q.empty()) {
    q.write(STDOUT_FILENO);
  }
}
#endif
