#include "cast.h"

#include <memory_resource>
#include <string_view>
#include <sys/uio.h>
#include <cassert>
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
    virtual ~BufBase() {}

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
    // Construct.
    FileBuf() = delete;
    FileBuf(int fd, size_t ofs, size_t size) : fd_(fd), ofs_(ofs), size_(size)
    {
    }

    // Copy.
    FileBuf(const FileBuf& rhs) : fd_(rhs.fd_), ofs_(rhs.ofs_), size_(rhs.size_)
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
    // Construct.
    ViewBuf(const ViewBuf& rhs) : sv_(rhs.sv_) {}
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
    // Called by class Buf.
    ViewBuf() {}

    std::span<const char> sv_;
};

class Buf : public ViewBuf
{
public:
    Buf() = delete;
    Buf(std::pmr::string&& buf) : buf_(std::move(buf)) { sv_ = buf_; }

    // No copy.
    Buf(const Buf&) = delete;
    Buf& operator=(const Buf&) = delete;

    // Move.
    Buf(Buf&& rhs) : buf_(std::move(rhs.buf_)) { sv_ = buf_; }

    // Move.
    Buf& operator=(Buf&& rhs)
    {
        buf_ = std::move(rhs.buf_);
        sv_ = buf_;
        return *this;
    }

private:
    std::pmr::string buf_;
};


class OQueue
{
public:
    OQueue(std::pmr::memory_resource* pool) : pool_(pool), bufs_(pool)
    {
        bufs_.reserve(5); // See README. Should not see more than 5.
    }

    template <typename T>
    void add(T&& buf)
    {
        bufs_.push_back(std::make_unique<T>(std::move(buf)));
    }

    bool empty() const { return bufs_.empty(); }

    void write(int fd)
    {
        // The real number should be max 5, per README. But that may
        // change as we add features.
        //
        // The important part is not alloca()ing so much that we skip
        // any stack guard pages.
        size_t size = std::min<size_t>(bufs_.size(), 10);

        // VLAs are not part of C++, and won't be.
        auto iov =
            static_cast<struct iovec*>(alloca(size * sizeof(struct iovec)));

        for (size_t c = 0; c < size; c++) {
            const auto maybe = bufs_[c]->buf();
            if (!maybe) {
                // Next buffer may be a sendfile().
                size = c;
                break;
            }
            const auto b = maybe.value();
            iov[c].iov_base = (void*)b.data();
            iov[c].iov_len = b.size();
        }
        if (size) {
            // TODO: set TCP_CORK if iov.size() < bufs_.size() ?
            auto rc = ::writev(fd, iov, safe_int_cast<int>(size));
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
    }

private:
    std::pmr::memory_resource* pool_;
    std::pmr::vector<std::unique_ptr<BufBase>> bufs_;
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
