use std::collections::HashMap;
use std::fmt::Write;
use std::io::Read;

use anyhow::{Context, Result};
use rayon::iter::IntoParallelRefMutIterator;
use rayon::iter::ParallelIterator;
use tracing::{info, trace};

#[must_use]
fn calculate_etag(bytes: &[u8]) -> String {
    use sha3::Digest;
    let mut h = sha3::Sha3_256::new();
    h.update(bytes);
    format!("{:#x}", h.finalize()).to_string()
}

/// Archive consists of the entire index and the memory mapped data.
pub struct Archive {
    mmap: memmap2::Mmap,
    content: HashMap<String, ArchiveEntry>,
}

/// Builder for Archive.
pub struct ArchiveBuilder {
    hugepages: Option<u8>,
    etags: bool,
}

impl ArchiveBuilder {
    pub fn build<P: AsRef<std::path::Path>>(&self, filename: P, prefix: &str) -> Result<Archive> {
        if let Some(bits) = self.hugepages {
            Archive::hugepages(filename.as_ref(), prefix, self.etags, bits)
        } else {
            Archive::new(filename.as_ref(), prefix, self.etags)
        }
    }
    pub fn etags(&mut self, v: bool) -> &mut Self {
        self.etags = v;
        self
    }
    pub fn hugepages(&mut self, v: Option<u8>) -> &mut Self {
        self.hugepages = v;
        self
    }
}

impl Archive {
    pub fn builder() -> ArchiveBuilder {
        ArchiveBuilder {
            hugepages: None,
            etags: false,
        }
    }

    fn new(filename: &std::path::Path, prefix: &str, etags: bool) -> Result<Self> {
        let file = std::fs::File::open(filename)?;
        let map = unsafe { memmap2::Mmap::map(&file)? };
        // Can't hurt to at least ask to be hugepages or mergable.
        map.advise(memmap2::Advice::HugePage)?;
        Self::new_inner(map, file, prefix, etags)
    }

    /// Map and index an archive with hugepages.
    fn hugepages(filename: &std::path::Path, prefix: &str, etags: bool, bits: u8) -> Result<Self> {
        use std::io::Seek;

        let mut file = std::fs::File::open(filename)?;
        let len = file.metadata()?.len();

        let page_size = 1 << bits;
        let maplen = (len + (page_size - 1)) & !(page_size - 1);
        let mut m = memmap2::MmapOptions::new()
            .len(maplen.try_into()?)
            .huge(Some(bits))
            .map_anon()
            .with_context(|| format!("Failed allocating 1<<{bits}={} bytes", 1 << bits))?;

        // Rewind the file.
        file.read_exact(&mut m.as_mut()[..len.try_into()?])?;
        file.seek(std::io::SeekFrom::Start(0))?;
        Self::new_inner(m.make_read_only()?, file, prefix, etags)
    }

    /// Shared constructor code.
    fn new_inner(
        mmap: memmap2::Mmap,
        file: std::fs::File,
        prefix: &str,
        etags: bool,
    ) -> Result<Self> {
        mmap.advise(memmap2::Advice::Mergeable)?;
        let mut archive = tar::Archive::new(file);
        let mut content = HashMap::new();
        info!("Indexing…");
        for e in archive.entries()? {
            let e = e?;
            if !matches![e.header().entry_type(), tar::EntryType::Regular] {
                continue;
            }
            let name = e.path()?;
            let name = name.to_string_lossy();
            let name = name.strip_prefix(prefix).unwrap_or(name.as_ref());
            let modified = e
                .header()
                .mtime()
                .map(|t| std::time::UNIX_EPOCH + std::time::Duration::from_secs(t))
                .ok();
            let mut headers = String::new();
            if let Some(m) = modified {
                write!(
                    &mut headers,
                    "Last-Modified: {}\r\n",
                    httpdate::fmt_http_date(m)
                )?;
            }
            content.insert(
                name.to_string(),
                ArchiveEntry {
                    plain: ArchiveRange {
                        pos: e.raw_file_position().try_into()?,
                        len: e.size().try_into()?,
                    },
                    brotli: None,
                    gzip: None,
                    zstd: None,
                    modified,
                    etag: None, // Set later.
                    headers,
                },
            );
        }
        if etags {
            info!("Hashing etags…");
            content
                .par_iter_mut()
                .map(|(_k, v)| {
                    let etag = calculate_etag(&mmap[v.plain.pos..(v.plain.pos + v.plain.len)]);
                    write!(v.headers, "ETag: {etag}\r\n")?;
                    v.etag = Some(etag);
                    Ok::<(), anyhow::Error>(())
                })
                .find_first(std::result::Result::is_err)
                .unwrap_or(Ok(()))?;
        }
        let c2 = content.clone();
        for (k, v) in &c2 {
            let Some(ext) = std::path::Path::new(k).extension() else {
                continue;
            };
            let base = &k[..(k.len() - ext.len() - 1)];
            let Some(r) = content.get_mut(base) else {
                continue;
            };
            let v = Some(v.plain.clone());
            match ext.to_str().unwrap_or_default() {
                "br" => r.brotli = v,
                "zstd" => r.zstd = v,
                "gz" => r.gzip = v,
                _ => {}
            }
        }
        Ok(Self { mmap, content })
    }

    /// Get the `ArchiveEntry` for a given filename.
    #[must_use]
    pub fn entry(&self, filename: &str) -> Option<&ArchiveEntry> {
        use std::borrow::Cow;
        if filename.is_empty() {
            return None;
        }
        // Strip initial slash.
        let filename = filename.strip_prefix("/").unwrap_or(filename);

        // Add index.html to directory paths.
        let filename = if filename.is_empty() || filename.ends_with('/') {
            Cow::Owned(filename.to_owned() + "index.html")
        } else {
            Cow::Borrowed(filename)
        };

        trace!("Looking up {filename}");
        self.content.get(filename.as_ref())
    }

    /// Get a slice from the mapped memory area.
    #[must_use]
    pub fn get_slice(&self, pos: usize, len: usize) -> &[u8] {
        let data: &[u8] = &self.mmap;
        &data[pos..(pos + len)]
    }
}

/// Just the byte range inside the mapped area.
#[derive(Clone, Debug)]
pub struct ArchiveRange {
    pub pos: usize,
    pub len: usize,
}

/// All metadata about a particular file, including alternative encodings.
#[derive(Clone)]
pub struct ArchiveEntry {
    plain: ArchiveRange,
    gzip: Option<ArchiveRange>,
    brotli: Option<ArchiveRange>,
    zstd: Option<ArchiveRange>,
    modified: Option<std::time::SystemTime>,
    etag: Option<String>,
    headers: String,
}

impl ArchiveEntry {
    pub fn plain(&self) -> &ArchiveRange {
        &self.plain
    }
    pub fn brotli(&self) -> Option<&ArchiveRange> {
        self.brotli.as_ref()
    }
    pub fn gzip(&self) -> Option<&ArchiveRange> {
        self.gzip.as_ref()
    }
    pub fn zstd(&self) -> Option<&ArchiveRange> {
        self.zstd.as_ref()
    }
    pub fn modified(&self) -> Option<&std::time::SystemTime> {
        self.modified.as_ref()
    }
    pub fn etag(&self) -> Option<&str> {
        self.etag.as_deref()
    }
    pub fn headers(&self) -> &str {
        &self.headers
    }
}
