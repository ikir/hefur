#include <fnmatch.h>

#include <mimosa/fs/find.hh>

#include "fs-tree-white-list.hh"
#include "hefur.hh"
#include "options.hh"
#include "log.hh"

namespace hefur
{
  FsTreeWhiteList::FsTreeWhiteList(const std::string & root,
                                   m::Time             rescan_interval)
    : root_(root),
      rescan_interval_(rescan_interval),
      stop_(),
      scan_thread_([this] { this->loopScan(); })
  {
    scan_thread_.start();
  }

  FsTreeWhiteList::~FsTreeWhiteList()
  {
    stop_.set(true);
    scan_thread_.join();
  }

  void
  FsTreeWhiteList::scan()
  {
    uint32_t nb_inodes = 0;
    m::fs::find(root_, MAX_SCAN_DEPTH, [&] (const std::string & path) {
        if (++nb_inodes > MAX_SCAN_INODES) {
          log->error("reached the limit of scanned inodes: %d", MAX_SCAN_INODES);
          return false;
        }

        if (::fnmatch("*.torrent", path.c_str(), FNM_CASEFOLD))
          return true;

        auto tdb = Hefur::instance().torrentDb();
        if (tdb)
          tdb->addTorrent(Torrent::parseFile(path));
        return true;
      });
  }

  void
  FsTreeWhiteList::loopScan()
  {
    do {
      scan();
    } while (!stop_.timedWait(m::time() + rescan_interval_));
  }
}
