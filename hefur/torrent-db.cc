#include "torrent-db.hh"
#include "log.hh"
#include "options.hh"

namespace hefur
{
  TorrentDb::TorrentDb()
    : cleanup_stop_(),
      cleanup_thread_([this] { this->cleanupLoop(); }),
      torrents_lock_(),
      torrents_()
  {
    cleanup_thread_.start();
  }

  TorrentDb::~TorrentDb()
  {
    // stop the cleanup thread
    cleanup_stop_.set(true);
    cleanup_thread_.join();

    // lock to let threads finish to use the db
    m::SharedMutex::Locker locker(torrents_lock_);
  }

  AnnounceResponse::Ptr
  TorrentDb::announce(AnnounceRequest::Ptr request)
  {
    m::SharedMutex::Locker locker(torrents_lock_);

    Torrent * torrent = torrents_.find(request->info_sha1_.bytes());
    if (!torrent)
    {
      // we didn't find the torrent, so let's answer an error
      AnnounceResponse::Ptr response = new AnnounceResponse;
      response->error_               = true;
      response->error_msg_           = "torrent not found";
      return response;
    }
    // forward the request to the torrent
    auto response       = torrent->announce(request);
    response->interval_ = ANNOUNCE_INTERVAL * 60;
    return response;
  }

  ScrapeResponse::Ptr
  TorrentDb::scrape(ScrapeRequest::Ptr request)
  {
    ScrapeResponse::Ptr response = new ScrapeResponse;
    response->error_             = false;

    m::SharedMutex::ReadLocker locker(torrents_lock_);
    for (auto it = request->info_sha1s_.begin(); it != request->info_sha1s_.end(); ++it)
    {
      ScrapeResponse::Item item;
      Torrent * torrent = torrents_.find(it->bytes());
      if (!torrent)
        continue;

      item.info_sha1_   = *it;
      item.nleechers_   = torrent->leechers();
      item.nseeders_    = torrent->seeders();
      item.ndownloaded_ = torrent->completed();
      response->items_.push_back(item);
    }
    response->interval_ = SCRAPE_INTERVAL * 60;
    return response;
  }

  void
  TorrentDb::cleanup()
  {
    // as we are not modifying the trie, we can use shared locking
    // the torrent, will do exclusive locking for itself
    m::SharedMutex::ReadLocker locker(torrents_lock_);
    torrents_.foreach([] (Torrent::Ptr torrent) {
        torrent->cleanup();
      });
  }

  void
  TorrentDb::cleanupLoop()
  {
    while (!cleanup_stop_.timedWait(m::time() + m::minute))
      cleanup();
  }

  void
  TorrentDb::addTorrent(Torrent::Ptr torrent)
  {
    // we are so nice to check :o)
    if (!torrent)
      return;

    // this is the only part which requires exclusive locking as we
    // modify the trie
    m::SharedMutex::Locker locker(torrents_lock_);
    torrents_.insert(torrent);
  }
}
