#include <arpa/inet.h>
#include <sys/socket.h>
#include <gnutls/gnutls.h>
#include <gnutls/crypto.h>

#include <mimosa/stream/hash.hh>

#include "hefur.hh"
#include "log.hh"
#include "announce-request.hh"
#include "udp-server.hh"

namespace hefur
{
  UdpServer::UdpServer()
    : fd_(-1),
      stop_(false),
      thread_([this] { this->run(); })
  {

  }

  UdpServer::~UdpServer()
  {
    stop();
  }

  bool
  UdpServer::start(uint16_t port,
                   bool     ipv6)
  {
    if (ipv6)
    {
      log->fatal("ipv6 not supported for udp");
      return false;
    }

    if (fd_ >= 0)
      stop();

    if (gnutls_rnd(GNUTLS_RND_RANDOM, &secret_key_, sizeof (secret_key_)) < 0)
    {
      log->fatal("generation of the secret key failed");
      return false;
    }

    fd_ = ::socket(PF_INET, SOCK_DGRAM, 0);
    if (fd_ == 0)
    {
      log->fatal("failed to create the socket: %s", ::strerror(errno));
      return false;
    }

    static const int enable = 1;
      ::setsockopt(fd_, SOL_SOCKET, SO_REUSEADDR,
                   &enable, sizeof(enable));

    struct sockaddr_in addr;
    ::memset(&addr, 0, sizeof (addr));
    addr.sin_addr.s_addr = htonl(INADDR_ANY);
    addr.sin_family = AF_INET;
    addr.sin_port = htons(port);
    if (::bind(fd_, (struct sockaddr*)&addr, sizeof (addr)))
    {
      log->fatal("failed to bind the port %d: %s", port, ::strerror(errno));
      return false;
    }

    thread_.start();

    return true;
  }

  uint64_t
  UdpServer::generateConnectionId(const struct sockaddr_in& addr) const
  {
    char s[sizeof (secret_key_) + sizeof (addr.sin_addr.s_addr)];
    memcpy(s, &secret_key_, sizeof (secret_key_));
    memcpy(s + 8, &addr.sin_addr.s_addr, sizeof (addr.sin_addr.s_addr));

    mimosa::stream::Sha1::Ptr hash = new mimosa::stream::Sha1;

    hash->write(s, sizeof (s));

    uint64_t res;
    assert(sizeof (res) > hash->digestLen());
    memcpy(&res, hash->digest(), sizeof (res));

    return res;
  }

  void
  UdpServer::recvMsg(MsgCtx& msg_ctx) const
  {
    socklen_t addr_len;

    log->warning("receive");

    msg_ctx.byte_count = recvfrom(fd_,
                                  msg_ctx.buff,
                                  buff_size,
                                  0,
                                  (struct sockaddr*)&msg_ctx.from,
                                  &addr_len);
    if (msg_ctx.byte_count <= 0)
    {
      log->warning("failed to recvfrom UDP: %s", ::strerror(errno));
    }
  }

  bool
  UdpServer::parseMsg(const MsgCtx& msg_ctx)
  {
    /* minimun udp packet size */
    if (msg_ctx.byte_count < 16)
      return false;

    switch(ntohl(msg_ctx.buff_32[2]))
    {
    case 0: /* connect action */
      handleConnect(msg_ctx);
      break;
    case 1: /* announce action */
      handleAnnounce(msg_ctx);
      break;
    case 2: /* scrape action */
      handleScrape(msg_ctx);
      break;
    default: /* unknown action */
      return false;
    }

    return true;
  }

  void
  UdpServer::sendError(const MsgCtx& msg_ctx,
                       const std::string& msg) const
  {
    char output[2 * sizeof (uint32_t) + msg.size() + 1];

    uint32_t error_code = htonl(3);

    memcpy(output, &error_code, sizeof (uint32_t));
    memcpy(output + sizeof (uint32_t),
           &msg_ctx.buff_32[3],
           sizeof (msg_ctx.buff_32[3]));

    log->warning(msg.c_str());

    if (sendto(fd_,
               output,
               sizeof (output),
               0,
               (struct sockaddr*)&msg_ctx.from,
               sizeof (msg_ctx.from)) == -1)
      log->warning("failed to send error message", ::strerror(errno));
  }

  void
  UdpServer::handleConnect(const MsgCtx& msg_ctx)
  {
    log->warning("handle_connect");
    uint32_t output[4];
    /* look for udp bittorrent magic ic */

    if ((ntohl(msg_ctx.buff_32[0]) != 0x417) || (ntohl(msg_ctx.buff_32[1]) != 0x27101980))
      return;

    uint64_t connection_id;
    if (gnutls_rnd(GNUTLS_RND_RANDOM, &connection_id, sizeof (connection_id)) < 0)
    {
      sendError(msg_ctx, "generation of a connection_id failed");
      return;
    }

    output[0] = 0; /* action connect */
    output[1] = msg_ctx.buff_32[3]; /* transaction_id */

    memcpy(output + 2, &connection_id, sizeof (connection_id));

    if (sendto(fd_,
               output,
               sizeof (output),
               0,
               (struct sockaddr*)&msg_ctx.from,
                       sizeof (msg_ctx.from)) == -1)
    {
      log->warning("failed to send connect response", ::strerror(errno));
      return;
    }

    connection_cache_[msg_ctx.from.sin_addr.s_addr] = { connection_id, mimosa::time() };
  }

  void
  UdpServer::handleAnnounce(const MsgCtx& msg_ctx) const
  {
    log->warning("handle_announce");

    if (msg_ctx.byte_count < sizeof (msg_client_announce))
      return;

    auto it_cache = connection_cache_.find(msg_ctx.from.sin_addr.s_addr);

    if (it_cache == connection_cache_.end() ||
        it_cache->second.connection_id != msg_ctx.announce.connection_id ||
        mimosa::time() - it_cache->second.time > 2 * mimosa::minute)
    {
      return;
    }

    // Convert the request to hefur binary representation
    AnnounceRequest::Ptr rq = new AnnounceRequest;

    memcpy(rq->peerid_, msg_ctx.announce.peer_id, sizeof (msg_ctx.announce.peer_id));
    memcpy(rq->info_sha1_.bytes_,
           msg_ctx.announce.info_hash,
           sizeof (msg_ctx.announce.info_hash));

    int32_t num_want = ntohl(msg_ctx.announce.num_want);
    if (num_want == -1)
      rq->num_want_ = 50;
    else if (num_want > 100)
      rq->num_want_ = 100;
    else
      rq->num_want_ = num_want;

    switch (ntohl(msg_ctx.announce.event))
    {
    case 0:
      rq->event_ = AnnounceRequest::kNone;
      break;
    case 1:
      rq->event_ = AnnounceRequest::kCompleted;
      break;
    case 2:
      rq->event_ = AnnounceRequest::kStarted;
      break;
    case 3:
      rq->event_ = AnnounceRequest::kStopped;
    }

    rq->downloaded_ = htobe64(msg_ctx.announce.downloaded);
    rq->uploaded_ = htobe64(msg_ctx.announce.uploaded);
    rq->left_ = htobe64(msg_ctx.announce.left);

    uint32_t ip = ntohl(msg_ctx.announce.ip);

    if (ip == 0)
      rq->addr_ = (const struct sockaddr*)&msg_ctx.from;
    else
    {
      rq->addr_.family_ = AF_INET;
      memcpy(rq->addr_.in_.addr_, &ip, sizeof (ip));
      rq->addr_.in_.port_ = ntohs(msg_ctx.announce.port);
    }

    auto tdb = Hefur::instance().torrentDb();

    if (!tdb)
    {
      sendError(msg_ctx, "Service unavailable");
      return;
    }

    auto rp = tdb->announce(rq);
    if (!rp || rp->error_)
    {
      sendError(msg_ctx, rp ? rp->error_msg_ : "Internal error");
      return;
    }


    uint16_t output[5 * 2 * (3 * rp->addrs_.size())];
    msg_response_announce* bin_rp = (msg_response_announce*) output;

    bin_rp->action = htonl(1);
    bin_rp->transaction_id = msg_ctx.announce.transaction_id;
    bin_rp->interval = htonl(rp->interval_);
    bin_rp->leechers = htonl(rp->nleechers_);
    bin_rp->seeders = htonl(rp->nseeders_);

    for (unsigned int i = 0; i < rp->addrs_.size(); ++i)
    {
      memcpy(&bin_rp->addrs[i].ip, rp->addrs_[i].in_.addr_, sizeof(bin_rp->addrs[i].ip));
      bin_rp->addrs[i].ip = htonl(bin_rp->addrs[i].ip);
      bin_rp->addrs[i].port = htons(rp->addrs_[i].in_.port_);
    }

    if (sendto(fd_,
               output,
               sizeof (output),
               0,
               (struct sockaddr*)&msg_ctx.from,
               sizeof (msg_ctx.from)) == -1)
      log->warning("failed to send error message", ::strerror(errno));
  }

  void
  UdpServer::handleScrape(const MsgCtx& msg_ctx) const
  {
    log->warning("handle_scrape");
  }
  void
  UdpServer::run()
  {
    while (!stop_)
    {
      MsgCtx msg_ctx;
      recvMsg(msg_ctx);
      if (msg_ctx.byte_count > 0)
        parseMsg(msg_ctx);

    }
  }

  void
  UdpServer::stop()
  {
    if (fd_ <= 0)
      return;

    stop_ = true;
    ::close(fd_);
    fd_ = -1;
    thread_.join();
  }
}
