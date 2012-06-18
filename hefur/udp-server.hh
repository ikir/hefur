#ifndef HEFUR_UDP_SERVER_HH
# define HEFUR_UDP_SERVER_HH

# include <cstdint>
# include <unordered_map>

# include <mimosa/time.hh>
# include <mimosa/thread.hh>

namespace hefur
{
  /**
   * This is the udp bittorrent tracker.
   *
   * See:
   * - http://www.bittorrent.org/beps/bep_0015.html (protocol)
   *
   * and see @class HttpServer for more documentation.
   */
  class UdpServer
  {
  public:
    UdpServer();
    ~UdpServer();

    /**
     * Starts the server. If the server is already started,
     * then it restarts.
     *
     * @return true on success, and false otherwise
     */
    bool start(uint16_t port,
               bool     ipv6);

    /**
     * Stops the server, and does nothing if the server is already
     * stopped.
     */
    void stop();

  private:
    static const uint64_t buff_size = 8192;
    uint64_t generateConnectionId(const struct sockaddr_in& addr) const;

    struct msg_client_connect
    {
      int64_t connection_id;
      int32_t action;
      int32_t transaction_id;
    };

    struct msg_client_announce
    {
      uint64_t   connection_id;
      int32_t    action;
      int32_t    transaction_id;
      char       info_hash[20];
      char       peer_id[20];
      int64_t    downloaded;
      int64_t    left;
      int64_t    uploaded;
      int32_t    event;
      uint32_t   ip;
      int32_t    key;
      int32_t    num_want;
      uint16_t   port;
    } __attribute__((packed));

    struct msg_response_announce
    {
      int32_t   action;
      int32_t   transaction_id;
      int32_t   interval;
      int32_t   leechers;
      int32_t   seeders;
      struct
      {
        uint32_t ip;
        uint16_t port;
      } addrs[];
    }__attribute__((packed));

    struct MsgCtx
    {
      union
      {
        char                buff[buff_size];
        uint32_t            buff_32[buff_size / sizeof(uint32_t)];
        msg_client_announce announce;
      };
      ssize_t            byte_count;
      struct sockaddr_in from;
    };

    struct connection_cache_entry
    {
      uint64_t     connection_id;
      mimosa::Time time;
    };

    void run();
    void recvMsg(MsgCtx& msg_ctx) const;
    bool parseMsg(const MsgCtx& msg_ctx);
    void handleConnect(const MsgCtx& msg_ctx);
    void handleAnnounce(const MsgCtx& msg_ctx) const;
    void handleScrape(const MsgCtx& msg_ctx) const;
    void sendError(const MsgCtx& msg_ctx,
                   const std::string& msg) const;

    int            fd_;
    bool           stop_;
    uint64_t       secret_key_;
    mimosa::Thread thread_;
    std::unordered_map<uint32_t /*s_addr*/,
                       connection_cache_entry> connection_cache_;
  };
}

#endif /* !HEFUR_UDP_SERVER_HH */
