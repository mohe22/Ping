#include <arpa/inet.h>
#include <chrono>
#include <cstring>
#include <iomanip>
#include <iostream>
#include <netdb.h>
#include <sstream>
#include <sys/socket.h>
#include <sys/types.h>
#include <thread>
#include <unistd.h>
using namespace std;
using namespace std::chrono;

struct ICMPPacket {
  uint8_t type;
  uint8_t code;
  uint16_t checksum;
  uint16_t id;
  uint16_t sequence;
  uint8_t payload[56];
};

class ICMP {
private:
  ICMPPacket packet_;
  static string payloadHex(const uint8_t* data, size_t len) {
    stringstream ss;
    ss << hex << uppercase << setfill('0');
    for (size_t i = 0; i < len; ++i)
      ss << setw(2) << (int)data[i] << (i < len-1 ? " " : "");
    return ss.str();
  }
  static string payloadAscii(const uint8_t* data, size_t len) {
    string s;
    for (size_t i = 0; i < len; ++i)
      s += isprint(data[i]) ? (char)data[i] : '.';
    return s;
  }
  static uint16_t calculateChecksum(const void *data, size_t len) {
    const uint16_t *words = static_cast<const uint16_t *>(data);
    uint32_t sum = 0;
    size_t count = len / 2;
    for (size_t i = 0; i < count; ++i) {
      sum += ntohs(words[i]);
    }
    if (len & 1) {
      sum += *(reinterpret_cast<const uint8_t *>(data) + len - 1);
    }
    sum = (sum >> 16) + (sum & 0xFFFF);
    sum += (sum >> 16);
    return static_cast<uint16_t>(~sum);
  }
public:
  ICMP(uint16_t id = 0, uint16_t seq = 0) {
    packet_.type = 8;
    packet_.code = 0;
    packet_.id = htons(id ? id : (getpid() & 0xFFFF));
    packet_.sequence = htons(seq);
    memset(packet_.payload, 0xAA, sizeof(packet_.payload));
    updateChecksum();
  }
  void setSequence(uint16_t seq) { packet_.sequence = htons(seq); updateChecksum(); }
  void updateChecksum() {
    packet_.checksum = 0;
    packet_.checksum = htons(calculateChecksum(&packet_, sizeof(packet_)));
  }
  uint16_t getId() const { return ntohs(packet_.id); }
  uint16_t getSeq() const { return ntohs(packet_.sequence); }
  uint16_t getCksum() const { return ntohs(packet_.checksum); }
  size_t size() const { return sizeof(packet_); }
  const ICMPPacket* raw() const { return &packet_; }
  bool matches(const ICMPPacket* r) const {
    return r->type == 0 && r->code == 0 &&
           r->id == packet_.id && r->sequence == packet_.sequence;
  }
  string sentInfo(const string& ip) const {
    stringstream ss;
    ss << "PING " << ip << " (" << getId() << ") "
       << sizeof(packet_.payload) << " data bytes: "
       << "cksum=0x" << hex << uppercase << setw(4) << setfill('0')
       << getCksum() << dec;
    return ss.str();
  }
  string replyInfo(const in_addr& from, double rtt) const {
    stringstream ss;
    ss << (8 + sizeof(packet_.payload)) << " bytes from " << inet_ntoa(from)
       << ": icmp_seq=" << getSeq() << " id=" << getId()
       << " ttl=128 time=" << fixed << setprecision(3) << rtt << " ms"
       << " cksum=0x" << hex << uppercase << setw(4) << setfill('0')
       << getCksum() << dec;
    return ss.str();
  }
};

bool resolveHost(const string& host, sockaddr_storage& out, socklen_t& len) {
  addrinfo hints{}, *res;
  hints.ai_family = AF_INET;
  hints.ai_socktype = SOCK_RAW;
  if (getaddrinfo(host.c_str(), nullptr, &hints, &res)) return false;
  memcpy(&out, res->ai_addr, res->ai_addrlen);
  len = res->ai_addrlen;
  freeaddrinfo(res);
  return true;
}


int main(int argc, char* argv[]) {
  if (argc < 3) {
    cerr << "Usage: " << argv[0] << " [-c count] <host>\n";
    return 1;
  }

  int count = 4;
  string host;
  for (int i = 1; i < argc; ++i) {
    if (string(argv[i]) == "-c" && i+1 < argc) count = atoi(argv[++i]);
    else host = argv[i];
  }
  if (host.empty()) { cerr << "Host required\n"; return 1; }

  sockaddr_storage dst{};
  socklen_t dlen = 0;
  if (!resolveHost(host, dst, dlen)) return 1;

  char ipStr[INET_ADDRSTRLEN];
  inet_ntop(AF_INET, &((sockaddr_in*)&dst)->sin_addr, ipStr, sizeof(ipStr));

  int sock = socket(AF_INET, SOCK_RAW, IPPROTO_ICMP);
  if (sock < 0) { cerr << "socket: " << strerror(errno) << "\n"; return 1; }

  timeval tv{1, 0};
  setsockopt(sock, SOL_SOCKET, SO_RCVTIMEO, &tv, sizeof(tv));

  uint16_t pid = getpid() & 0xFFFF;
  int sent = 0, recv = 0;
  double minRtt = 1e9, maxRtt = 0, sumRtt = 0;

  for (int seq = 1; seq <= count; ++seq) {
      ICMP pkt(pid, seq);
      cout << pkt.sentInfo(ipStr) << "\n";

      auto st = high_resolution_clock::now();
      if (sendto(sock, pkt.raw(), pkt.size(), 0, (sockaddr*)&dst, dlen) < 0) {
          cerr << "sendto error: " << strerror(errno) << "\n";
          continue;
      }
      ++sent;

      char buf[512];
      sockaddr_in from{};
      socklen_t flen = sizeof(from);

      ssize_t n = recvfrom(sock, buf, sizeof(buf), 0, (sockaddr*)&from, &flen);
      auto end = high_resolution_clock::now();
      double rtt = duration_cast<microseconds>(end - st).count() / 1000.0;
      this_thread::sleep_for(milliseconds(400));
      if (n < 0) {
          if (errno == EAGAIN || errno == EWOULDBLOCK) {
              cout << "Request timeout for icmp_seq=" << seq << "\n";
          } else {
              cerr << "recvfrom error: " << strerror(errno) << "\n";
          }
          continue;
      }

      int ipLen = (buf[0] & 0x0F) * 4;
      if (n < ipLen + (int)sizeof(ICMPPacket)) continue;

      const ICMPPacket* rep = (const ICMPPacket*)(buf + ipLen);
      if (!pkt.matches(rep)) continue;  // not our packet

      ++recv;
      minRtt = min(minRtt, rtt);
      maxRtt = max(maxRtt, rtt);
      sumRtt += rtt;

      cout << pkt.replyInfo(from.sin_addr, rtt) << "\n";
  }

  if (sent) {
    cout << "\n--- " << host << " ping statistics ---\n"
         << sent << " packets transmitted, " << recv << " received, "
         << (sent - recv) * 100 / sent << "% packet loss\n";
    if (recv) {
      double avg = sumRtt / recv;
      cout << "rtt min/avg/max = " << fixed << setprecision(3)
           << minRtt << "/" << avg << "/" << maxRtt << " ms\n";
    }
  }
  close(sock);
  return 0;
}
