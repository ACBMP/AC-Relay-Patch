// Win32 check: can a 32-bit process under Wine enumerate global IPv6,
// pick the OS-preferred source, bind AF_INET6 UDP and round-trip a datagram?
#include <winsock2.h>
#include <ws2tcpip.h>
#include <iphlpapi.h>
#include <cstdio>
#include <vector>
static void p6(const char* tag, const in6_addr& a){ char s[64]; inet_ntop(AF_INET6,(void*)&a,s,sizeof s); printf("%s %s\n",tag,s); }
int main(){
  WSADATA w; WSAStartup(MAKEWORD(2,2),&w);
  ULONG len=32768; std::vector<char> buf(len);
  auto* aa=(IP_ADAPTER_ADDRESSES*)buf.data();
  ULONG r=GetAdaptersAddresses(AF_INET6,GAA_FLAG_SKIP_ANYCAST|GAA_FLAG_SKIP_MULTICAST|GAA_FLAG_SKIP_DNS_SERVER,nullptr,aa,&len);
  printf("GetAdaptersAddresses=%lu\n",r);
  for(auto* a=aa; r==0 && a; a=a->Next) for(auto* u=a->FirstUnicastAddress;u;u=u->Next){
    auto* sa=(sockaddr_in6*)u->Address.lpSockaddr; bool global=(sa->sin6_addr.s6_addr[0]&0xe0)==0x20;
    char s[64]; inet_ntop(AF_INET6,&sa->sin6_addr,s,sizeof s);
    printf("  if=%-12S %s global=%d dad=%d suffix=%d\n",a->FriendlyName,s,global,(int)u->DadState,(int)u->SuffixOrigin);
  }
  // OS-preferred source address: connect a UDP socket (sends nothing) and getsockname
  SOCKET c=socket(AF_INET6,SOCK_DGRAM,IPPROTO_UDP);
  sockaddr_in6 dst{}; dst.sin6_family=AF_INET6; dst.sin6_port=htons(53); inet_pton(AF_INET6,"2606:4700:4700::1111",&dst.sin6_addr);
  if(connect(c,(sockaddr*)&dst,sizeof dst)){ printf("connect err %d\n",WSAGetLastError()); return 1; }
  sockaddr_in6 me{}; int ml=sizeof me; getsockname(c,(sockaddr*)&me,&ml); p6("preferred source:",me.sin6_addr); closesocket(c);
  // bind that address, send to ourselves via the global address
  SOCKET s=socket(AF_INET6,SOCK_DGRAM,IPPROTO_UDP);
  me.sin6_port=0; if(bind(s,(sockaddr*)&me,sizeof me)){ printf("bind err %d\n",WSAGetLastError()); return 1; }
  ml=sizeof me; getsockname(s,(sockaddr*)&me,&ml); printf("bound port %u\n",ntohs(me.sin6_port));
  const char msg[]="acb-v6-test"; int n=sendto(s,msg,sizeof msg,0,(sockaddr*)&me,sizeof me); printf("sendto=%d\n",n);
  DWORD to=2000; setsockopt(s,SOL_SOCKET,SO_RCVTIMEO,(char*)&to,sizeof to);
  char in[64]; sockaddr_in6 from{}; int fl=sizeof from; n=recvfrom(s,in,sizeof in,0,(sockaddr*)&from,&fl);
  printf("recvfrom=%d fromlen=%d '%s'\n",n,fl,n>0?in:""); if(n>0) p6("from:",from.sin6_addr);
  return 0;
}
