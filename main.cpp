#include <stdio.h>
#include <pcap.h> 
#include <stdint.h>
#include <libnet/include/libnet.h>
#include <netinet/ether.h> //ether_ntoa()
//#include <net/ethernet.h>
//#include <netinet/ip.h>
//#include <arpa/inet.h>
//#include <netinet/tcp.h>

#define IP_ADDR_LEN 4
#define RST_FW 567
#define RST_BK 678
#define HEADER_LEN 54
#define CARRY 65536

uint8_t attacker_mac[ETHER_ADDR_LEN];
uint8_t fake_mac[ETHER_ADDR_LEN];
const char* http_method[6] = {"GET", "POST", "HEAD", "PUT", "DELETE", "OPTIONS"};
const char *http_msg = "blocked";

#pragma pack(push,1)

struct tcp_structure {
	struct libnet_ethernet_hdr eth_hdr;
	struct libnet_ipv4_hdr ip_hdr;
	struct libnet_tcp_hdr tcp_hdr;
};

struct pseudo_header{
	struct in_addr ip_src;
	struct in_addr ip_dst;
	uint8_t reserved = 0;
	uint8_t ip_p;
	u_short tcp_len;
};

#pragma pack(pop)

void dump(const u_char* p, int len) {
  if(len<=0) {
    printf("None\n");
    return;
  }
  for(int i =0; i < len; i++) {
    printf("%02x " , *p);
    p++;
    if((i & 0x0f) == 0x0f)
      printf("\n");
  }
  printf("\n");
}

void usage() {
  printf("syntax: pcap_test <interface>\n");
  printf("sample: pcap_test wlan0\n");
}

uint16_t calculate(uint16_t* data, int length) {
  uint16_t res;
  int temp_checksum = 0;
  int len;
  bool flag = false;
  if(!(length%2))
    len = length/2;
  else {
    len = (length/2) + 1;
    flag = true;
  }

  for(int i= 0; i< len; ++i) {
  	if(i == len - 1 && flag)
  	  temp_checksum += ntohs(data[i]&0x00ff);
  	else
  	  temp_checksum += ntohs(data[i]);

  	if(temp_checksum > CARRY)
  	  {temp_checksum -= CARRY; temp_checksum += 1;}

  }
res = temp_checksum;
  return res;

}

uint16_t cal_ip_checksum(struct libnet_ipv4_hdr* iph) {
  iph->ip_sum  = 0;
  uint16_t checksum = calculate((uint16_t*)iph,iph->ip_hl*4);
  checksum = htons(checksum^0xffff);

  return checksum;
}


uint16_t cal_tcp_checksum(struct libnet_ipv4_hdr* iph, struct libnet_tcp_hdr* tcph, int length){
  struct pseudo_header pseudo_hdr;
  memcpy(&pseudo_hdr.ip_src, &iph->ip_src, IP_ADDR_LEN);
  memcpy(&pseudo_hdr.ip_dst, &iph->ip_dst, IP_ADDR_LEN);
  pseudo_hdr.ip_p = iph->ip_p;
  pseudo_hdr.tcp_len = htons(length - (iph->ip_hl * 4));

  uint16_t pseudo_res = calculate((uint16_t*)&pseudo_hdr, sizeof(pseudo_hdr));

  tcph->th_sum = 0;
  uint16_t res = calculate((uint16_t*) tcph, ntohs(pseudo_hdr.tcp_len));

  int tmp;
  uint16_t checksum;

  if((tmp = pseudo_res + res) > CARRY)
	  checksum = tmp-CARRY + 1;
  else
	  checksum = tmp;

  checksum = ntohs(checksum^0xffff);

  return checksum;
}

void make_tcp_rst(uint8_t *packet_s, struct tcp_structure *packet, int ip_len, int tcp_len, int tcp_sl, uint32_t way) {
  
  uint32_t tcp_seq = htonl(ntohl(packet->tcp_hdr.th_seq) + tcp_sl);

  packet->ip_hdr.ip_ttl = 0xff;
  packet->ip_hdr.ip_tos = 0x44;
  packet->tcp_hdr.th_off = 0x5;
  packet->tcp_hdr.th_win = 0;
  packet->tcp_hdr.th_urp = 0;

  if(packet->tcp_hdr.th_flags == TH_SYN)
  {	printf("len: %d\n", tcp_sl);   printf("seq: %d\n",ntohl(packet->tcp_hdr.th_seq));}

  packet->tcp_hdr.th_flags = TH_RST + TH_ACK;

  memcpy(&packet->tcp_hdr.th_seq , &tcp_seq , 4);

  packet->ip_hdr.ip_len = htons(0x0028);
  //memcpy(fake_mac, packet->eth_hdr.ether_dhost,ETHER_ADDR_LEN);
  //memcpy(&packet->eth_hdr.ether_shost, fake_mac, ETHER_ADDR_LEN);
  if(way == RST_BK) {
  	struct in_addr tmp_ip;
  	uint32_t tmp_port;
    memcpy(packet->eth_hdr.ether_dhost, packet->eth_hdr.ether_shost, ETHER_ADDR_LEN);
    memcpy(&tmp_ip, &packet->ip_hdr.ip_src, IP_ADDR_LEN);
    memcpy(&packet->ip_hdr.ip_src , &packet->ip_hdr.ip_dst, IP_ADDR_LEN);
    memcpy(&packet->ip_hdr.ip_dst , &tmp_ip, IP_ADDR_LEN);
    tmp_port = packet->tcp_hdr.th_dport;
    packet->tcp_hdr.th_dport = packet->tcp_hdr.th_sport;
    packet->tcp_hdr.th_sport = tmp_port;
    memcpy(&packet->tcp_hdr.th_seq , &packet->tcp_hdr.th_ack , 4);
    memcpy(&packet->tcp_hdr.th_ack , &tcp_seq , 4);
  }

  memcpy(packet->eth_hdr.ether_shost, attacker_mac, ETHER_ADDR_LEN);
  
  packet->ip_hdr.ip_sum = cal_ip_checksum(&packet->ip_hdr);
  packet->tcp_hdr.th_sum = cal_tcp_checksum(&packet->ip_hdr, &packet->tcp_hdr, 40);
 
  memcpy(packet_s,packet,sizeof(struct tcp_structure));
  
  //dump(packet_s, sizeof(struct tcp_structure));

}

void make_tcp_fin(uint8_t *packet_s, struct tcp_structure *packet, int ip_len, int tcp_len, int tcp_sl) {

 

  int tcp_seq = htonl(ntohl(packet->tcp_hdr.th_seq) + tcp_sl);
  struct in_addr tmp_ip;
  uint32_t tmp_port;

  packet->ip_hdr.ip_ttl = 0xff;
  packet->ip_hdr.ip_tos = 0x44;
  packet->tcp_hdr.th_flags = TH_FIN + TH_ACK;
  packet->tcp_hdr.th_off = 0x5;
  packet->tcp_hdr.th_win = 0;
  packet->tcp_hdr.th_urp = 0;

  memcpy(&packet->tcp_hdr.th_seq , &tcp_seq , 4);
  packet->ip_hdr.ip_len = htons(0x002f);

  //memcpy(fake_mac, packet->eth_hdr.ether_dhost,ETHER_ADDR_LEN);
  //memcpy(&packet->eth_hdr.ether_shost, fake_mac, ETHER_ADDR_LEN);
  memcpy(packet->eth_hdr.ether_dhost, packet->eth_hdr.ether_shost, ETHER_ADDR_LEN);
  memcpy(packet->eth_hdr.ether_shost, attacker_mac, ETHER_ADDR_LEN);

  memcpy(&tmp_ip, &packet->ip_hdr.ip_src, IP_ADDR_LEN);
  memcpy(&packet->ip_hdr.ip_src , &packet->ip_hdr.ip_dst, IP_ADDR_LEN);
  memcpy(&packet->ip_hdr.ip_dst , &tmp_ip, IP_ADDR_LEN);
  tmp_port = packet->tcp_hdr.th_dport;
  packet->tcp_hdr.th_dport = packet->tcp_hdr.th_sport;
  packet->tcp_hdr.th_sport = tmp_port;
  
  memcpy(&packet->tcp_hdr.th_seq , &packet->tcp_hdr.th_ack , 4);
  memcpy(&packet->tcp_hdr.th_ack , &tcp_seq , 4);

  memcpy(packet_s + HEADER_LEN, http_msg, strlen(http_msg));

  //printf("Dump 1\n");
  //dump(packet_s, sizeof(struct tcp_structure)+7);
  memcpy(packet_s,packet,sizeof(struct tcp_structure));
  //printf("Dump 2\n");
  //dump(packet_s, sizeof(struct tcp_structure));

  struct libnet_ipv4_hdr *ip_hd = (struct libnet_ipv4_hdr*) (packet_s + sizeof(libnet_ethernet_hdr));
  struct libnet_tcp_hdr *tcp_hd = (struct libnet_tcp_hdr* ) (packet_s + sizeof(libnet_ethernet_hdr) + ip_hd->ip_hl * 4);
  ip_hd->ip_sum = cal_ip_checksum(ip_hd);
  tcp_hd->th_sum = cal_tcp_checksum(ip_hd, tcp_hd, 47);
   
}

void packet_init(struct tcp_structure *tmp_packet1, struct tcp_structure *tmp_packet2, uint8_t *packet_sF, uint8_t *packet_sB, uint8_t *packet_sB_fin) {
  memset(tmp_packet1,'\x0', sizeof(tcp_structure));
  memset(tmp_packet2,'\x0', sizeof(tcp_structure));
  memset(packet_sF, '\x0', sizeof(tcp_structure));
  memset(packet_sB, '\x0', sizeof(tcp_structure));
  memset(packet_sB_fin, '\x0', sizeof(struct tcp_structure) + strlen(http_msg));
}

void find_data(pcap_t* handle, const uint8_t *packet, struct tcp_structure *tmp_packet1, struct tcp_structure *tmp_packet2, uint8_t *packet_sF, uint8_t *packet_sB, uint8_t *packet_sB_fin)  {
  struct libnet_ethernet_hdr *eth; 
  struct libnet_ipv4_hdr *iph;
  struct libnet_tcp_hdr *tcph;

  uint8_t *body;
  int ip_len;
  int tcp_len;
  int ip_tcp_hl;
  int tcp_sl;
  int tmp = 0;

  eth = (struct libnet_ethernet_hdr *) packet;

  if (ntohs(eth->ether_type) != ETHERTYPE_IP) 
    return; //not IP, big endian -> little endian
  iph = (struct libnet_ipv4_hdr *)(packet + sizeof(struct libnet_ethernet_hdr)); 
  ip_len = iph->ip_hl * 4;

  if(iph->ip_p != IPPROTO_TCP || iph->ip_v !=4) return; 
  tcph = (struct libnet_tcp_hdr *)(packet + sizeof(struct libnet_ethernet_hdr) + ip_len);
  tcp_len = tcph->th_off*4;
  ip_tcp_hl = ip_len + tcp_len;
  tcp_sl = ntohs(iph->ip_len) - ip_tcp_hl;


  if(tcph != NULL) {  

    body = (uint8_t*)(packet + sizeof(struct libnet_ethernet_hdr) + ip_tcp_hl);
    for(int i = 0; i < 6 ; i++) {
      if(strncmp((const char*)body,http_method[i],strlen(http_method[i])) == 0) {
        //printf("packet dump\n");
    	//dump(packet,header->caplen);
    	memcpy(tmp_packet1, packet, sizeof(tcp_structure));
    	memcpy(tmp_packet2, packet, sizeof(tcp_structure));
    	make_tcp_rst(packet_sF, tmp_packet1, ip_len, tcp_len, tcp_sl, RST_FW);
    	make_tcp_fin(packet_sB_fin, tmp_packet2, ip_len, tcp_len, tcp_sl);

    	//printf("block packet dump\n");
    	//dump(packet_sB,sizeof(struct tcp_structure) + 8);		
    	if(pcap_sendpacket(handle, packet_sB_fin, sizeof(struct tcp_structure) + 7) != 0)
    	  {perror("pcap_sendpacket"); return;}
    	//printf("fin dump\n");
        //dump(packet_sB_fin, sizeof(struct tcp_structure) + strlen(http_msg));

    	if(pcap_sendpacket(handle, packet_sF, sizeof(struct tcp_structure)) != 0)
    	  {perror("pcap_sendpacket"); return;}	
    	//printf("rst dump\n");
  		//dump(packet_sF, sizeof(struct tcp_structure));
    	tmp = 1;
    	break; 
      }
    }
    if (tmp == 0 ) {
      make_tcp_rst(packet_sF, tmp_packet1, ip_len, tcp_len, tcp_sl, RST_FW);
      make_tcp_rst(packet_sB, tmp_packet2, ip_len, tcp_len, tcp_sl, RST_BK);

      if(pcap_sendpacket(handle, packet_sF, sizeof(struct tcp_structure)) != 0)
        {perror("pcap_sendpacket"); free(packet_sF); free(packet_sB); pcap_close(handle); return;}   	

      if(pcap_sendpacket(handle, packet_sB, sizeof(struct tcp_structure)) != 0)
        {perror("pcap_sendpacket"); free(packet_sF); free(packet_sB); pcap_close(handle); return;}
    }
  }  	
}


int main(int argc, char* argv[]) {
  if (argc != 2) {
    usage();
    return -1;
  }

  char* dev = argv[1];
  char errbuf[PCAP_ERRBUF_SIZE];

  int sock = socket(AF_INET, SOCK_DGRAM, 0);
  if (sock < 0) { perror("socket"); return -1;}

  struct ifreq ifr;

  pcap_t* handle = pcap_open_live(dev, BUFSIZ, 1, 1, errbuf);
  if (handle == NULL) {
    fprintf(stderr, "couldn't open device %s: %s\n", dev, errbuf);
    return -1;
  }

  strncpy(ifr.ifr_name, dev, strlen(dev)+1); // copy until '\0' in str
  if(ioctl(sock, SIOCGIFHWADDR, &ifr) < 0) 
    {perror("ioctl"); return -1;} 
  memcpy(attacker_mac, ifr.ifr_hwaddr.sa_data, ETHER_ADDR_LEN);

  uint8_t *packet_sF = (uint8_t *) malloc(sizeof(struct tcp_structure));
  uint8_t *packet_sB = (uint8_t *) malloc(sizeof(struct tcp_structure));
  uint8_t *packet_sB_fin = (uint8_t *) malloc(sizeof(struct tcp_structure) + strlen(http_msg));
  struct tcp_structure *tmp_packet1 = (struct tcp_structure *) malloc(sizeof(struct tcp_structure));
  struct tcp_structure *tmp_packet2 = (struct tcp_structure *) malloc(sizeof(struct tcp_structure));


  while (true) {
    struct pcap_pkthdr* header;
    const uint8_t* packet;
    
    uint32_t res = pcap_next_ex(handle, &header, &packet);
    if (res == 0) continue;
    if (res == -1 || res == -2) {
    	free(packet_sF);
    	free(packet_sB);
    	free(packet_sB_fin);
    	free(tmp_packet1);
    	free(tmp_packet2);
    	pcap_close(handle);
    	return 0;
    }
    find_data(handle, packet, tmp_packet1, tmp_packet2, packet_sF, packet_sB, packet_sB_fin);
    packet_init(tmp_packet1, tmp_packet2, packet_sF, packet_sB, packet_sB_fin);    
  }

  free(packet_sF);
  free(packet_sB);
  free(packet_sB_fin);
  free(tmp_packet1);
  free(tmp_packet2);
  pcap_close(handle);
  return 0;
}

