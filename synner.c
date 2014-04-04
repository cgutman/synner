#include <stdio.h>
#include <sys/types.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <netinet/ip.h>
#include <netinet/tcp.h>
#include <netpacket/packet.h>
#include <net/ethernet.h>
#include <string.h>
#include <errno.h>
#include <stdlib.h>

#define PACKET_TTL 128
#define PACKET_WINDOW_SIZE 256

struct pseudoheader {
	uint32_t src;
	uint32_t dst;
	uint8_t zero;
	uint8_t proto;
	uint16_t length;
};

unsigned short
checksum(void *buf, int len)
{
	int i;
	unsigned short *data;
	unsigned int sum;

	sum = 0;
	data = (unsigned short *)buf;
	for (i = 0; i < len - 1; i += 2)
	{
		sum += *data;
		data++;
	}

	if (len & 1)
		sum += ((unsigned char*)buf)[i];

	while (sum >> 16) sum = (sum & 0xFFFF) + (sum >> 16);

	return ~sum;
}

unsigned short
tcp_checksum(struct iphdr *iphdr, struct tcphdr *tcphdr)
{
	char buf[sizeof(struct pseudoheader) + sizeof(struct tcphdr)];
	struct pseudoheader *phdr;

	phdr = (struct pseudoheader *)buf;
	phdr->src = iphdr->saddr;
	phdr->dst = iphdr->daddr;
	phdr->zero = 0;
	phdr->proto = IPPROTO_TCP;
	phdr->length = htons(sizeof(struct tcphdr));

	memcpy(&buf[sizeof(struct pseudoheader)], tcphdr, sizeof(struct tcphdr));

	return checksum(buf, sizeof(struct pseudoheader) + sizeof(struct tcphdr));
}

char *generate_tcp(struct iphdr *src_iphdr, struct tcphdr *src_tcphdr, int rst)
{
#define PACKET_LEN (sizeof(struct iphdr) + sizeof(struct tcphdr))
	unsigned char *buf;
	struct iphdr *iphdr;
	struct tcphdr *tcphdr;
	char ipstr[INET_ADDRSTRLEN];

	buf = malloc(PACKET_LEN);
	if (buf == NULL)
		return NULL;

	memset(buf, 0, PACKET_LEN);
	iphdr = (struct iphdr*)buf;
	tcphdr = (struct tcphdr*)&buf[sizeof(struct iphdr)];

	iphdr->version = 0x4;
	iphdr->ihl = 0x5;
	iphdr->tos = 0;
	iphdr->tot_len = htons(PACKET_LEN);
	iphdr->id = 0;
	iphdr->frag_off = htons(IP_DF);
	iphdr->ttl = PACKET_TTL;
	iphdr->protocol = IPPROTO_TCP;
	iphdr->check = 0;
	iphdr->saddr = src_iphdr->daddr;
	iphdr->daddr = src_iphdr->saddr;

	tcphdr->source = src_tcphdr->dest;
	tcphdr->dest = src_tcphdr->source;
	tcphdr->doff = 0x5;
	tcphdr->window = htons(PACKET_WINDOW_SIZE);
	tcphdr->check = 0;
	tcphdr->urg_ptr = 0;

	if (rst)
	{
		tcphdr->rst = 1;
	}
	else
	{
		tcphdr->syn = 1;
		tcphdr->ack = 1;
		tcphdr->ack_seq = htonl(htonl(src_tcphdr->seq) + 1);
		tcphdr->seq = src_tcphdr->seq;
	}

	tcphdr->check = tcp_checksum(iphdr, tcphdr);
	iphdr->check = checksum(iphdr, sizeof(struct iphdr));

	inet_ntop(AF_INET, &iphdr->daddr, ipstr, INET_ADDRSTRLEN);
	printf("SYN from %s on port %d\n", ipstr, htons(tcphdr->source));

	return buf;
}

int main(int argc, char *argv[])
{
	int sock, err;
	int recv_bytes, send_bytes;

	sock = socket(PF_PACKET, SOCK_DGRAM, htons(ETH_P_IP));
	if (sock == -1)
	{
		printf("socket() failed: %d\n", errno);
		return -1;
	}

	for (;;)
	{
		unsigned char ver_ihl;
		unsigned char *buf, *snd_buf;
		int iphdrlen;
		struct tcphdr *tcp_header;
		struct iphdr *ip_header;
		struct sockaddr_ll from;
		socklen_t from_len;

		recv_bytes = recvfrom(sock, &ver_ihl, 1, MSG_PEEK, NULL, NULL);
		if (recv_bytes != 1)
		{
			printf("recv() failed: %d\n", errno);
			return -1;
		}

		if ((ver_ihl & 0xF0) != 0x40)
		{
			/* not IPv4 */
			continue;
		}

		iphdrlen = (ver_ihl & 0x0F) << 2;
		buf = (char*) malloc(iphdrlen + sizeof(struct tcphdr));
		if (buf == NULL)
		{
			printf("malloc() failed\n");
			return -1;
		}

		from_len = sizeof(from);
		recv_bytes = recvfrom(sock, buf, iphdrlen + sizeof(struct tcphdr), 0, (struct sockaddr*)&from, &from_len);
		if (recv_bytes <= 0)
		{
			printf("recv() #2 failed: %d\n", errno);
			free(buf);
			return -1;
		}

		if (recv_bytes < iphdrlen + sizeof(struct tcphdr))
		{
			/* runt packet */
			continue;
		}

		ip_header = (struct iphdr*)buf;
		tcp_header = (struct tcphdr*)&buf[iphdrlen];

		if (ip_header->protocol != IPPROTO_TCP)
		{
			/* not TCP */
			free(buf);
			continue;
		}

		if (!(tcp_header->syn && !tcp_header->ack))
		{
			/* not a TCP connect */
			free(buf);
			continue;
		}

		/* send SYN-ACK */
		snd_buf = generate_tcp(ip_header, tcp_header, 0);
		if (snd_buf == NULL)
		{
			printf("generate_tcp() failed\n");
			free(buf);
			return -1;
		}

		send_bytes = sendto(sock, snd_buf, PACKET_LEN, 0, (struct sockaddr*)&from, sizeof(from));
		if (send_bytes != PACKET_LEN)
		{
			printf("sendto() failed: %d\n", errno);
			free(buf);
			return -1;
		}

		free(snd_buf);

#if 0
		/* send RST */
		snd_buf = generate_tcp(ip_header, tcp_header, 1);
		if (snd_buf == NULL)
		{
			printf("generate_tcp() failed\n");
			free(buf);
			return -1;
		}

		send_bytes = sendto(sock, snd_buf, PACKET_LEN, 0, (struct sockaddr*)&from, sizeof(from));
		if (send_bytes != PACKET_LEN)
		{
			printf("sendto() failed: %d\n", errno);
			free(buf);
			free(snd_buf);
			return -1;
		}

		free(snd_buf);
#endif
		free(buf);
	}
}
