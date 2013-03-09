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

unsigned short
checksum(void *buf, int len)
{
	int len_left = len;
	int sum = 0;
	unsigned short *word = (unsigned short *)buf;
	unsigned short answer = 0;

	while (len_left > 1)
	{
		sum += *word++;
		len_left -= sizeof(unsigned short);
	}

	if (len_left == 1)
	{
		*(unsigned char *)(&answer) = *(unsigned char *)word;
		sum += answer;
	}

	sum = (sum >> 16) + (sum & 0xFFFF);
	sum += (sum >> 16);
	answer = ~sum;
	return answer;
}

char *generate_synack(struct iphdr *src_iphdr, struct tcphdr *src_tcphdr)
{
#define PACKET_LEN (sizeof(struct iphdr) + sizeof(struct tcphdr))
	char *buf;
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
	iphdr->frag_off = 0;
	iphdr->ttl = PACKET_TTL;
	iphdr->protocol = IPPROTO_TCP;
	iphdr->check = 0;
	iphdr->saddr = src_iphdr->daddr;
	iphdr->daddr = src_iphdr->saddr;

	tcphdr->source = src_tcphdr->dest;
	tcphdr->dest = src_tcphdr->source;
	tcphdr->seq = src_tcphdr->seq;
	tcphdr->ack_seq = src_tcphdr->seq + 1;
	tcphdr->syn = 1;
	tcphdr->ack = 1;
	tcphdr->window = htons(PACKET_WINDOW_SIZE);
	tcphdr->check = 0;
	tcphdr->urg_ptr = 0;

	tcphdr->check = checksum(tcphdr, sizeof(struct tcphdr));
	iphdr->check = checksum(iphdr, PACKET_LEN);

	inet_ntop(AF_INET, &iphdr->daddr, ipstr, INET_ADDRSTRLEN); 
	printf("Sending SYN-ACK to %s:%d\n", ipstr, htons(tcphdr->dest));
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
		char ver_ihl;
		char *buf, *snd_buf;
		int iphdrlen;
		struct tcphdr *tcp_header;
		struct iphdr *ip_header;
		struct sockaddr_in dest;

		recv_bytes = recvfrom(sock, &ver_ihl, 1, MSG_PEEK, NULL, NULL);
		if (recv_bytes <= 0)
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

		recv_bytes = recvfrom(sock, buf, iphdrlen + sizeof(struct tcphdr), 0, NULL, NULL);
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

		dest.sin_family = AF_INET;
		dest.sin_port = 0;
		dest.sin_addr.s_addr = ip_header->saddr;

		snd_buf = generate_synack(ip_header, tcp_header);
		free(buf);
		if (snd_buf == NULL)
		{
			printf("generate_synack() failed\n");
			return -1;
		}

		send_bytes = sendto(sock, snd_buf, PACKET_LEN, 0, (struct sockaddr*)&dest, sizeof(dest));
		if (send_bytes < PACKET_LEN)
		{
			printf("sendto() failed\n");
			return -1;
		}

		free(snd_buf);
	}
}
