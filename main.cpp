#include <stdio.h>
#include <stdlib.h>					//strncmp
#include <string>					//std::string
#include <string.h>
#include <iostream>
#include <unistd.h>
#include <netinet/in.h>
#include <linux/types.h>
#include <linux/netfilter.h>
#include <errno.h>
#include <arpa/inet.h>
#include <netinet/in_systm.h>
#include <libnet/libnet-macros.h>
#define LIBNET_LIL_ENDIAN 1
#include <libnet/libnet-headers.h>
#include <libnetfilter_queue/libnetfilter_queue.h>
#include <map>
#include <checksum.h>
#include <flow.h>

using namespace std;

uint16_t flag = 0;
uint32_t new_data_len;
unsigned char* new_data;

string from_s, to_s;
map<flow, uint32_t> flow_check;

static u_int32_t print_pkt (struct nfq_data *tb)
{
	int id = 0;
	struct nfqnl_msg_packet_hdr *ph;
	int ret;
	unsigned char *data;

	ph = nfq_get_msg_packet_hdr(tb);
    	if (ph) {
        	id = ntohl(ph->packet_id);
    	}

	ret = nfq_get_payload(tb, &data);
	if(ret >= 0) {
		new_data = data;
		struct libnet_ipv4_hdr* ipH = (struct libnet_ipv4_hdr *) data;
		struct flow check;

		memcpy(&check.ip_dst, &ipH->ip_dst, sizeof(ipH->ip_dst));
		memcpy(&check.ip_src, &ipH->ip_src, sizeof(ipH->ip_src));

		if(ipH->ip_p == 6){
			data += (ipH->ip_hl)*4;
			struct libnet_tcp_hdr* tcpH = (struct libnet_tcp_hdr *) data;
			u_int16_t len = (ipH->ip_hl * 4)+(tcpH->th_off * 4);

			flag = 0;
			if(htons(ipH->ip_len) > len) {
				data += (tcpH->th_off * 4);
				string s_data;
				s_data = (char *) data;

				map<flow, uint32_t>::iterator iter, r_iter;
				iter = flow_check.find(check);
				if(s_data.find(from_s) != string::npos){
					size_t pos = 0;
					while((pos = s_data.find(from_s, pos)) != string::npos){
						s_data.replace(pos, from_s.length(), to_s);
						pos += to_s.length();
					}
					if(iter != flow_check.end()) tcpH->th_seq += htonl(iter->second);
					flow_check[check] += s_data.length() - (ret - len);

					memcpy((new_data + len), s_data.c_str(), s_data.length());
					calTCPChecksum(new_data , len + s_data.length());
					new_data_len = len + s_data.length();
					flag = 1;
				}

				check.reverse_flow();
				r_iter = flow_check.find(check);
				if(r_iter != flow_check.end()) {
					tcpH->th_ack -= htonl(r_iter->second);
					calTCPChecksum(new_data, ret);
					new_data_len = ret;
					flag = 1;
				}
			}

		}
	}

	return id;
}

static int cb(struct nfq_q_handle *qh, struct nfgenmsg *nfmsg,
          struct nfq_data *nfa, void *data)
{
    u_int32_t id = print_pkt(nfa);

    if(flag == 0)
    	return nfq_set_verdict(qh, id, NF_ACCEPT, 0, NULL);
    else {
	cout << "change!" << endl;
	return nfq_set_verdict(qh, id, NF_ACCEPT, new_data_len, new_data);
    }
}

int main(int argc, char **argv)
{
    if(argc != 3){
	printf("Not enough argv\n");
	printf("ex) ./tcp_data_len_change <from string> <to string>\n");
	exit(1);
    }

    from_s = argv[1];
    to_s = argv[2];

    struct nfq_handle *h;
    struct nfq_q_handle *qh;
    struct nfnl_handle *nh;
    int fd;
    int rv;
    char buf[4096] __attribute__ ((aligned));

    printf("opening library handle\n");
    h = nfq_open();
    if (!h) {
        printf("error during nfq_open()\n");
        exit(1);
    }

    printf("unbinding existing nf_queue handler for AF_INET (if any)\n");
    if (nfq_unbind_pf(h, AF_INET) < 0) {
        printf("error during nfq_unbind_pf()\n");
        exit(1);
    }

    printf("binding nfnetlink_queue as nf_queue handler for AF_INET\n");
    if (nfq_bind_pf(h, AF_INET) < 0) {
        printf("error during nfq_bind_pf()\n");
        exit(1);
    }

    printf("binding this socket to queue '0'\n");

    qh = nfq_create_queue(h,  0, &cb, NULL);					// Queue create
    if (!qh) {
        printf("error during nfq_create_queue()\n");
        exit(1);
    }

    printf("setting copy_packet mode\n");
    if (nfq_set_mode(qh, NFQNL_COPY_PACKET, 0xffff) < 0) {
        printf("can't set packet_copy mode\n");
        exit(1);
    }

    fd = nfq_fd(h);

    for (;;) {
        if ((rv = recv(fd, buf, sizeof(buf), 0)) >= 0) {
 //           printf("pkt received\n");
            nfq_handle_packet(h, buf, rv);
            continue;
        }
        if (rv < 0 && errno == ENOBUFS) {
            printf("losing packets!\n");
            continue;
        }
        perror("recv failed");
        break;
    }

    printf("unbinding from queue 0\n");
    nfq_destroy_queue(qh);

#ifdef INSANE
    printf("unbinding from AF_INET\n");
    nfq_unbind_pf(h, AF_INET);
#endif

    printf("closing library handle\n");
    nfq_close(h);

    exit(0);
}
