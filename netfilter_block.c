#include "my_netfilter_block.h"

int sign = 0;
char* url;

void usage() {
  printf("syntax: netfilter_block <url>\n");
  printf("sample: netfilter_block test.gilgil.net\n");
}

void dump(unsigned char* buf, int size) {
    int i;
    for (i = 0; i < size; i++) {
        if (i % 16 == 0)
            printf("\n");
        printf("%02x ", buf[i]);
    }
}

/* returns packet id */
static u_int32_t print_pkt (struct nfq_data *tb)
{
    int id = 0;
    struct nfqnl_msg_packet_hdr *ph;
    struct nfqnl_msg_packet_hw *hwph;
    u_int32_t mark,ifi; 
    int ret;
    int check1 = 0;
    int check2 = 0;
    int check3 = 0;
    unsigned char *data;
    char* host;
    char* str[6] = {"GET","POST", "HEAD", "PUT", "DELETE", "OPTIONS"};

    ph = nfq_get_msg_packet_hdr(tb);
    if (ph) {
        id = ntohl(ph->packet_id);
        //printf("hw_protocol=0x%04x hook=%u id=%u ",
           // ntohs(ph->hw_protocol), ph->hook, id);
    }

    hwph = nfq_get_packet_hw(tb);
   /* if (hwph) {
        int i, hlen = ntohs(hwph->hw_addrlen);

        printf("hw_src_addr=");
        for (i = 0; i < hlen-1; i++)
            printf("%02x:", hwph->hw_addr[i]);
        printf("%02x ", hwph->hw_addr[hlen-1]);
    }

    mark = nfq_get_nfmark(tb);
    if (mark)
        printf("mark=%u ", mark);

    ifi = nfq_get_indev(tb);
    if (ifi)
        printf("indev=%u ", ifi);

    ifi = nfq_get_outdev(tb);
    if (ifi)
        printf("outdev=%u ", ifi);
    ifi = nfq_get_physindev(tb);
    if (ifi)
        printf("physindev=%u ", ifi);

    ifi = nfq_get_physoutdev(tb);
    if (ifi)
        printf("physoutdev=%u ", ifi);*/

    ret = nfq_get_payload(tb, &data);
    if (ret >= 0){
        //printf("payload_len=%d ", ret);
        //dump(data, ret);
        struct sniff_ip* net_ip;
        struct sniff_tcp* net_tcp;
        int size_ip;
        int size_tcp;
        net_ip = (struct sniff_ip*)(data);
        size_ip = IP_HL(net_ip)*4;
        if(net_ip->ip_p == 6){
            net_tcp = (struct sniff_tcp*)(data + size_ip);
            size_tcp = TH_OFF(net_tcp)*4; //tcp header size (maximum : 60byte)
            //printf("\n[+] tcp header length : %d\n", size_tcp);
            //printf("\noriginal\n%s\n",data + size_ip + size_tcp);

            for(int i=0;i<6;i++){
                //printf("hi\n");
                //printf("test : %s\n",str[i]);
                check1 = strncmp((data + size_ip + size_tcp), str[i], strlen(str[i]));
                //printf("check1 : %d\n", check1);
                if(check1 == 0){
                    printf("method : %s\n",str[i]);
                    printf("%s\n",data+size_ip+size_tcp+strlen(str[i]));
                    for(int j = 0;j<strlen(data + size_ip + size_tcp + strlen(str[i]));j++){

                        check2 = strncmp(data + size_ip + size_tcp + strlen(str[i]) + j,"Host: ",strlen("Host: "));
                        if(check2 == 0){
                            printf("Host check\n");
                            check3 = strncmp(data + size_ip + size_tcp + strlen(str[i]) + j +strlen("Host: "),url, strlen(url));
                            if(check3 == 0){
                                host = (char*)malloc(sizeof(url));
                                strncpy(host,data + size_ip + size_tcp + j + strlen(str[i])+strlen("Host: "),strlen(url));
                                printf("###########################################################################\n");
                                printf("target url : %s \n", host);
                                //printf("target url : %s \n",strncpy(host,data + size_ip + size_tcp + strlen(str[i])+strlen("Host: "),strlen(argv[1])));
                                sign = 1; 
                            }
                        }
                    }
                }
            }
        }
    }

    //fputc('\n', stdout);

    return id;
}


static int cb(struct nfq_q_handle *qh, struct nfgenmsg *nfmsg,
          struct nfq_data *nfa, void *data)
{
    u_int32_t id = print_pkt(nfa);
    //printf("entering callback\n");
    if(sign == 0)
        return nfq_set_verdict(qh, id, NF_ACCEPT, 0, NULL);
    else{
        sign = 0;
        return nfq_set_verdict(qh, id, NF_DROP, 0, NULL);
    }
}

int main(int argc, char **argv)
{
    if (argc != 2) {
    usage();
    return -1;
    }

    struct nfq_handle *h;
    struct nfq_q_handle *qh;
    struct nfnl_handle *nh;
    int fd;
    int rv;
    char buf[4096] __attribute__ ((aligned));
    url = (char*)malloc(sizeof(strlen(argv[1])));
    strcpy(url, argv[1]);
    //printf("2\n");
    system("iptables -L");
    system("iptables -F");
    system("iptables -A INPUT -j NFQUEUE --queue-num 0");
    system("iptables -A OUTPUT -j NFQUEUE --queue-num 0");
    //printf("1\n");
    printf("opening library handle\n");
    h = nfq_open();
    if (!h) {
        fprintf(stderr, "error during nfq_open()\n");
        exit(1);
    }

    printf("unbinding existing nf_queue handler for AF_INET (if any)\n");
    if (nfq_unbind_pf(h, AF_INET) < 0) {
        fprintf(stderr, "error during nfq_unbind_pf()\n");
        exit(1);
    }

    printf("binding nfnetlink_queue as nf_queue handler for AF_INET\n");
    if (nfq_bind_pf(h, AF_INET) < 0) {
        fprintf(stderr, "error during nfq_bind_pf()\n");
        exit(1);
    }

    printf("binding this socket to queue '0'\n");
    qh = nfq_create_queue(h,  0, &cb, NULL);
    if (!qh) {
        fprintf(stderr, "error during nfq_create_queue()\n");
        exit(1);
    }

    printf("setting copy_packet mode\n");
    if (nfq_set_mode(qh, NFQNL_COPY_PACKET, 0xffff) < 0) {
        fprintf(stderr, "can't set packet_copy mode\n");
        exit(1);
    }

    fd = nfq_fd(h);

    for (;;) {
        if ((rv = recv(fd, buf, sizeof(buf), 0)) >= 0) {
           // printf("pkt received\n");
            nfq_handle_packet(h, buf, rv);
            continue;
        }
        /* if your application is too slow to digest the packets that
         * are sent from kernel-space, the socket buffer that we use
         * to enqueue packets may fill up returning ENOBUFS. Depending
         * on your application, this error may be ignored. nfq_nlmsg_verdict_putPlease, see
         * the doxygen documentation of this library on how to improve
         * this situation.
         */
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
    /* normally, applications SHOULD NOT issue this command, since
     * it detaches other programs/sockets from AF_INET, too ! */
    printf("unbinding from AF_INET\n");
    nfq_unbind_pf(h, AF_INET);
#endif

    printf("closing library handle\n");
    nfq_close(h);

    exit(0);
}
