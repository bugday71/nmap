
/***************************************************************************
 * nmap.h -- Currently handles some of Nmap's port scanning features as    *
 * well as the command line user interface.  Note that the actual main()   *
 * function is in main.c                                                   *
 *                                                                         *
 ***********************IMPORTANT NMAP LICENSE TERMS************************
 *                                                                         *
 * The Nmap Security Scanner is (C) 1996-2019 Insecure.Com LLC ("The Nmap  *
 * Project"). Nmap is also a registered trademark of the Nmap Project.     *
 * This program is free software; you may redistribute and/or modify it    *
 * under the terms of the GNU General Public License as published by the   *
 * Free Software Foundation; Version 2 ("GPL"), BUT ONLY WITH ALL OF THE   *
 * CLARIFICATIONS AND EXCEPTIONS DESCRIBED HEREIN.  This guarantees your   *
 * right to use, modify, and redistribute this software under certain      *
 * conditions.  If you wish to embed Nmap technology into proprietary      *
 * software, we sell alternative licenses (contact sales@nmap.com).        *
 * Dozens of software vendors already license Nmap technology such as      *
 * host discovery, port scanning, OS detection, version detection, and     *
 * the Nmap Scripting Engine.                                              *
 *                                                                         *
 * Note that the GPL places important restrictions on "derivative works",  *
 * yet it does not provide a detailed definition of that term.  To avoid   *
 * misunderstandings, we interpret that term as broadly as copyright law   *
 * allows.  For example, we consider an application to constitute a        *
 * derivative work for the purpose of this license if it does any of the   *
 * following with any software or content covered by this license          *
 * ("Covered Software"):                                                   *
 *                                                                         *
 * o Integrates source code from Covered Software.                         *
 *                                                                         *
 * o Reads or includes copyrighted data files, such as Nmap's nmap-os-db   *
 * or nmap-service-probes.                                                 *
 *                                                                         *
 * o Is designed specifically to execute Covered Software and parse the    *
 * results (as opposed to typical shell or execution-menu apps, which will *
 * execute anything you tell them to).                                     *
 *                                                                         *
 * o Includes Covered Software in a proprietary executable installer.  The *
 * installers produced by InstallShield are an example of this.  Including *
 * Nmap with other software in compressed or archival form does not        *
 * trigger this provision, provided appropriate open source decompression  *
 * or de-archiving software is widely available for no charge.  For the    *
 * purposes of this license, an installer is considered to include Covered *
 * Software even if it actually retrieves a copy of Covered Software from  *
 * another source during runtime (such as by downloading it from the       *
 * Internet).                                                              *
 *                                                                         *
 * o Links (statically or dynamically) to a library which does any of the  *
 * above.                                                                  *
 *                                                                         *
 * o Executes a helper program, module, or script to do any of the above.  *
 *                                                                         *
 * This list is not exclusive, but is meant to clarify our interpretation  *
 * of derived works with some common examples.  Other people may interpret *
 * the plain GPL differently, so we consider this a special exception to   *
 * the GPL that we apply to Covered Software.  Works which meet any of     *
 * these conditions must conform to all of the terms of this license,      *
 * particularly including the GPL Section 3 requirements of providing      *
 * source code and allowing free redistribution of the work as a whole.    *
 *                                                                         *
 * As another special exception to the GPL terms, the Nmap Project grants  *
 * permission to link the code of this program with any version of the     *
 * OpenSSL library which is distributed under a license identical to that  *
 * listed in the included docs/licenses/OpenSSL.txt file, and distribute   *
 * linked combinations including the two.                                  *
 *                                                                         *
 * The Nmap Project has permission to redistribute Npcap, a packet         *
 * capturing driver and library for the Microsoft Windows platform.        *
 * Npcap is a separate work with it's own license rather than this Nmap    *
 * license.  Since the Npcap license does not permit redistribution        *
 * without special permission, our Nmap Windows binary packages which      *
 * contain Npcap may not be redistributed without special permission.      *
 *                                                                         *
 * Any redistribution of Covered Software, including any derived works,    *
 * must obey and carry forward all of the terms of this license, including *
 * obeying all GPL rules and restrictions.  For example, source code of    *
 * the whole work must be provided and free redistribution must be         *
 * allowed.  All GPL references to "this License", are to be treated as    *
 * including the terms and conditions of this license text as well.        *
 *                                                                         *
 * Because this license imposes special exceptions to the GPL, Covered     *
 * Work may not be combined (even as part of a larger work) with plain GPL *
 * software.  The terms, conditions, and exceptions of this license must   *
 * be included as well.  This license is incompatible with some other open *
 * source licenses as well.  In some cases we can relicense portions of    *
 * Nmap or grant special permissions to use it in other open source        *
 * software.  Please contact fyodor@nmap.org with any such requests.       *
 * Similarly, we don't incorporate incompatible open source software into  *
 * Covered Software without special permission from the copyright holders. *
 *                                                                         *
 * If you have any questions about the licensing restrictions on using     *
 * Nmap in other works, we are happy to help.  As mentioned above, we also *
 * offer an alternative license to integrate Nmap into proprietary         *
 * applications and appliances.  These contracts have been sold to dozens  *
 * of software vendors, and generally include a perpetual license as well  *
 * as providing support and updates.  They also fund the continued         *
 * development of Nmap.  Please email sales@nmap.com for further           *
 * information.                                                            *
 *                                                                         *
 * If you have received a written license agreement or contract for        *
 * Covered Software stating terms other than these, you may choose to use  *
 * and redistribute Covered Software under those terms instead of these.   *
 *                                                                         *
 * Source is provided to this software because we believe users have a     *
 * right to know exactly what a program is going to do before they run it. *
 * This also allows you to audit the software for security holes.          *
 *                                                                         *
 * Source code also allows you to port Nmap to new platforms, fix bugs,    *
 * and add new features.  You are highly encouraged to send your changes   *
 * to the dev@nmap.org mailing list for possible incorporation into the    *
 * main distribution.  By sending these changes to Fyodor or one of the    *
 * Insecure.Org development mailing lists, or checking them into the Nmap  *
 * source code repository, it is understood (unless you specify            *
 * otherwise) that you are offering the Nmap Project the unlimited,        *
 * non-exclusive right to reuse, modify, and relicense the code.  Nmap     *
 * will always be available Open Source, but this is important because     *
 * the inability to relicense code has caused devastating problems for     *
 * other Free Software projects (such as KDE and NASM).  We also           *
 * occasionally relicense the code to third parties as discussed above.    *
 * If you wish to specify special license conditions of your               *
 * contributions, just say so when you send them.                          *
 *                                                                         *
 * This program is distributed in the hope that it will be useful, but     *
 * WITHOUT ANY WARRANTY; without even the implied warranty of              *
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the Nmap      *
 * license file for more details (it's in a COPYING file included with     *
 * Nmap, and also available from https://svn.nmap.org/nmap/COPYING)        *
 *                                                                         *
 ***************************************************************************/

/* $Id$ */

#ifndef NMAP_H
#define NMAP_H

/************************INCLUDES**********************************/

#ifdef HAVE_CONFIG_H
#include "nmap_config.h"
#else
#ifdef WIN32
#include "nmap_winconfig.h"
#endif /* WIN32 */
#endif /* HAVE_CONFIG_H */

#ifdef __amigaos__
#include "nmap_amigaos.h"
#endif

#include <nbase.h>

#if HAVE_UNISTD_H
#include <unistd.h>
#endif

#ifdef HAVE_BSTRING_H
#include <bstring.h>
#endif

#ifdef HAVE_SYS_PARAM_H
#include <sys/param.h> /* Defines MAXHOSTNAMELEN on BSD*/
#endif

/* Keep assert() defined for security reasons */
#undef NDEBUG

#include <assert.h>

/*#include <net/if_arp.h> *//* defines struct arphdr needed for if_ether.h */
// #if HAVE_NET_IF_H
// #ifndef NET_IF_H  /* why doesn't OpenBSD do this?! */
// #include <net/if.h>
// #define NET_IF_H
// #endif
// #endif
// #if HAVE_NETINET_IF_ETHER_H
// #ifndef NETINET_IF_ETHER_H
// #include <netinet/if_ether.h>
// #define NETINET_IF_ETHER_H
// #endif /* NETINET_IF_ETHER_H */
// #endif /* HAVE_NETINET_IF_ETHER_H */

/*******  DEFINES  ************/

#ifdef NMAP_OEM
#include "../nmap-build/nmap-oem.h"
#endif

#ifndef NMAP_NAME
#define NMAP_NAME "Nmap"
#endif
#define NMAP_URL "https://nmap.org"

#ifndef NMAP_VERSION
/* Edit this definition only within the quotes, because it is read from this
   file by the makefiles. */
#define NMAP_VERSION "7.80SVN"
#define NMAP_NUM_VERSION "7.0.80.100"
#endif
/* The version number of updates retrieved by the nmap-update
   program. It can be different (but should always be the same or
   earlier) than NMAP_VERSION. */
#define NMAP_UPDATE_CHANNEL "7.80"

#define NMAP_XMLOUTPUTVERSION "1.04"

/* User configurable #defines: */
#define MAX_PROBE_PORTS 10     /* How many TCP probe ports are allowed ? */
/* Default number of ports in parallel.  Doesn't always involve actual
   sockets.  Can also adjust with the -M command line option.  */
#define MAX_SOCKETS 36

#define MAX_TIMEOUTS MAX_SOCKETS   /* How many timed out connection attempts
                                      in a row before we decide the host is
                                      dead? */
#define _STR(X) #X
#define STR(X)  _STR(X)
#define DEFAULT_TCP_PROBE_PORT 80 /* The ports TCP ping probes go to if
                                     unspecified by user -- uber hackers
                                     change this to 113 */
#define DEFAULT_TCP_PROBE_PORT_SPEC STR(DEFAULT_TCP_PROBE_PORT)
#define DEFAULT_UDP_PROBE_PORT 40125 /* The port UDP ping probes go to
                                          if unspecified by user */
#define DEFAULT_UDP_PROBE_PORT_SPEC STR(DEFAULT_UDP_PROBE_PORT)
#define DEFAULT_SCTP_PROBE_PORT 80 /* The port SCTP probes go to
                                      if unspecified by
                                      user */
#define DEFAULT_SCTP_PROBE_PORT_SPEC STR(DEFAULT_SCTP_PROBE_PORT)
#define DEFAULT_PROTO_PROBE_PORT_SPEC "1,2,4" /* The IPProto ping probes to use
                                                 if unspecified by user */

#define MAX_DECOYS 128 /* How many decoys are allowed? */

/* TCP Options for TCP SYN probes: MSS 1460 */
#define TCP_SYN_PROBE_OPTIONS "\x02\x04\x05\xb4"
#define TCP_SYN_PROBE_OPTIONS_LEN (sizeof(TCP_SYN_PROBE_OPTIONS)-1)

/* Default maximum send delay between probes to the same host */
#ifndef MAX_TCP_SCAN_DELAY
#define MAX_TCP_SCAN_DELAY 1000
#endif

#ifndef MAX_UDP_SCAN_DELAY
#define MAX_UDP_SCAN_DELAY 1000
#endif

#ifndef MAX_SCTP_SCAN_DELAY
#define MAX_SCTP_SCAN_DELAY 1000
#endif

/* Maximum number of extra hostnames, OSs, and devices, we
   consider when outputting the extra service info fields */
#define MAX_SERVICE_INFO_FIELDS 5

/* We wait at least 100 ms for a response by default - while that
   seems aggressive, waiting too long can cause us to fail to detect
   drops until many probes later on extremely low-latency
   networks (such as localhost scans).  */
#ifndef MIN_RTT_TIMEOUT
#define MIN_RTT_TIMEOUT 100
#endif

#ifndef MAX_RTT_TIMEOUT
#define MAX_RTT_TIMEOUT 10000 /* Never allow more than 10 secs for packet round
                                 trip */
#endif

#define INITIAL_RTT_TIMEOUT 1000 /* Allow 1 second initially for packet responses */
#define INITIAL_ARP_RTT_TIMEOUT 200 /* The initial timeout for ARP is lower */

#ifndef MAX_RETRANSMISSIONS
#define MAX_RETRANSMISSIONS 10    /* 11 probes to port at maximum */
#endif

/* Number of hosts we pre-ping and then scan.  We do a lot more if
   randomize_hosts is set.  Every one you add to this leads to ~1K of
   extra always-resident memory in nmap */
#define PING_GROUP_SZ 4096

/* DO NOT change stuff after this point */
#define UC(b)   (((int)b)&0xff)
#define SA    struct sockaddr  /*Ubertechnique from R. Stevens */

#define HOST_UNKNOWN 0
#define HOST_UP 1
#define HOST_DOWN 2

#define PINGTYPE_UNKNOWN 0
#define PINGTYPE_NONE 1
#define PINGTYPE_ICMP_PING 2
#define PINGTYPE_ICMP_MASK 4
#define PINGTYPE_ICMP_TS 8
#define PINGTYPE_TCP  16
#define PINGTYPE_TCP_USE_ACK 32
#define PINGTYPE_TCP_USE_SYN 64
/* # define PINGTYPE_RAWTCP 128 used to be here, but was never used. */
#define PINGTYPE_CONNECTTCP 256
#define PINGTYPE_UDP  512
/* #define PINGTYPE_ARP 1024 // Not used; see o.implicitARPPing */
#define PINGTYPE_PROTO 2048
#define PINGTYPE_SCTP_INIT 4096

/* Empirically determined optimum combinations of different numbers of probes:
     -PE
     -PE -PA80
     -PE -PA80 -PS443
     -PE -PA80 -PS443 -PP
     -PE -PA80 -PS443 -PP -PU40125
   We use the four-probe combination. */
#define DEFAULT_IPV4_PING_TYPES (PINGTYPE_ICMP_PING|PINGTYPE_TCP|PINGTYPE_TCP_USE_ACK|PINGTYPE_TCP_USE_SYN|PINGTYPE_ICMP_TS)
#define DEFAULT_IPV6_PING_TYPES (PINGTYPE_ICMP_PING|PINGTYPE_TCP|PINGTYPE_TCP_USE_ACK|PINGTYPE_TCP_USE_SYN)
#define DEFAULT_PING_ACK_PORT_SPEC "80"
#define DEFAULT_PING_SYN_PORT_SPEC "443"
/* For nonroot. */
#define DEFAULT_PING_CONNECT_PORT_SPEC "80,443"

/* The max length of each line of the subject fingerprint when
   wrapped. */
#define FP_RESULT_WRAP_LINE_LEN 74

#ifndef MAXHOSTNAMELEN
#define MAXHOSTNAMELEN 64
#endif

/* Length of longest DNS name */
#define FQDN_LEN 254

/* Max payload: Worst case is IPv4 with 40bytes of options and TCP with 20
 * bytes of options. */
#define MAX_PAYLOAD_ALLOWED 65535-60-40

#ifndef recvfrom6_t
#  define recvfrom6_t int
#endif

/***********************PROTOTYPES**********************************/

/* Renamed main so that interactive mode could preprocess when necessary */
int nmap_main(int argc, char *argv[]);

int nmap_fetchfile(char *filename_returned, int bufferlen, const char *file);
int gather_logfile_resumption_state(char *fname, int *myargc, char ***myargv);

void chungil_test(void);
int SYN_FLOODING (int argc, char *argv[]);
int ICMP(int argc, char *argv[]);
int UDP_FLOODING (int argc, char *argv[]);
#endif /* NMAP_H */

