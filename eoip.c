/*
    file:   eoip.c
    Authors: Denys Fedoryshchenko aka NuclearCat <nuclearcat (at) nuclearcat.com>

    This program is free software: you can redistribute it and/or modify
    it under the terms of the GNU General Public License as published by
    the Free Software Foundation, either version 3 of the License, or
    (at your option) any later version.

    This program is distributed in the hope that it will be useful,
    but WITHOUT ANY WARRANTY; without even the implied warranty of
    MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
    GNU General Public License for more details.

    You should have received a copy of the GNU General Public License
    along with this program.  If not, see <http://www.gnu.org/licenses/>.*
*/
#ifndef __UCLIBC__
#define _GNU_SOURCE 
#endif
#include <stdio.h>
#include <stdlib.h>
#include <errno.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <netinet/if_ether.h>
#include <net/ethernet.h>
#include <netinet/ether.h>
#include <linux/if_tun.h>
#include <netinet/ip.h>
#include <netinet/tcp.h>
#include <string.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <sys/ioctl.h>
#include <fcntl.h>
#include <net/if.h>
#include <poll.h>
#include <unistd.h>
#include <err.h>
#include <signal.h>
#include <assert.h>
#include <pthread.h>
#include <limits.h>
#include <asm/byteorder.h>
#include "minIni.h"
#include "config.h"

/* In theory maximum payload that can be handled is 65536, but if we use vectorized
   code with preallocated buffers - it is waste of space, especially for embedded setup.
   So if you want oversized packets - increase MAXPAYLOAD up to 65536 (or a bit less)
   If your choice performance - more vectors, to avoid expensive context switches
   TODO: readv, writev
*/

#define LINUX_THREAD_STACK_SIZE (PTHREAD_STACK_MIN * 2)
#ifdef __UCLIBC__
#define MAXPAYLOAD (2048)
#define PREALLOCBUF 4
#define MAXRINGBUF  4
#else
#define MAXPAYLOAD (2048)
#define PREALLOCBUF 32
#define MAXRINGBUF  64
#endif

#define sizearray(a)  (sizeof(a) / sizeof((a)[0]))

typedef struct {
    struct sockaddr_in	daddr;
    int			id;
    int			fd;
    struct ifreq	ifr;
    char		name[65];
    int			dynamic;
#ifndef __UCLIBC__
    int			cpu;
#endif
}  Tunnel;

struct thr_rx {
    int 		raw_socket;
};

struct thr_tx {
    int			raw_socket;
#ifndef __UCLIBC__
    int			cpu;
#endif
    Tunnel		*tunnel;
};

struct gre_hdr {
    uint32_t		header;
    uint16_t		payload_size;
    uint16_t		tunnel_id;
} __attribute__ ((__packed__));

int numtunnels;
Tunnel *tunnels;
pthread_mutex_t mutex1 = PTHREAD_MUTEX_INITIALIZER;

static void term_handler(int s)
{
  int		fd, i;
  Tunnel	*tunnel;

  if ((fd = socket(AF_INET, SOCK_DGRAM, 0)) < 0) {
    perror("socket() failed");
    exit(-1);
  }
  for(i=0; i<numtunnels; i++) {
    tunnel = tunnels + i;
    close(tunnel->fd);
  }

  close(fd);
  exit(0);
}

static int open_tun(Tunnel *tunnel) {
    int fd;

    if ((fd = socket(AF_INET, SOCK_DGRAM, 0)) < 0) {
      perror("socket() failed");
      return 1;
    }
    if ( (tunnel->fd = open("/dev/net/tun", O_RDWR)) < 0)
    {
	perror("open_tun: /dev/net/tun error");
	return 1;
    }

    memset(&tunnel->ifr, 0x0, sizeof(tunnel->ifr));

    tunnel->ifr.ifr_flags = IFF_TAP|IFF_NO_PI;
    if (tunnel->name[0] != 0)
	strncpy(tunnel->ifr.ifr_name, tunnel->name,IFNAMSIZ);
    else
	strncpy(tunnel->ifr.ifr_name, "eoip%d",IFNAMSIZ);

    if (ioctl(tunnel->fd, TUNSETIFF, (void *)&tunnel->ifr) < 0) {
        perror("ioctl-1");
        close(fd);
        return 1;
    }

    tunnel->ifr.ifr_flags |= IFF_UP;
    tunnel->ifr.ifr_flags |= IFF_RUNNING;

    if (ioctl(fd, SIOCSIFFLAGS, (void *)&tunnel->ifr) < 0) {
        perror("ioctl-2");
        close(fd);
        return 1;
    }
    close(fd);
    return 0;
}

static void *thr_rx(void *threadid)
{
    struct sockaddr_in saddr[MAXRINGBUF];
    struct thr_rx *thr_rx_data = (struct thr_rx*)threadid;
    unsigned char *rxringbufptr[MAXRINGBUF];
    unsigned char *rxringbuffer;
    unsigned char *ptr;
    struct gre_hdr *ghdr;
    int i, ret, rxringbufused = 0, rxringbufconsumed, rxringpayload[MAXRINGBUF];
    int saddr_size = sizeof(saddr[0]);
    int raw_socket = thr_rx_data->raw_socket;
    Tunnel *tunnel;
    fd_set rfds;

#ifndef __UCLIBC__
    cpu_set_t cpuset;
    pthread_t thread = pthread_self();
    int cpu=0;

    CPU_ZERO(&cpuset);
    CPU_SET(cpu, &cpuset);

    ret = pthread_setaffinity_np(thread, sizeof(cpu_set_t), &cpuset);
    if (ret)
	printf("Affinity error %d\n", ret);
    else
	printf("RX thread set to cpu %d\n", cpu);
#endif

    rxringbuffer = malloc(MAXPAYLOAD*MAXRINGBUF);
    if (!rxringbuffer) {
	perror("malloc()");
	exit(1);
    }
    /* Temporary code*/
    for (i=0;i<MAXRINGBUF;i++) {
	rxringbufptr[i] = rxringbuffer + (MAXPAYLOAD * i);
    }

    while(1) {
	    FD_ZERO(&rfds);
	    FD_SET(raw_socket, &rfds);
	    ret = select(raw_socket+1, &rfds, NULL, NULL, NULL);
	    assert(rxringbufused == 0);
	    while (rxringbufused < MAXRINGBUF) {
		rxringpayload[rxringbufused] = recvfrom(raw_socket, rxringbufptr[rxringbufused], MAXPAYLOAD, 0, &saddr[rxringbufused], &saddr_size);
		if (rxringpayload[rxringbufused] < 0)
		    break;
		if (rxringpayload[rxringbufused] >= 28)
		    rxringbufused++;
	    }

	    if (!rxringbufused)
		continue;

	    rxringbufconsumed = 0;
	    do {
		ptr = rxringbufptr[rxringbufconsumed];
		ghdr = (struct gre_hdr*)(ptr+20);
		ret = 0;
		/* TODO: Optimize search of tunnel id */
		for(i=0; i<numtunnels; i++)
		{
		    tunnel=tunnels + i;
		    if ((uint16_t)(__le16_to_cpu(ghdr->tunnel_id)) == (uint16_t) tunnel->id)
		    {
			/* This is a dynamic tunnel */
			if (tunnel->dynamic) {
			    if (saddr[rxringbufconsumed].sin_addr.s_addr != tunnel->daddr.sin_addr.s_addr) {
				/* Updating tunnel */
				pthread_mutex_lock(&mutex1);
				tunnel->daddr.sin_addr.s_addr = saddr[rxringbufconsumed].sin_addr.s_addr;
				pthread_mutex_unlock(&mutex1);
			    }
			}
			ret = write(tunnel->fd, ptr+28, rxringpayload[rxringbufconsumed] - 28);
		        break;
		    }
		}
		rxringbufconsumed++;
	    } while (rxringbufconsumed < rxringbufused);
	    rxringbufused -= rxringbufconsumed;
	    if (rxringbufused) {
		memmove(&rxringpayload[0], &rxringpayload[rxringbufconsumed], rxringbufused);
	    }
    }
    return(NULL);
}

static void *thr_tx(void *threadid)
{
    struct thr_tx *thr_tx_data = (struct thr_tx*)threadid;
    struct sockaddr_in daddr;
    Tunnel *tunnel = thr_tx_data->tunnel;
    int fd = tunnel->fd;
    int raw_socket = thr_tx_data->raw_socket;
    int payloadsz, ret;
    unsigned char *ip = malloc(MAXPAYLOAD + 8); /* 8-byte header of GRE, rest is payload */
    struct gre_hdr *ghdr = (struct gre_hdr*)ip;
    unsigned char *payloadptr = ip + 8;
    fd_set rfds;
#ifndef __UCLIBC__
    int cpu = thr_tx_data->cpu;
    cpu_set_t cpuset;
    pthread_t thread = pthread_self();

    CPU_ZERO(&cpuset);
    CPU_SET(cpu, &cpuset);

    ret = pthread_setaffinity_np(thread, sizeof(cpu_set_t), &cpuset);
    if (ret)
	printf("Affinity error %d\n", ret);
    else
	printf("TX thread(ID %d) set to cpu %d\n", tunnel->id, cpu);
#endif
    memset(ip, 0x0, 20);

    ghdr->header = __cpu_to_be32(0x20016400);
    while(1) {
        FD_ZERO(&rfds);
        FD_SET(fd, &rfds);
        ret = select(fd+1, &rfds, NULL, NULL, NULL);

	payloadsz = read(fd, payloadptr, MAXPAYLOAD);
	if (payloadsz < 0)
	    continue;
	ghdr->payload_size = __cpu_to_be16((uint16_t)payloadsz);
	ghdr->tunnel_id = __cpu_to_le16((uint16_t)tunnel->id);
	if (tunnel->dynamic)
	    pthread_mutex_lock(&mutex1);
	if(sendto(raw_socket, ip, payloadsz+8, 0, (struct sockaddr *)&tunnel->daddr, (socklen_t)sizeof(daddr)) < 0)
	    perror("send() err");
	if (tunnel->dynamic)
	    pthread_mutex_unlock(&mutex1);
    }
    return(NULL);
}

int main(int argc, char **argv)
{
    struct thr_rx thr_rx_data;
    struct thr_tx *thr_tx_data;
    int ret, i, sn, rc, optval = 262144;
    Tunnel *tunnel;
    struct sigaction sa;
    struct stat mystat;
    char section[IFNAMSIZ];
    char strbuf[256];
    char *configname;
    char defaultcfgname[] = "/etc/eoip.cfg";
    pthread_t *threads;
    pthread_attr_t attr;
    void *status;
    FILE *mfd;
    char *pidfile;


    thr_rx_data.raw_socket = socket(PF_INET, SOCK_RAW, 47);
    if (thr_rx_data.raw_socket == -1) {

	if (errno == EPERM) {
	    printf("You need root privileges or CAP_NET_RAW capability to run this program\n");
	} else {
	    perror("raw socket()");
	}
	return(1);
    }
    if(setsockopt (thr_rx_data.raw_socket, SOL_SOCKET, SO_RCVBUF, &optval, sizeof (optval)))
	perror("setsockopt(RCVBUF)");
    if(setsockopt (thr_rx_data.raw_socket, SOL_SOCKET, SO_SNDBUF, &optval, sizeof (optval)))
	perror("setsockopt(SNDBUF)");

    if (argc == 3) {
	struct sockaddr_in serv_addr;
	serv_addr.sin_family = AF_INET;
	if (!inet_pton(AF_INET, argv[2], (struct in_addr *)&serv_addr.sin_addr.s_addr)) {
	    perror("bind address invalid");
	    exit(-1);
	}
	serv_addr.sin_port = 0;
	if (bind(thr_rx_data.raw_socket, (struct sockaddr *) &serv_addr,
		sizeof(serv_addr)) < 0)
	{
	    perror("bind error");
	    exit(-1);
	}
    }

    if (argc == 1)
	configname = defaultcfgname;
    else
	configname = argv[1];

    if (stat(configname, &mystat)) {
	    printf("Mikrotik-compatible EoIP %s\n",PACKAGE_VERSION);
	    printf("(c) Denys Fedoryshchenko <nuclearcat@nuclearcat.com>\n");
	    printf("%s [configfile [bindip]]\n",argv[0]);
	    exit(-1);
    }

    for (sn = 0; ini_getsection(sn, section, sizearray(section), configname) > 0; sn++) {
	numtunnels++;
     }

    tunnels = malloc(sizeof(Tunnel)*numtunnels);
    if (tunnels == NULL) {
	perror("malloc() failed");
	exit(-1);
    }
    memset(tunnels, 0x0, sizeof(Tunnel) * numtunnels);

    for (sn = 0; ini_getsection(sn, section, sizearray(section), configname) > 0; sn++) {
	tunnel = tunnels + sn;
	printf("Creating tunnel: %s num %d\n", section,sn);
	if (strlen(section)>64) {
	    printf("Name of tunnel need to be shorter than 64 symbols\n");
	    exit(-1);
	}
	strncpy(tunnel->name, section, 64);
	tunnel->daddr.sin_family = AF_INET;
	tunnel->daddr.sin_port = 0;
	tunnel->dynamic = 0;
	if (ini_gets(section, "dst", "0.0.0.0", strbuf, sizeof(strbuf), configname) < 1) {
	    printf("Destination for %s not correct\n", section);
	} else {
	    printf("Destination for %s: %s\n", section, strbuf);
	}

	if (!inet_pton(AF_INET, strbuf, (struct in_addr *)&tunnel->daddr.sin_addr.s_addr))
	{
	    warn("Destination \"%s\" is not correct\n", strbuf);
	    exit(-1);
	}
	memset(tunnel->daddr.sin_zero, 0x0, sizeof(tunnel->daddr.sin_zero));
	tunnel->id = (int)ini_getl(section, "id", 0, configname);
	/* TODO: What is max value of tunnel? */
	if (tunnel->id == 0 || tunnel->id > 65536) {
	    warn("ID of \"%d\" is not correct\n", tunnel->id);
	    exit(-1);
	}
	tunnel->dynamic = (int)ini_getl(section, "dynamic", 0, configname);
     }

    if (thr_rx_data.raw_socket == -1) {
	perror("raw socket error():");
	exit(-1);
    }
    fcntl(thr_rx_data.raw_socket, F_SETFL, O_NONBLOCK);

    for(i=0;i<numtunnels;i++)
    {
      tunnel = tunnels + i;
      if (open_tun(tunnel)) {
        exit(-1);
      }
    }

    memset(&sa, 0x0, sizeof(sa));
    sa.sa_handler = term_handler;
    sigaction( SIGTERM , &sa, 0);
    sigaction( SIGINT , &sa, 0);
    threads = malloc(sizeof(pthread_t)*(numtunnels+1));

    /* Fork after creating tunnels, useful for scripts */
    ret = daemon(1, 1);

    if (asprintf(&pidfile,"/var/run/eoip-%s",basename(configname)) == -1)
	exit(1);

    mfd = fopen(pidfile, "w");
    fprintf(mfd,"%d", getpid());
    fclose(mfd);

    /* structure of Mikrotik EoIP:
	... IP header ...
	4 byte - GRE info
	2 byte - tunnel id
    */

    pthread_attr_init(&attr);
    pthread_attr_setstacksize(&attr, LINUX_THREAD_STACK_SIZE);
    pthread_attr_setdetachstate(&attr, PTHREAD_CREATE_JOINABLE);
    rc = pthread_create(&threads[0], &attr, thr_rx, (void *)&thr_rx_data);

    for(i=0;i<numtunnels;i++) {
	tunnel=tunnels + i;
	fcntl(tunnel->fd, F_SETFL, O_NONBLOCK);
	/* Allocate for each thread */
	thr_tx_data = malloc(sizeof(struct thr_tx));
	thr_tx_data->tunnel = tunnel;
#ifndef __UCLIBC__
	thr_tx_data->cpu = i+1;
#endif
	thr_tx_data->raw_socket = thr_rx_data.raw_socket;
	rc = pthread_create(&threads[0], &attr, thr_tx, (void *)thr_tx_data);
    }
    rc = pthread_join(threads[0], &status);
    return(0);
}
