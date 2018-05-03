#include <string.h>
#include <sys/socket.h>
#include <arpa/inet.h>  /* for sockaddr_in and inet_ntoa() */

#include <stdio.h>
#include <sys/types.h>
#include <unistd.h>
#include <string.h>
#include <errno.h>
#include <stdlib.h>
#include <signal.h>
#include <netinet/tcp.h>
#include <arpa/inet.h>


#define pr_err(fmt, ...)                                           \
        printf("Error: " fmt, ##__VA_ARGS__)

#define pr_perror(fmt, ...)                                             \
        pr_err(fmt ": %s\n", ##__VA_ARGS__, strerror(errno))

#define fail(fmt, ...)                                             \
        pr_err(fmt ": %s\n", ##__VA_ARGS__, strerror(errno))

union sockaddr_inet {
	struct sockaddr addr;
	struct sockaddr_in v4;
	struct sockaddr_in6 v6;
};

int tcp_init_server(int family, int *port)
{
	union sockaddr_inet addr;
	int sock;
	int yes = 1, ret;

	memset(&addr,0,sizeof(addr));
	if (family == AF_INET) {
		addr.v4.sin_family = family;
		inet_pton(family, "0.0.0.0", &(addr.v4.sin_addr));
	} else if (family == AF_INET6){
		addr.v6.sin6_family = family;
		inet_pton(family, "::0", &(addr.v6.sin6_addr));
	} else
		return -1;

	sock = socket(family, SOCK_STREAM, IPPROTO_TCP);
	if (sock == -1) {
		pr_perror("socket() failed");
		return -1;
	}

	if (setsockopt(sock, SOL_SOCKET, SO_REUSEADDR, &yes, sizeof(int)) == -1 ) {
		pr_perror("setsockopt() error");
		return -1;
	}

	while (1) {
		if (family == AF_INET)
			addr.v4.sin_port = htons(*port);
		else if (family == AF_INET6)
			addr.v6.sin6_port = htons(*port);

		ret = bind(sock, (struct sockaddr *) &addr, sizeof(addr));

		/* criu doesn't restore sock opts, so we need this hack */
		if (ret == -1 && errno == EADDRINUSE) {
			(*port)++;
			continue;
		}
		break;
	}

	if (ret == -1) {
		pr_perror("bind() failed");
		return -1;
	}

	if (listen(sock, 1) == -1) {
		pr_perror("listen() failed");
		return -1;
	}
	return sock;
}

int tcp_accept_server(int sock)
{
	struct sockaddr_in maddr;
	int sock2;
	socklen_t addrlen;
#ifdef DEBUG
	test_msg ("Waiting for connection..........\n");
#endif
	addrlen = sizeof(maddr);
	sock2 = accept(sock,(struct sockaddr *) &maddr, &addrlen);

	if (sock2 == -1) {
		pr_perror("accept() failed");
		return -1;
	}

#ifdef DEBUG
	test_msg ("Connection!!\n");
#endif
	return sock2;
}

int __tcp_init_client(int sock, int family, char *servIP, unsigned short servPort)
{
	union sockaddr_inet servAddr;

	/* Construct the server address structure */
	memset(&servAddr, 0, sizeof(servAddr));
	if (family == AF_INET) {
		servAddr.v4.sin_family      = AF_INET;
		servAddr.v4.sin_port        = htons(servPort);
		inet_pton(AF_INET, servIP, &servAddr.v4.sin_addr);
	} else {
		servAddr.v6.sin6_family      = AF_INET6;
		servAddr.v6.sin6_port        = htons(servPort);
		inet_pton(AF_INET6, servIP, &servAddr.v6.sin6_addr);
	}
	if (connect(sock, (struct sockaddr *) &servAddr, sizeof(servAddr)) < 0) {
		pr_perror("can't connect to server");
		return -1;
	}
	return sock;
}

int tcp_init_client(int family, char *servIP, unsigned short servPort)
{
	int sock;

	if ((sock = socket(family, SOCK_STREAM, IPPROTO_TCP)) < 0) {
		pr_perror("can't create socket");
		return -1;
	}
	return __tcp_init_client(sock, family, servIP, servPort);
}

#ifdef ZDTM_IPV6
#define ZDTM_FAMILY AF_INET6
#else
#define ZDTM_FAMILY AF_INET
#endif
static int port = 8880;

int main(int argc, char **argv)
{
	int fd, fd_s, clt, sk;
	union sockaddr_inet src_addr, dst_addr, addr;
	socklen_t aux;
	char c = 5;

	sk = socket(ZDTM_FAMILY, SOCK_STREAM, 0);
	if (sk < 0) {
		pr_perror("socket");
		return 1;
	}

	if ((fd_s = tcp_init_server(ZDTM_FAMILY, &port)) < 0) {
		pr_err("initializing server failed\n");
		return 1;
	}

	clt = tcp_init_client(ZDTM_FAMILY, "localhost", port);
	if (clt < 0)
		return 1;

	/*
	 * parent is server of TCP connection
	 */
	fd = tcp_accept_server(fd_s);
	if (fd < 0) {
		pr_err("can't accept client connection\n");
		return 1;
	}

	shutdown(clt, SHUT_WR);

	{
		union sockaddr_inet addr;
		int fd1;

		memset(&addr, 0, sizeof(addr));
		addr.v4.sin_family      = AF_UNSPEC;
		if (connect(fd, (struct sockaddr *) &addr, sizeof(addr)))
			return 1;

		if (__tcp_init_client(fd, ZDTM_FAMILY, "localhost", port) < 0)
			return 1;

		return 0;
		fd1 = tcp_accept_server(fd_s);
		if (fd1 < 0) {
			pr_err("can't accept client connection\n");
			return 1;
		}
	}

	return 0;
}
