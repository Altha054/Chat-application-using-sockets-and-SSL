#include <stdio.h>
#include <netinet/in.h>
#include <stdlib.h>
#include <string.h>
#include <sys/socket.h>
#include <sys/types.h>
#include <unistd.h>
#include <openssl/ssl.h>
#include <openssl/err.h>

#define MAX 80
#define PORT 8080
#define SA struct sockaddr

void error(const char *msg)
{
    perror(msg);
    exit(1);
}

void init_openssl()
{
    SSL_load_error_strings();
    OpenSSL_add_ssl_algorithms();
}

SSL_CTX *create_context()
{
    const SSL_METHOD *method;
    SSL_CTX *ctx;

    method = SSLv23_server_method(); // Use SSLv23_method() for compatibility with older SSL versions
    ctx = SSL_CTX_new(method);
    if (!ctx)
    {
        perror("Unable to create SSL context");
        ERR_print_errors_fp(stderr);
        exit(EXIT_FAILURE);
    }

    return ctx;
}

void configure_context(SSL_CTX *ctx)
{
    SSL_CTX_set_ecdh_auto(ctx, 1);

    if (SSL_CTX_use_certificate_file(ctx, "server.crt", SSL_FILETYPE_PEM) <= 0)
    {
        ERR_print_errors_fp(stderr);
        exit(EXIT_FAILURE);
    }

    if (SSL_CTX_use_PrivateKey_file(ctx, "server.key", SSL_FILETYPE_PEM) <= 0)
    {
        ERR_print_errors_fp(stderr);
        exit(EXIT_FAILURE);
    }
}

void func(SSL *ssl)
{
    char buff[MAX];
    int n;
    for (;;)
    {
        bzero(buff, MAX);
        SSL_read(ssl, buff, sizeof(buff));
        printf("From client: %s\t To client: ", buff);
        bzero(buff, MAX);
        n = 0;
        while ((buff[n++] = getchar()) != '\n')
            ;
        SSL_write(ssl, buff, sizeof(buff));
        if (strncmp("exit", buff, 4) == 0)
        {
            printf("Server Exit...\n");
            break;
        }
    }
}

int main()
{
    SSL_CTX *ctx;
    int sockfd, connfd;
    struct sockaddr_in servaddr, cli;

    init_openssl();
    ctx = create_context();
    configure_context(ctx);

    sockfd = socket(AF_INET, SOCK_STREAM, 0);
    if (sockfd == -1)
    {
        error("Socket creation failed...\n");
    }
    else
    {
        printf("Socket successfully created..\n");
    }
    bzero(&servaddr, sizeof(servaddr));

    servaddr.sin_family = AF_INET;
    servaddr.sin_addr.s_addr = htonl(INADDR_ANY); // inet_addr("IP ADDRESS OF SERVER(if you wish to connect different systems)");
    servaddr.sin_port = htons(PORT);

    if ((bind(sockfd, (SA *)&servaddr, sizeof(servaddr))) != 0)
    {
        error("Socket bind failed...\n");
    }
    else
    {
        printf("Socket successfully binded..\n");
    }

    if ((listen(sockfd, 5)) != 0)
    {
        error("Listen failed...\n");
    }
    else
    {
        printf("Server listening..\n");
    }
    socklen_t len = sizeof(cli);

    connfd = accept(sockfd, (SA *)&cli, &len);
    if (connfd < 0)
    {
        error("Server acccept failed...\n");
    }
    else
    {
        printf("Server acccept the client...\n");
    }

    SSL *ssl = SSL_new(ctx);
    SSL_set_fd(ssl, connfd);

    if (SSL_accept(ssl) <= 0)
    {
        ERR_print_errors_fp(stderr);
    }
    else
    {
        func(ssl);
    }

    SSL_shutdown(ssl);
    SSL_free(ssl);
    close(sockfd);
    SSL_CTX_free(ctx);
    return 0;
}