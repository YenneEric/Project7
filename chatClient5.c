#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <arpa/inet.h>
#include <openssl/ssl.h>
#include <openssl/err.h>
#include "inet.h"
#include "common.h"

#define MAX_NICKNAME 51
#define MAX_CHAT_ROOMS 10
#define RESPONSE_SIZE 512

// Structure to hold chat room information
struct chat_room {
    char topic[MAX_NICKNAME];
    int port;
    char ip[INET_ADDRSTRLEN];
};

struct chat_room chat_rooms[MAX_CHAT_ROOMS];
int num_rooms = 0;

SSL_CTX *create_ssl_context() {
    SSL_CTX *ctx = SSL_CTX_new(TLS_client_method());
    if (!ctx) {
        perror("Unable to create SSL context");
        ERR_print_errors_fp(stderr);
        exit(EXIT_FAILURE);
    }

    // Set the TLS version to 1.3
    SSL_CTX_set_min_proto_version(ctx, TLS1_3_VERSION);
    SSL_CTX_set_max_proto_version(ctx, TLS1_3_VERSION);

    return ctx;
}

void configure_ssl_context(SSL_CTX *ctx) {
    // Set up the certificate verification paths (if any)
    SSL_CTX_set_verify(ctx, SSL_VERIFY_PEER, NULL);
    SSL_CTX_load_verify_locations(ctx, "directory_server_cert.pem", NULL);
}

void query_directory_server() {
    int sockfd;
    struct sockaddr_in dir_addr;
    SSL_CTX *ctx;
    SSL *ssl;
    char message[] = "L";
    char response[RESPONSE_SIZE];

    // Initialize OpenSSL
    ctx = create_ssl_context();
    configure_ssl_context(ctx);

    // Create socket
    if ((sockfd = socket(AF_INET, SOCK_STREAM, 0)) < 0) {
        perror("Cannot create socket for directory query");
        SSL_CTX_free(ctx);
        return;
    }

    memset(&dir_addr, 0, sizeof(dir_addr));
    dir_addr.sin_family = AF_INET;
    dir_addr.sin_addr.s_addr = inet_addr(SERV_HOST_ADDR);
    dir_addr.sin_port = htons(DIR_SERVER_PORT);

    // Connect to the Directory Server
    if (connect(sockfd, (struct sockaddr *)&dir_addr, sizeof(dir_addr)) < 0) {
        perror("Cannot connect to directory server");
        close(sockfd);
        SSL_CTX_free(ctx);
        return;
    }

    // Create SSL object and attach it to the socket
    ssl = SSL_new(ctx);
    SSL_set_fd(ssl, sockfd);

    // Perform SSL handshake
    if (SSL_connect(ssl) <= 0) {
        ERR_print_errors_fp(stderr);
        SSL_free(ssl);
        close(sockfd);
        SSL_CTX_free(ctx);
        return;
    }

    // Send LIST request
    SSL_write(ssl, message, strlen(message));

    // Read response
    ssize_t nread = SSL_read(ssl, response, sizeof(response) - 1);
    if (nread <= 0) {
        perror("Error reading from directory server");
    } else {
        response[nread] = '\0';
        char *line = strtok(response, "\n");
        num_rooms = 0;
        while (line != NULL && num_rooms < MAX_CHAT_ROOMS) {
            sscanf(line, "Topic: %50[^,], Port: %d", chat_rooms[num_rooms].topic, &chat_rooms[num_rooms].port);
            strcpy(chat_rooms[num_rooms].ip, SERV_HOST_ADDR);
            num_rooms++;
            line = strtok(NULL, "\n");
        }
    }

    SSL_shutdown(ssl);
    SSL_free(ssl);
    close(sockfd);
    SSL_CTX_free(ctx);
}

SSL *connect_to_server(const char *ip, int port, SSL_CTX *ctx) {
    int sockfd;
    struct sockaddr_in serv_addr;

    if ((sockfd = socket(AF_INET, SOCK_STREAM, 0)) < 0) {
        perror("client: can't open stream socket");
        return NULL;
    }

    memset(&serv_addr, 0, sizeof(serv_addr));
    serv_addr.sin_family = AF_INET;
    serv_addr.sin_addr.s_addr = inet_addr(ip);
    serv_addr.sin_port = htons(port);

    if (connect(sockfd, (struct sockaddr *)&serv_addr, sizeof(serv_addr)) < 0) {
        perror("client: can't connect to server");
        close(sockfd);
        return NULL;
    }

    SSL *ssl = SSL_new(ctx);
    SSL_set_fd(ssl, sockfd);

    if (SSL_connect(ssl) <= 0) {
        ERR_print_errors_fp(stderr);
        SSL_free(ssl);
        close(sockfd);
        return NULL;
    }

    return ssl;
}

int main() {
    char message[MAX] = {'\0'};
    fd_set readset;
    SSL_CTX *ctx;
    SSL *ssl;
    char nickname[MAX_NICKNAME];

    // Initialize OpenSSL
    SSL_library_init();
    OpenSSL_add_ssl_algorithms();
    SSL_load_error_strings();

    // Query the Directory Server
    query_directory_server();

    fprintf(stdout, "\nAvailable Chat Rooms:\n");
    for (int i = 0; i < num_rooms; i++) {
        fprintf(stdout, "%d. Topic: %s, Port: %d\n", i + 1, chat_rooms[i].topic, chat_rooms[i].port);
    }

    fprintf(stdout, "Enter the port number of the chat room to connect to: ");
    int port;
    scanf("%d", &port);
    getchar();

    char *selected_ip = NULL;
    for (int i = 0; i < num_rooms; i++) {
        if (chat_rooms[i].port == port) {
            selected_ip = chat_rooms[i].ip;
            break;
        }
    }

    if (!selected_ip) {
        fprintf(stderr, "No chat room found with port %d.\n", port);
        return -1;
    }

    ctx = create_ssl_context();
    configure_ssl_context(ctx);

    ssl = connect_to_server(selected_ip, port, ctx);
    if (!ssl) {
        fprintf(stderr, "Failed to connect to chat server on port %d.\n", port);
        SSL_CTX_free(ctx);
        return -1;
    }

    fprintf(stdout, "What is your nickname (up to 50 characters): ");
    fgets(nickname, MAX_NICKNAME, stdin);
    nickname[strcspn(nickname, "\n")] = '\0';

    SSL_write(ssl, nickname, strlen(nickname));

    for (;;) {
        FD_ZERO(&readset);
        FD_SET(STDIN_FILENO, &readset);
        FD_SET(SSL_get_fd(ssl), &readset);

        if (select(SSL_get_fd(ssl) + 1, &readset, NULL, NULL, NULL) > 0) {
            if (FD_ISSET(STDIN_FILENO, &readset)) {
                if (fgets(message, MAX, stdin) != NULL) {
                    size_t len = strlen(message);
                    if (message[len - 1] == '\n') message[len - 1] = '\0';

                    SSL_write(ssl, message, len);
                }
            }

            if (FD_ISSET(SSL_get_fd(ssl), &readset)) {
                ssize_t nread = SSL_read(ssl, message, MAX - 1);
                if (nread <= 0) {
                    if (nread == 0) {
                        fprintf(stdout, "Server closed the connection.\n");
                    } else {
                        perror("Error reading from server");
                    }
                    break;
                }
                message[nread] = '\0';
                fprintf(stdout, "%s\n", message);
            }
        }
    }

    SSL_shutdown(ssl);
    SSL_free(ssl);
    SSL_CTX_free(ctx);
    return 0;
}
