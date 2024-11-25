#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <errno.h>
#include <arpa/inet.h>
#include <sys/select.h>
#include <sys/queue.h>
#include <signal.h>
#include <openssl/ssl.h>
#include <openssl/err.h>
#include "inet.h"
#include "common.h"

#define MAX_NICKNAME 51
#define MESSAGE_SIZE 256
#define MAX_TOPIC 100

#define CHAT_SERVER_CERT "ksu_football.crt"
#define CHAT_SERVER_KEY "ksu_football.key"

// Structure for holding client connection information
struct connection {
    int socket;
    SSL *ssl;
    char nickname[MAX_NICKNAME];
    LIST_ENTRY(connection) entries;
};

// Head of the connection list for holding the connection sockets
LIST_HEAD(connection_listhead, connection) connection_list;

int sockfd;  // Global socket variable for the server
char current_topic[MAX_TOPIC] = "KSU Football";  // Predefined topic

// SSL context for the chat server
SSL_CTX *create_ssl_context() {
    SSL_CTX *ctx = SSL_CTX_new(TLS_server_method());
    if (!ctx) {
        perror("Unable to create SSL context");
        ERR_print_errors_fp(stderr);
        exit(EXIT_FAILURE);
    }

    SSL_CTX_set_min_proto_version(ctx, TLS1_3_VERSION);
    SSL_CTX_set_max_proto_version(ctx, TLS1_3_VERSION);

    return ctx;
}

void configure_ssl_context(SSL_CTX *ctx) {
    if (SSL_CTX_use_certificate_file(ctx, CHAT_SERVER_CERT, SSL_FILETYPE_PEM) <= 0) {
        ERR_print_errors_fp(stderr);
        exit(EXIT_FAILURE);
    }

    if (SSL_CTX_use_PrivateKey_file(ctx, CHAT_SERVER_KEY, SSL_FILETYPE_PEM) <= 0) {
        ERR_print_errors_fp(stderr);
        exit(EXIT_FAILURE);
    }
}

void shutdown_server() {
    close(sockfd);
    printf("Chat server for topic '%s' shut down.\n", current_topic);
    exit(0);
}

void handle_sigint(int sig) {
    (void)sig;
    shutdown_server();
}

void handle_client_message(struct connection *conn, struct connection_listhead *connection_list, fd_set *readset) {
    char buffer[MESSAGE_SIZE];
    ssize_t nread = SSL_read(conn->ssl, buffer, sizeof(buffer) - 1);
    if (nread <= 0) {
        if (nread == 0) {
            printf("%s has disconnected.\n", conn->nickname);
        } else {
            perror("Error reading from client");
        }

        // Close and remove the client connection
        close(conn->socket);
        SSL_free(conn->ssl);
        LIST_REMOVE(conn, entries);
        free(conn);
    } else {
        buffer[nread] = '\0';
        printf("%s: %s\n", conn->nickname, buffer);

        // Broadcast the message to all clients
        struct connection *client;
        LIST_FOREACH(client, connection_list, entries) {
            if (client != conn) {
                SSL_write(client->ssl, buffer, nread);
            }
        }
    }
}

int main(int argc, char **argv) {
    if (argc != 3) {
        fprintf(stderr, "Usage: %s \"topic\" <port>\n", argv[0]);
        exit(EXIT_FAILURE);
    }

    // Parse command-line arguments
    int port = atoi(argv[2]);
    if (port <= 0) {
        fprintf(stderr, "Invalid port number.\n");
        exit(EXIT_FAILURE);
    }

    strncpy(current_topic, argv[1], MAX_TOPIC);

    unsigned int clientlen;
    struct sockaddr_in client_addr, serv_addr;
    fd_set readset;

    SSL_CTX *ctx;
    ctx = create_ssl_context();
    configure_ssl_context(ctx);

    // Initialize the list head
    LIST_INIT(&connection_list);

    // Register signal handler
    signal(SIGINT, handle_sigint);

    // Create communication endpoint
    if ((sockfd = socket(AF_INET, SOCK_STREAM, 0)) < 0) {
        perror("server: can't open stream socket");
        exit(EXIT_FAILURE);
    }

    // Bind socket to local address
    memset(&serv_addr, 0, sizeof(serv_addr));
    serv_addr.sin_family = AF_INET;
    serv_addr.sin_addr.s_addr = htonl(INADDR_ANY);
    serv_addr.sin_port = htons(port);

    if (bind(sockfd, (struct sockaddr *)&serv_addr, sizeof(serv_addr)) < 0) {
        perror("server: can't bind local address");
        shutdown_server();
    }

    if (listen(sockfd, 5) < 0) {
        perror("server: error listening on socket");
        shutdown_server();
    }

    printf("Chat server for topic '%s' is running on port %d...\n", current_topic, port);

    for (;;) {
        FD_ZERO(&readset);
        FD_SET(sockfd, &readset);
        int max_socket = sockfd;

        // Add client sockets to the read set
        struct connection *conn;
        LIST_FOREACH(conn, &connection_list, entries) {
            FD_SET(conn->socket, &readset);
            if (conn->socket > max_socket) {
                max_socket = conn->socket;
            }
        }

        if (select(max_socket + 1, &readset, NULL, NULL, NULL) > 0) {
            // Accept new connection
            if (FD_ISSET(sockfd, &readset)) {
                clientlen = sizeof(client_addr);
                int newsockfd = accept(sockfd, (struct sockaddr *)&client_addr, &clientlen);
                if (newsockfd < 0) {
                    perror("server: accept error");
                    continue;
                }

                // Create SSL object and attach to socket
                SSL *ssl = SSL_new(ctx);
                SSL_set_fd(ssl, newsockfd);

                if (SSL_accept(ssl) <= 0) {
                    ERR_print_errors_fp(stderr);
                    SSL_free(ssl);
                    close(newsockfd);
                    continue;
                }

                // Read the client's nickname
                char nickname[MAX_NICKNAME];
                ssize_t nread = SSL_read(ssl, nickname, sizeof(nickname) - 1);
                if (nread <= 0) {
                    perror("Error reading nickname from client");
                    SSL_free(ssl);
                    close(newsockfd);
                    continue;
                }
                nickname[nread] = '\0';

                // Add new client to the connection list
                struct connection *new_conn = malloc(sizeof(struct connection));
                new_conn->socket = newsockfd;
                new_conn->ssl = ssl;
                strncpy(new_conn->nickname, nickname, MAX_NICKNAME);
                LIST_INSERT_HEAD(&connection_list, new_conn, entries);

                printf("%s has joined the chat.\n", nickname);
            }

            // Handle messages from existing clients
            LIST_FOREACH(conn, &connection_list, entries) {
                if (FD_ISSET(conn->socket, &readset)) {
                    handle_client_message(conn, &connection_list, &readset);
                }
            }
        }
    }

    // Cleanup
    close(sockfd);
    SSL_CTX_free(ctx);
    return 0;
}
