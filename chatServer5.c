#include "inet.h" // Includes SERV_HOST_ADDR and DIR_SERVER_PORT
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <signal.h>
#include <sys/queue.h>
#include <errno.h>
#include <fcntl.h>
#include <sys/select.h>
#include <sys/socket.h>
#include <openssl/ssl.h>
#include <openssl/err.h>
#include <openssl/ssl.h>
#include <openssl/err.h>

#define MAX_NICKNAME 51
#define MESSAGE_SIZE 256
#define MAX_TOPIC 100

#define CHAT_SERVER_CERT "ksu_football.crt"
#define CHAT_SERVER_KEY "ksu_football.key"

void shutdownServer();

// Structure for holding client connection information
struct connection {
    int socket;
    char nickname[MAX_NICKNAME];
    SSL *ssl; // SSL connection for the client
    LIST_ENTRY(connection) entries;
};

// Linked list for managing client connections
LIST_HEAD(connection_listhead, connection) connection_list;

// Global variables
int sockfd;         // Server socket
int port;           // Server port
char current_topic[MAX_TOPIC]; // Chat topic
int first_user_msg_sent = 0;

// Create and configure SSL context
SSL_CTX *create_ssl_context() {
    SSL_CTX *ctx = SSL_CTX_new(TLS_server_method());
    if (!ctx) {
        perror("Unable to create SSL context");
        ERR_print_errors_fp(stderr);
        exit(EXIT_FAILURE);
    }

    // Set TLS version to 1.3
    SSL_CTX_set_min_proto_version(ctx, TLS1_3_VERSION);
    SSL_CTX_set_max_proto_version(ctx, TLS1_3_VERSION);
    return ctx;
}

int configure_ssl_context(SSL_CTX *ctx, char *name) {

   printf("%s" , name);
    if(strncmp("KSUFootball",name,MAX_TOPIC) ==0) {

    if (SSL_CTX_use_certificate_file(ctx, CHAT_SERVER_CERT, SSL_FILETYPE_PEM) <= 0) {
        ERR_print_errors_fp(stderr);
        exit(EXIT_FAILURE);
    }

    if (SSL_CTX_use_PrivateKey_file(ctx, CHAT_SERVER_KEY, SSL_FILETYPE_PEM) <= 0) {
        ERR_print_errors_fp(stderr);
        exit(EXIT_FAILURE);
    }
    return 0;
    }
    return 1;
    
    
}

// Shutdown the server
void shutdownServer() {
    printf("Shutting down server...\n");
    close(sockfd);
    exit(0);
}

// Signal handler for SIGINT
void handle_sigint(int sig) {
    printf("\nCaught signal %d. Deregistering and shutting down...\n", sig);
    shutdownServer();
}

// Register server with the directory server


void register_with_directory(char *topic, int port) {
    SSL_CTX *ctx;
    SSL *ssl;
    int sockfd;
    struct sockaddr_in dir_addr;
    char message[MESSAGE_SIZE];
    char response[MESSAGE_SIZE];

    SSL_library_init();
    ctx = SSL_CTX_new(TLS_client_method());
    if (!ctx) {
        perror("SSL context creation failed");
        exit(1);
    }

    if ((sockfd = socket(AF_INET, SOCK_STREAM, 0)) < 0) {
        perror("Cannot create socket");
        SSL_CTX_free(ctx);
        exit(1);
    }

    memset(&dir_addr, 0, sizeof(dir_addr));
    dir_addr.sin_family = AF_INET;
    dir_addr.sin_addr.s_addr = inet_addr(SERV_HOST_ADDR);
    dir_addr.sin_port = htons(DIR_SERVER_PORT);

    if (connect(sockfd, (struct sockaddr *)&dir_addr, sizeof(dir_addr)) < 0) {
        perror("Cannot connect to directory server");
        close(sockfd);
        SSL_CTX_free(ctx);
        exit(1);
    }

    ssl = SSL_new(ctx);
    SSL_set_fd(ssl, sockfd);

    if (SSL_connect(ssl) <= 0) {
        ERR_print_errors_fp(stderr);
        SSL_free(ssl);
        close(sockfd);
        SSL_CTX_free(ctx);
        exit(1);
    }

    topic[strcspn(topic, "\n")] = '\0';
    snprintf(message, sizeof(message), "R %s %d", topic, port);
    printf("Debug: Constructed registration message: '%s'\n", message);

    int bytes_written = SSL_write(ssl, message, strlen(message));
    printf("Debug: Bytes written to server: %d\n", bytes_written);
    if (bytes_written <= 0) {
        perror("Error sending message to directory server");
    }

    int nread = SSL_read(ssl, response, sizeof(response) - 1);
    if (nread > 0) {
        response[nread] = '\0';
        printf("Response from directory server: %s\n", response);
    } else {
        perror("Error reading from directory server");
    }

    SSL_shutdown(ssl);
    SSL_free(ssl);
    close(sockfd);
    SSL_CTX_free(ctx);
}



// Main server loop
int main(int argc, char **argv) {
    if (argc < 3) {
        fprintf(stderr, "Usage: %s \"topic\" <port>\n", argv[0]);
        exit(EXIT_FAILURE);
    }

    // Initialize OpenSSL
    SSL_library_init();
    SSL_load_error_strings();
    OpenSSL_add_ssl_algorithms();

    // Parse arguments
    strncpy(current_topic, argv[1], MAX_TOPIC);
    port = atoi(argv[2]);

    // Create SSL context
    SSL_CTX *ctx = create_ssl_context();
    if(configure_ssl_context(ctx, current_topic) != 0){
                exit(EXIT_FAILURE);
    }

    // Register signal handler
    signal(SIGINT, handle_sigint);

    // Register with the directory server
    register_with_directory(current_topic, port);

    // Create server socket
    struct sockaddr_in serv_addr;
    if ((sockfd = socket(AF_INET, SOCK_STREAM, 0)) < 0) {
        perror("Cannot open server socket");
        exit(EXIT_FAILURE);
    }

    memset(&serv_addr, 0, sizeof(serv_addr));
    serv_addr.sin_family = AF_INET;
    serv_addr.sin_addr.s_addr = htonl(INADDR_ANY);
    serv_addr.sin_port = htons(port);

    if (bind(sockfd, (struct sockaddr *)&serv_addr, sizeof(serv_addr)) < 0) {
        perror("Cannot bind server socket");
        close(sockfd);
        exit(EXIT_FAILURE);
    }

    if (listen(sockfd, 5) < 0) {
        perror("Error listening on server socket");
        close(sockfd);
        exit(EXIT_FAILURE);
    }

    printf("Chat server '%s' listening on port %d...\n", current_topic, port);

    // Initialize connection list
    LIST_INIT(&connection_list);

    fd_set readset;

    // Main server loop
    while (1) {
        FD_ZERO(&readset);
        FD_SET(sockfd, &readset);
        int max_fd = sockfd;

        struct connection *conn;
        LIST_FOREACH(conn, &connection_list, entries) {
            FD_SET(conn->socket, &readset);
            if (conn->socket > max_fd) {
                max_fd = conn->socket;
            }
        }

        if (select(max_fd + 1, &readset, NULL, NULL, NULL) > 0) {
            // Handle new connections
            if (FD_ISSET(sockfd, &readset)) {
                struct sockaddr_in client_addr;
                socklen_t client_len = sizeof(client_addr);
                int client_sock = accept(sockfd, (struct sockaddr *)&client_addr, &client_len);
                if (client_sock < 0) {
                    perror("Error accepting connection");
                    continue;
                }

                SSL *ssl = SSL_new(ctx);
                SSL_set_fd(ssl, client_sock);

                if (SSL_accept(ssl) <= 0) {
                    ERR_print_errors_fp(stderr);
                    SSL_free(ssl);
                    close(client_sock);
                    continue;
                }

                char nickname[MAX_NICKNAME];
                ssize_t nread = SSL_read(ssl, nickname, sizeof(nickname) - 1);
                if (nread <= 0) {
                    perror("Error reading nickname");
                    SSL_free(ssl);
                    close(client_sock);
                    continue;
                }
                nickname[nread] = '\0';

                // Add client to the list
                struct connection *new_conn = malloc(sizeof(struct connection));
                new_conn->socket = client_sock;
                new_conn->ssl = ssl;
                strncpy(new_conn->nickname, nickname, MAX_NICKNAME);
                LIST_INSERT_HEAD(&connection_list, new_conn, entries);

                printf("Client '%s' connected.\n", nickname);
            }

            // Handle messages from connected clients
            LIST_FOREACH(conn, &connection_list, entries) {
                if (FD_ISSET(conn->socket, &readset)) {
                    char buffer[MESSAGE_SIZE];
                    ssize_t nread = SSL_read(conn->ssl, buffer, sizeof(buffer) - 1);
                    if (nread <= 0) {
                        printf("Client '%s' disconnected.\n", conn->nickname);
                        SSL_free(conn->ssl);
                        close(conn->socket);
                        LIST_REMOVE(conn, entries);
                        free(conn);
                    } else {
                        buffer[nread] = '\0';
                        printf("%s: %s\n", conn->nickname, buffer);

                        // Broadcast message to all clients
                        struct connection *temp;
                        LIST_FOREACH(temp, &connection_list, entries) {
                            if (temp != conn) {
                                SSL_write(temp->ssl, buffer, nread);
                            }
                        }
                    }
                }
            }
        }
    }

    // Cleanup
    close(sockfd);
    SSL_CTX_free(ctx);
    EVP_cleanup();
    return 0;
}
