//all works


#include "inet.h" 
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
#include "common.h"

// function prototypes
void shutdown_server();
void deregister_from_directory();

// structure for holding client connection information
struct connection {
    int socket;
    char nickname[MAX_NICKNAME];
    SSL *ssl; // SSL connection for the client
    LIST_ENTRY(connection) entries;
};

// linked list for managing client connections
LIST_HEAD(connection_listhead, connection) connection_list;

// global variables
int server_socket;         // server socket
int server_port;           // server port
char current_topic[MAX_TOPIC]; // chat topic
int first_user_connected = 0; // flag to track if the first user has connected

// create and configure SSL context
SSL_CTX *create_ssl_context() {
    SSL_CTX *ctx = SSL_CTX_new(TLS_server_method());
    if (!ctx) {
        perror("unable to create SSL context");
        ERR_print_errors_fp(stderr);
        exit(EXIT_FAILURE);
    }

    // set TLS version to 1.3
    SSL_CTX_set_min_proto_version(ctx, TLS1_3_VERSION);
    SSL_CTX_set_max_proto_version(ctx, TLS1_3_VERSION);
    return ctx;
}

// function to check if a nickname is already in use
int is_nickname_taken(const char *nickname) {
    struct connection *conn;
    LIST_FOREACH(conn, &connection_list, entries) {
        if (strncmp(conn->nickname, nickname, MAX_NICKNAME) == 0) {
            return 1; // nickname is already in use
        }
    }
    return 0; // nickname is available
}

// configure SSL context based on the server name
int configure_ssl_context(SSL_CTX *ctx, char *topic) {
    char cert_path[MAX] = {0};
    char key_path[MAX] = {0};

    if (strcmp(topic, "KSUFootball") == 0) {
        strcpy(cert_path, "KSUFootball.crt");
        strcpy(key_path, "KSUFootball.key");
    } else if (strcmp(topic, "MovieTalk") == 0) {
        strcpy(cert_path, "MovieTalk.crt");
        strcpy(key_path, "MovieTalk.key");
    } else {
        fprintf(stderr, "Unknown topic: %s\n", topic);
        return 1;
    }

    if (SSL_CTX_use_certificate_file(ctx, cert_path, SSL_FILETYPE_PEM) <= 0) {
        ERR_print_errors_fp(stderr);
        exit(EXIT_FAILURE);
    }
    if (SSL_CTX_use_PrivateKey_file(ctx, key_path, SSL_FILETYPE_PEM) <= 0) {
        ERR_print_errors_fp(stderr);
        exit(EXIT_FAILURE);
    }
    if (SSL_CTX_load_verify_locations(ctx, "ca.crt", NULL) <= 0) {
        ERR_print_errors_fp(stderr);
        exit(EXIT_FAILURE);
    }

    SSL_CTX_set_verify(ctx, SSL_VERIFY_PEER, NULL);
    return 0;
}


// function to deregister from the directory server
void deregister_from_directory() {
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

    // create socket to connect to directory server
    if ((sockfd = socket(AF_INET, SOCK_STREAM, 0)) < 0) {
        perror("cannot create socket");
        SSL_CTX_free(ctx);
        exit(1);
    }

    memset(&dir_addr, 0, sizeof(dir_addr));
    dir_addr.sin_family = AF_INET;
    dir_addr.sin_addr.s_addr = inet_addr(SERV_HOST_ADDR);  // change with actual directory server IP address
    dir_addr.sin_port = htons(DIR_SERVER_PORT);

    // connect to directory server
    if (connect(sockfd, (struct sockaddr *)&dir_addr, sizeof(dir_addr)) < 0) {
        perror("cannot connect to directory server");
        close(sockfd);
        SSL_CTX_free(ctx);
        exit(1);
    }

    ssl = SSL_new(ctx);
    SSL_set_fd(ssl, sockfd);

    // establish SSL connection
    if (SSL_connect(ssl) <= 0) {
        ERR_print_errors_fp(stderr);
        SSL_free(ssl);
        close(sockfd);
        SSL_CTX_free(ctx);
        exit(1);
    }

    // send deregistration message
    snprintf(message, sizeof(message), "D %s %d", current_topic, server_port);  // dereg ister message format
    SSL_write(ssl, message, strnlen(message, sizeof(message)));

    int nread = SSL_read(ssl, response, sizeof(response) - 1);
    if (nread > 0) {
        response[nread] = '\0';
        printf("response from directory server: %s\n", response);
    } else {
        perror("error reading from directory server");
    }

    SSL_shutdown(ssl);
    SSL_free(ssl);
    close(sockfd);
    SSL_CTX_free(ctx);
}

// shutdown the server
void shutdown_server() {
    printf("shutting down server...\n");

    // deregister from the directory server
    deregister_from_directory();

    // close server socket and free SSL context
    close(server_socket);
    EVP_cleanup();
    exit(0);
}

// signal handler for SIGINT
void handle_sigint(int sig) {
    printf("\ncaught signal %d. deregistering and shutting down...\n", sig);
    shutdown_server();
}

// register server with the directory server
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

    // create socket to connect to directory server
    if ((sockfd = socket(AF_INET, SOCK_STREAM, 0)) < 0) {
        perror("cannot create socket");
        SSL_CTX_free(ctx);
        exit(1);
    }

    memset(&dir_addr, 0, sizeof(dir_addr));
    dir_addr.sin_family = AF_INET;
    dir_addr.sin_addr.s_addr = inet_addr(SERV_HOST_ADDR);
    dir_addr.sin_port = htons(DIR_SERVER_PORT);

    // connect to directory server
    if (connect(sockfd, (struct sockaddr *)&dir_addr, sizeof(dir_addr)) < 0) {
        perror("cannot connect to directory server");
        close(sockfd);
        SSL_CTX_free(ctx);
        exit(1);
    }

    ssl = SSL_new(ctx);
    SSL_set_fd(ssl, sockfd);

    // establish SSL connection
    if (SSL_connect(ssl) <= 0) {
        ERR_print_errors_fp(stderr);
        SSL_free(ssl);
        close(sockfd);
        SSL_CTX_free(ctx);
        exit(1);
    }

    // send registration message
    snprintf(message, sizeof(message), "R %s %d", topic, port);
    SSL_write(ssl, message, strnlen(message, sizeof(message)));

    int nread = SSL_read(ssl, response, sizeof(response) - 1);
    if (nread > 0) {
        response[nread] = '\0';
        printf("response from directory server: %s\n", response);
    } else {
        perror("error reading from directory server");
    }

    SSL_shutdown(ssl);
    SSL_free(ssl);
    close(sockfd);
    SSL_CTX_free(ctx);
}

// broadcast message to all connected clients except the sender
void broadcast_message(struct connection *sender, const char *message) {
    struct connection *conn;
    char full_message[MESSAGE_SIZE];

    // format the message to include the sender's nickname
    if (sender) {
        snprintf(full_message, sizeof(full_message), "%s: %s", sender->nickname, message);
    } else {
        snprintf(full_message, sizeof(full_message), "%s", message);
    }

    LIST_FOREACH(conn, &connection_list, entries) {
        if (conn != sender) {
            SSL_write(conn->ssl, full_message, strnlen(full_message, sizeof(full_message)));
        }
    }
}

// main server loop
int main(int argc, char **argv) {
    if (argc < 3) {
        fprintf(stderr, "usage: %s \"topic\" <port>\n", argv[0]);
        exit(EXIT_FAILURE);
    }

    // initialize OpenSSL
    SSL_library_init();
    SSL_load_error_strings();
    OpenSSL_add_ssl_algorithms();

    // parse arguments
    strncpy(current_topic, argv[1], MAX_TOPIC);
    current_topic[MAX_TOPIC - 1] = '\0'; // ensure null termination
    server_port = atoi(argv[2]);

    // create SSL context
    SSL_CTX *ctx = create_ssl_context();
   if (configure_ssl_context(ctx, current_topic) != 0) {
    fprintf(stderr, "Failed to configure SSL context for topic %s.\n", current_topic);
    exit(EXIT_FAILURE);
}


    // register signal handler
    signal(SIGINT, handle_sigint);

    // register with the directory server
    register_with_directory(current_topic, server_port);

    // create server socket
    struct sockaddr_in serv_addr;
    if ((server_socket = socket(AF_INET, SOCK_STREAM, 0)) < 0) {
        perror("cannot open server socket");
        exit(EXIT_FAILURE);
    }

    memset(&serv_addr, 0, sizeof(serv_addr));
    serv_addr.sin_family = AF_INET;
    serv_addr.sin_addr.s_addr = htonl(INADDR_ANY);
    serv_addr.sin_port = htons(server_port);

    // bind server socket
    if (bind(server_socket, (struct sockaddr *)&serv_addr, sizeof(serv_addr)) < 0) {
        perror("cannot bind server socket");
        close(server_socket);
        exit(EXIT_FAILURE);
    }

    // listen for incoming connections
    if (listen(server_socket, 5) < 0) {
        perror("error listening on server socket");
        close(server_socket);
        exit(EXIT_FAILURE);
    }

    printf("chat server '%s' listening on port %d...\n", current_topic, server_port);

    // initialize connection list
    LIST_INIT(&connection_list);

    fd_set readset;

    // main server loop
    while (1) {
        FD_ZERO(&readset);
        FD_SET(server_socket, &readset);
        int max_fd = server_socket;

        struct connection *conn;
        LIST_FOREACH(conn, &connection_list, entries) {
            FD_SET(conn->socket, &readset);
            if (conn->socket > max_fd) {
                max_fd = conn->socket;
            }
        }

        // wait for activity on sockets
        if (select(max_fd + 1, &readset, NULL, NULL, NULL) > 0) {
            // handle new connections
            if (FD_ISSET(server_socket, &readset)) {
                struct sockaddr_in client_addr;
                socklen_t client_len = sizeof(client_addr);
                int client_sock = accept(server_socket, (struct sockaddr *)&client_addr, &client_len);
                if (client_sock < 0) {
                    perror("error accepting connection");
                    continue;
                }

                SSL *ssl = SSL_new(ctx);
                SSL_set_fd(ssl, client_sock);

                // establish SSL connection
                if (SSL_accept(ssl) <= 0) {
                    ERR_print_errors_fp(stderr);
                    SSL_free(ssl);
                    close(client_sock);
                    continue;
                }

                char nickname[MAX_NICKNAME];
                ssize_t nread = SSL_read(ssl, nickname, sizeof(nickname) - 1);
                if (nread <= 0) {
                    perror("error reading nickname");
                    SSL_free(ssl);
                    close(client_sock);
                    continue;
                }
                nickname[nread] = '\0';

                // check if there is a duplicated nickname
                if (is_nickname_taken(nickname)) {
                    const char *error_msg = "nickname already in use. please choose another one.\n";
                    SSL_write(ssl, error_msg, strnlen("nickname already in use. please choose another one.\n", sizeof("nickname already in use. please choose another one.\n")));
                    SSL_shutdown(ssl);
                    SSL_free(ssl);
                    close(client_sock);
                    continue;
                }

                // add client to the list
                struct connection *new_conn = malloc(sizeof(struct connection));
                new_conn->socket = client_sock;
                new_conn->ssl = ssl;
                strncpy(new_conn->nickname, nickname, MAX_NICKNAME);
                new_conn->nickname[MAX_NICKNAME - 1] = '\0'; // ensure null termination
                LIST_INSERT_HEAD(&connection_list, new_conn, entries);

                // notify only the first user
                if (first_user_connected == 0) {
                    SSL_write(ssl, "you are the first user to join the chat.\n", 41);
                    first_user_connected = 1;
                } else {
                    char join_message[MESSAGE_SIZE];
                    snprintf(join_message, sizeof(join_message), "%s has joined the chat.", nickname);
                    broadcast_message(NULL, join_message);
                }

                printf("client '%s' connected.\n", nickname);
            }

            // handle messages from connected clients
            LIST_FOREACH(conn, &connection_list, entries) {
                if (FD_ISSET(conn->socket, &readset)) {
                    char buffer[MESSAGE_SIZE];
                    ssize_t nread = SSL_read(conn->ssl, buffer, sizeof(buffer) - 1);
                    if (nread <= 0) {
                        printf("client '%s' disconnected.\n", conn->nickname);
                        char leave_message[MESSAGE_SIZE];
                        snprintf(leave_message, sizeof(leave_message), "%s has left the chat.", conn->nickname);
                        broadcast_message(NULL, leave_message);

                        SSL_free(conn->ssl);
                        close(conn->socket);
                        LIST_REMOVE(conn, entries);
                        free(conn);
                    } else {
                        buffer[nread] = '\0';
                        broadcast_message(conn, buffer);
                    }
                }
            }
        }
    }

    // cleanup
    close(server_socket);
    SSL_CTX_free(ctx);
    EVP_cleanup();
    return 0;
}