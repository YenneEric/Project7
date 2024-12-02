//all works

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <errno.h>
#include <arpa/inet.h>
#include <openssl/ssl.h>
#include <openssl/err.h>
#include <signal.h>
#include "inet.h"
#include "common.h"


struct chatServerRooms {
    char topic[MAX_TOPIC];
    int port;
    char ip[INET_ADDRSTRLEN];
};

struct chatServerRooms chatServers[MAX_CHAT_SERVERS];
int chatServerRooms_count = 0;
int sockfd;

// function to cr   eate SSL context
SSL_CTX *create_ssl_context() {
    SSL_CTX *ctx = SSL_CTX_new(TLS_server_method());
    if (!ctx) {
        perror("Unable to create SSL context");
        ERR_print_errors_fp(stderr);
        exit(1);
    }
    SSL_CTX_set_min_proto_version(ctx, TLS1_3_VERSION);
    return ctx;
}

// function to configure SSL context with cert and key
void configure_ssl_context(SSL_CTX *ctx) {
    if (SSL_CTX_use_certificate_file(ctx, "directory_server.crt", SSL_FILETYPE_PEM) <= 0) {
        ERR_print_errors_fp(stderr);
        exit(EXIT_FAILURE);
    }
    if (SSL_CTX_use_PrivateKey_file(ctx, "directory_server.key", SSL_FILETYPE_PEM) <= 0) {
        ERR_print_errors_fp(stderr);
        exit(EXIT_FAILURE);
    }
    if (SSL_CTX_load_verify_locations(ctx, "ca.crt", NULL) <= 0) {
        ERR_print_errors_fp(stderr);
        exit(EXIT_FAILURE);
    }
    SSL_CTX_set_verify(ctx, SSL_VERIFY_PEER, NULL);
}


// function to cleanup and exit gracefully
void cleanup_and_exit() {
    close(sockfd);
    printf("\nDirectory Server shutting down...\n");
    exit(0);
}

// signal handler for SIGINT to cleanup before exiting
void handle_sigint(int sig) {
    (void)sig;
    cleanup_and_exit();
}

// function to check if the port is already in use
int is_port_taken(int port) {
    for (int i = 0; i < chatServerRooms_count; i++) {
        if (chatServers[i].port == port) {
            return 1; // Port is already in use
        }
    }
    return 0; // Port is available
}

// function to register a new chat room server
void register_chatServerRooms(char *topic, int port, char *ip, SSL *ssl) {
    printf("Debug: Received registration message\n");

    // check if the port is already in use
    if (is_port_taken(port)) {
        fprintf(stderr, "Error: Port %d is already in use. Registration failed.\n", port);
        SSL_write(ssl, "E: Port already in use\n", strlen("E: Port already in use\n"));
        return;
    }

    // check if the port is valid
    if (port <= 0) {
        fprintf(stderr, "Error: Port is invalid (%d). Registration failed.\n", port);
        SSL_write(ssl, "E: Invalid port\n", strlen("E: Invalid port\n"));
        return;
    }

    // check for duplicate topics
    for (int i = 0; i < chatServerRooms_count; i++) {
        if (strncmp(chatServers[i].topic, topic, MAX_TOPIC) == 0) {
            printf("Directory Server: Duplicate topic '%s'. Registration failed.\n", topic);
            SSL_write(ssl, "E: Duplicate topic\n", strlen("E: Duplicate topic\n"));
            return;
        }
    }

    // safely store topic, port, and IP address
    snprintf(chatServers[chatServerRooms_count].topic, MAX_TOPIC, "%s", topic);
    chatServers[chatServerRooms_count].port = port;
    snprintf(chatServers[chatServerRooms_count].ip, INET_ADDRSTRLEN, "%s", ip);
    chatServerRooms_count++;

    // print stored rooms
    for (int i = 0; i < chatServerRooms_count; i++) {
        printf("Stored room #%d: Topic='%s', Port=%d, IP='%s'\n",
               i, chatServers[i].topic, chatServers[i].port, chatServers[i].ip);
    }

    // send success response to client
    SSL_write(ssl, "S: Registered successfully\n", strlen("S: Registered successfully\n"));
    printf("Registered chat room: Topic='%s', Port=%d, IP='%s'\n", topic, port, ip);
}

// function to deregister a chat room server by topic
void deregister_chatServerRooms(char *topic, SSL *ssl) {
    for (int i = 0; i < chatServerRooms_count; i++) {
        if (strncmp(chatServers[i].topic, topic, MAX_TOPIC) == 0) {
            // shift remaining rooms to fill the spot
            for (int j = i; j < chatServerRooms_count - 1; j++) {
                chatServers[j] = chatServers[j + 1];
            }
            chatServerRooms_count--;
            SSL_write(ssl, "S: Deregistered successfully\n", strlen("S: Deregistered successfully\n"));
            printf("Deregistered chat room: Topic='%s'\n", topic);
            return;
        }
    }

    // handle topic not found for deregistration
    SSL_write(ssl, "E: Topic not found\n", strlen("E: Topic not found\n"));
    printf("Directory Server: Topic '%s' not found for deregistration.\n", topic);
}

// function to list available chat servers
void listOfServers(SSL *ssl) {
    char response[RESPONSE_SIZE];
    memset(response, 0, sizeof(response));

    // check if there are active chat rooms
    if (chatServerRooms_count == 0) {
        snprintf(response, sizeof(response), "No active chat rooms available.\n");
    } else {
        // iterate over and append available chat rooms
        for (int i = 0; i < chatServerRooms_count; i++) {
            char entry[RESPONSE_SIZE];
            snprintf(entry, sizeof(entry), "Topic: %s, Port: %d\n", chatServers[i].topic, chatServers[i].port);
            strncat(response, entry, sizeof(response) - strnlen(response, sizeof(response)) - 1); 
        }
    }

    // send the list of servers to the client
    SSL_write(ssl, response, strlen(response));
}


int main() {
    int port = DIR_SERVER_PORT;
    struct sockaddr_in serv_addr;
    SSL_CTX *ctx;

    // setup SIGINT signal handler
    signal(SIGINT, handle_sigint);

    // initialize OpenSSL
    SSL_library_init();
    OpenSSL_add_ssl_algorithms();
    SSL_load_error_strings();

    // create SSL context and configure it
    ctx = create_ssl_context();
    configure_ssl_context(ctx);

    // create and bind server socket
    if ((sockfd = socket(AF_INET, SOCK_STREAM, 0)) < 0) {
        perror("Unable to open socket");
        exit(1);
    }

    int opt = 1;
    setsockopt(sockfd, SOL_SOCKET, SO_REUSEADDR, &opt, sizeof(opt));

    memset(&serv_addr, 0, sizeof(serv_addr));
    serv_addr.sin_family = AF_INET;
    serv_addr.sin_addr.s_addr = htonl(INADDR_ANY);
    serv_addr.sin_port = htons(port);

    if (bind(sockfd, (struct sockaddr *)&serv_addr, sizeof(serv_addr)) < 0) {
        perror("Unable to bind socket");
        cleanup_and_exit();
    }

    // start listening for connections
    if (listen(sockfd, 5) < 0) {
        perror("Unable to listen on socket");
        cleanup_and_exit();
    }

    printf("Directory Server listening on port %d...\n", port);

    while (1) {
        struct sockaddr_in cli_addr;
        socklen_t cli_len = sizeof(cli_addr);
        int client_sock = accept(sockfd, (struct sockaddr *)&cli_addr, &cli_len);
        if (client_sock < 0) {
            perror("Error accepting connection");
            continue;
        }

        // create SSL object and handle SSL handshake
        SSL *ssl = SSL_new(ctx);
        SSL_set_fd(ssl, client_sock);

        if (SSL_accept(ssl) <= 0) {
            ERR_print_errors_fp(stderr);
            SSL_free(ssl);
            close(client_sock);
            continue;
        }

        char buffer[RESPONSE_SIZE];
        memset(buffer, 0, sizeof(buffer));

        // read data from client
        if (SSL_read(ssl, buffer, sizeof(buffer)) <= 0) {
            perror("Error reading from client");
            SSL_free(ssl);
            close(client_sock);
            continue;
        }

        // process client requests based on first character
        if (buffer[0] == 'R') {
            char topic[MAX_TOPIC];
            int clientPort;
            sscanf(buffer + 1, "%s %d", topic, &clientPort);
            register_chatServerRooms(topic, clientPort, inet_ntoa(cli_addr.sin_addr), ssl);
        } else if (buffer[0] == 'L') {
            listOfServers(ssl);
        } else if (buffer[0] == 'D') {
            char topic[MAX_TOPIC];
            sscanf(buffer + 1, "%s", topic);
            deregister_chatServerRooms(topic, ssl);
        } else {
            SSL_write(ssl, "Invalid request\n", strlen("Invalid request\n"));
        }

        // clean up and close connection
        SSL_shutdown(ssl);
        SSL_free(ssl);
        close(client_sock);
    }

    // close server socket and free SSL context
    close(sockfd);
    SSL_CTX_free(ctx);
    EVP_cleanup();

    return 0;
}
