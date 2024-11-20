#include <openssl/ssl.h>
#include <openssl/err.h>
#include <stdio.h>
#include <string.h>
#include <unistd.h>
#include <arpa/inet.h>
#include <sys/select.h>
#include <sys/types.h>
#include <stdlib.h>
#include "inet.h"
#include "common.h"

#define MAX_CLIENTS 10
#define BUFFER_SIZE 512
#define MAX_NICKNAME 51  // Add this line to fix the error


// Structure for storing client information
typedef struct {
    int socket;
    SSL *ssl;
    char nickname[MAX_NICKNAME];
} Client;

Client clients[MAX_CLIENTS];

// Initialize the OpenSSL library
void initialize_ssl_library() {
    SSL_load_error_strings();
    OpenSSL_add_ssl_algorithms();
}

// Create an SSL context for the server
SSL_CTX *create_ssl_context() {
    SSL_CTX *ctx = SSL_CTX_new(TLS_server_method());
    if (!ctx) {
        perror("Unable to create SSL context");
        ERR_print_errors_fp(stderr);
        exit(EXIT_FAILURE);
    }

    // Load server certificate and private key
    if (SSL_CTX_use_certificate_file(ctx, CHAT_CERT, SSL_FILETYPE_PEM) <= 0 ||
        SSL_CTX_use_PrivateKey_file(ctx, CHAT_KEY, SSL_FILETYPE_PEM) <= 0) {
        ERR_print_errors_fp(stderr);
        exit(EXIT_FAILURE);
    }

    return ctx;
}

// Broadcast a message to all connected clients except the sender
void broadcast_message(Client *sender, const char *message) {
    for (int i = 0; i < MAX_CLIENTS; i++) {
        if (clients[i].socket != 0 && clients[i].socket != sender->socket) {
            SSL_write(clients[i].ssl, message, strlen(message));
        }
    }
}

// Remove a client from the clients array
void remove_client(int client_index) {
    SSL_shutdown(clients[client_index].ssl);
    SSL_free(clients[client_index].ssl);
    close(clients[client_index].socket);
    clients[client_index].socket = 0;
    memset(&clients[client_index], 0, sizeof(Client));
}

int main(int argc, char **argv) {
    if (argc < 3) {
        fprintf(stderr, "Usage: %s <chat room name> <port>\n", argv[0]);
        exit(EXIT_FAILURE);
    }

    char *topic = argv[1];
    int port = atoi(argv[2]);

    initialize_ssl_library();

    SSL_CTX *ctx = create_ssl_context();
    int server_socket, max_sd, activity, new_socket, addrlen;
    struct sockaddr_in address;
    fd_set readfds;
    char buffer[BUFFER_SIZE];

    memset(clients, 0, sizeof(clients));

    // Create a socket for the server
    if ((server_socket = socket(AF_INET, SOCK_STREAM, 0)) == 0) {
        perror("Socket creation failed");
        exit(EXIT_FAILURE);
    }

    address.sin_family = AF_INET;
    address.sin_addr.s_addr = INADDR_ANY;
    address.sin_port = htons(port);

    // Bind the socket to the port
    if (bind(server_socket, (struct sockaddr *)&address, sizeof(address)) < 0) {
        perror("Bind failed");
        exit(EXIT_FAILURE);
    }

    if (listen(server_socket, MAX_CLIENTS) < 0) {
        perror("Listen failed");
        exit(EXIT_FAILURE);
    }

    printf("Chat server '%s' started on port %d\n", topic, port);
    addrlen = sizeof(address);

    for (;;) {
        FD_ZERO(&readfds);
        FD_SET(server_socket, &readfds);
        max_sd = server_socket;

        for (int i = 0; i < MAX_CLIENTS; i++) {
            int sd = clients[i].socket;
            if (sd > 0) FD_SET(sd, &readfds);
            if (sd > max_sd) max_sd = sd;
        }

        activity = select(max_sd + 1, &readfds, NULL, NULL, NULL);

        if (FD_ISSET(server_socket, &readfds)) {
            if ((new_socket = accept(server_socket, (struct sockaddr *)&address, (socklen_t *)&addrlen)) < 0) {
                perror("Accept failed");
                exit(EXIT_FAILURE);
            }

            // Initialize SSL for the new connection
            SSL *ssl = SSL_new(ctx);
            SSL_set_fd(ssl, new_socket);

            if (SSL_accept(ssl) <= 0) {
                ERR_print_errors_fp(stderr);
                SSL_free(ssl);
                close(new_socket);
                continue;
            }

            // Add the new client to the clients array
            for (int i = 0; i < MAX_CLIENTS; i++) {
                if (clients[i].socket == 0) {
                    clients[i].socket = new_socket;
                    clients[i].ssl = ssl;
                    printf("New client connected on socket %d\n", new_socket);

                    // Ask for and receive the client's nickname
                    int nread = SSL_read(ssl, clients[i].nickname, MAX_NICKNAME - 1);
                    if (nread > 0) {
                        clients[i].nickname[nread] = '\0';
                        char join_msg[BUFFER_SIZE];
                        snprintf(join_msg, BUFFER_SIZE, "%s has joined the chat\n", clients[i].nickname);
                        broadcast_message(&clients[i], join_msg);
                    } else {
                        remove_client(i);
                    }
                    break;
                }
            }
        }

        for (int i = 0; i < MAX_CLIENTS; i++) {
            int sd = clients[i].socket;
            if (sd == 0) continue;

            if (FD_ISSET(sd, &readfds)) {
                int nread = SSL_read(clients[i].ssl, buffer, BUFFER_SIZE - 1);
                if (nread <= 0) {
                    printf("Client %s disconnected\n", clients[i].nickname);
                    char leave_msg[BUFFER_SIZE];
                    snprintf(leave_msg, BUFFER_SIZE, "%s has left the chat\n", clients[i].nickname);
                    broadcast_message(&clients[i], leave_msg);
                    remove_client(i);
                } else {
                    buffer[nread] = '\0';
                    char message[BUFFER_SIZE];
                    snprintf(message, BUFFER_SIZE, "%s: %s", clients[i].nickname, buffer);
                    broadcast_message(&clients[i], message);
                }
            }
        }
    }

    close(server_socket);
    SSL_CTX_free(ctx);
    EVP_cleanup();
    return 0;
}
