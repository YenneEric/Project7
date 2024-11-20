#include <openssl/ssl.h>
#include <openssl/err.h>
#include <stdio.h>
#include <string.h>
#include <unistd.h>
#include <arpa/inet.h>
#include <sys/select.h>
#include "inet.h"
#include "common.h"

#define MAX_CHAT_ROOMS 10
#define BUFFER_SIZE 512

// Structure to hold chat room information
typedef struct {
    char topic[MAX_TOPIC];
    int port;
    char ip[INET_ADDRSTRLEN];
} ChatRoom;

ChatRoom chat_rooms[MAX_CHAT_ROOMS];
int num_rooms = 0;

// Initialize the OpenSSL library
void initialize_ssl_library() {
    SSL_load_error_strings();
    OpenSSL_add_ssl_algorithms();
}

// Create an SSL context for the Directory Server
SSL_CTX *create_ssl_context() {
    SSL_CTX *ctx = SSL_CTX_new(TLS_server_method());
    if (!ctx) {
        perror("Unable to create SSL context");
        ERR_print_errors_fp(stderr);
        exit(EXIT_FAILURE);
    }

    // Load server certificate and private key
    if (SSL_CTX_use_certificate_file(ctx, DIR_CERT, SSL_FILETYPE_PEM) <= 0 ||
        SSL_CTX_use_PrivateKey_file(ctx, DIR_KEY, SSL_FILETYPE_PEM) <= 0) {
        ERR_print_errors_fp(stderr);
        exit(EXIT_FAILURE);
    }

    return ctx;
}

// Register a chat room
void register_chat_room(const char *topic, int port, const char *ip, SSL *ssl) {
    if (num_rooms >= MAX_CHAT_ROOMS) {
        SSL_write(ssl, "E: Chat room limit reached\n", strlen("E: Chat room limit reached\n"));
        return;
    }

    for (int i = 0; i < num_rooms; i++) {
        if (strcmp(chat_rooms[i].topic, topic) == 0) {
            SSL_write(ssl, "E: Duplicate topic\n", strlen("E: Duplicate topic\n"));
            return;
        }
    }

    strcpy(chat_rooms[num_rooms].topic, topic);
    chat_rooms[num_rooms].port = port;
    strcpy(chat_rooms[num_rooms].ip, ip);
    num_rooms++;

    SSL_write(ssl, "S: Registered successfully\n", strlen("S: Registered successfully\n"));
}

// Deregister a chat room
void deregister_chat_room(const char *topic, int port, const char *ip, SSL *ssl) {
    for (int i = 0; i < num_rooms; i++) {
        if (strcmp(chat_rooms[i].topic, topic) == 0 && chat_rooms[i].port == port &&
            strcmp(chat_rooms[i].ip, ip) == 0) {
            for (int j = i; j < num_rooms - 1; j++) {
                chat_rooms[j] = chat_rooms[j + 1];
            }
            num_rooms--;
            SSL_write(ssl, "S: Deregistered successfully\n", strlen("S: Deregistered successfully\n"));
            return;
        }
    }

    SSL_write(ssl, "E: Chat room not found\n", strlen("E: Chat room not found\n"));
}

// List all active chat rooms
void list_chat_rooms(SSL *ssl) {
    char response[BUFFER_SIZE] = "";

    if (num_rooms == 0) {
        strcpy(response, "No active chat rooms available.\n");
    } else {
        for (int i = 0; i < num_rooms; i++) {
            char entry[BUFFER_SIZE];
            snprintf(entry, sizeof(entry), "Topic: %s, Port: %d, IP: %s\n",
                     chat_rooms[i].topic, chat_rooms[i].port, chat_rooms[i].ip);
            strcat(response, entry);
        }
    }

    SSL_write(ssl, response, strlen(response));
}

int main() {
    initialize_ssl_library();

    SSL_CTX *ctx = create_ssl_context();
    int server_sock, client_sock, max_sd, activity;
    struct sockaddr_in address, client_addr;
    socklen_t addrlen = sizeof(client_addr);
    fd_set readfds;

    // Create the Directory Server socket
    if ((server_sock = socket(AF_INET, SOCK_STREAM, 0)) == 0) {
        perror("Socket creation failed");
        exit(EXIT_FAILURE);
    }

    address.sin_family = AF_INET;
    address.sin_addr.s_addr = INADDR_ANY;
    address.sin_port = htons(DIR_SERVER_PORT);

    if (bind(server_sock, (struct sockaddr *)&address, sizeof(address)) < 0) {
        perror("Bind failed");
        exit(EXIT_FAILURE);
    }

    if (listen(server_sock, MAX_CHAT_ROOMS) < 0) {
        perror("Listen failed");
        exit(EXIT_FAILURE);
    }

    printf("Directory Server started on port %d\n", DIR_SERVER_PORT);

    for (;;) {
        FD_ZERO(&readfds);
        FD_SET(server_sock, &readfds);
        max_sd = server_sock;

        activity = select(max_sd + 1, &readfds, NULL, NULL, NULL);

        if (FD_ISSET(server_sock, &readfds)) {
            client_sock = accept(server_sock, (struct sockaddr *)&client_addr, &addrlen);
            if (client_sock < 0) {
                perror("Accept failed");
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

            // Read client request
            char buffer[BUFFER_SIZE];
            int nread = SSL_read(ssl, buffer, sizeof(buffer) - 1);
            if (nread <= 0) {
                SSL_free(ssl);
                close(client_sock);
                continue;
            }
            buffer[nread] = '\0';

            // Parse and process the request
            switch (buffer[0]) {
                case 'R': {  // Register chat room
                    char topic[MAX_TOPIC];
                    int port;
                    sscanf(buffer + 1, "%s %d", topic, &port);
                    register_chat_room(topic, port, inet_ntoa(client_addr.sin_addr), ssl);
                    break;
                }
                case 'D': {  // Deregister chat room
                    char topic[MAX_TOPIC];
                    int port;
                    sscanf(buffer + 1, "%s %d", topic, &port);
                    deregister_chat_room(topic, port, inet_ntoa(client_addr.sin_addr), ssl);
                    break;
                }
                case 'L': {  // List chat rooms
                    list_chat_rooms(ssl);
                    break;
                }
                default:
                    SSL_write(ssl, "E: Invalid command\n", strlen("E: Invalid command\n"));
                    break;
            }

            SSL_free(ssl);
            close(client_sock);
        }
    }

    close(server_sock);
    SSL_CTX_free(ctx);
    EVP_cleanup();

    return 0;
}
