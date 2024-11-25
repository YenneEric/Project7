#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <errno.h>
#include <arpa/inet.h>
#include <openssl/ssl.h>
#include <openssl/err.h>
#include <signal.h>

#define DEFAULT_PORT 2222
#define RESPONSE_SIZE 512
#define MAX_CHAT_SERVERS 10
#define MAX_TOPIC 100

#define DIR_CERT "directory_server_cert.pem"
#define DIR_KEY "directory_server_key.pem"

// Structure to hold chat room information
struct chatServerRooms {
    char topic[MAX_TOPIC];
    int port;
    char ip[INET_ADDRSTRLEN];
};

struct chatServerRooms chatServers[MAX_CHAT_SERVERS];
int chatServerRooms_count = 0;
int sockfd; // Global server socket for cleanup

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
    if (SSL_CTX_use_certificate_file(ctx, DIR_CERT, SSL_FILETYPE_PEM) <= 0) {
        ERR_print_errors_fp(stderr);
        exit(EXIT_FAILURE);
    }

    if (SSL_CTX_use_PrivateKey_file(ctx, DIR_KEY, SSL_FILETYPE_PEM) <= 0) {
        ERR_print_errors_fp(stderr);
        exit(EXIT_FAILURE);
    }
}

void cleanup_and_exit() {
    close(sockfd);
    printf("\nDirectory Server shutting down...\n");
    exit(0);
}

void handle_sigint(int sig) {
    (void)sig; // Suppress unused parameter warning
    cleanup_and_exit();
}

void register_chatServerRooms(char *topic, int port, char *ip, SSL *ssl) {
    if (chatServerRooms_count >= MAX_CHAT_SERVERS) {
        SSL_write(ssl, "E: Chat room limit reached\n", strlen("E: Chat room limit reached\n"));
        return;
    }

    for (int i = 0; i < chatServerRooms_count; i++) {
        if (strcmp(chatServers[i].topic, topic) == 0) {
            SSL_write(ssl, "E: Duplicate topic\n", strlen("E: Duplicate topic\n"));
            return;
        }
    }

    strcpy(chatServers[chatServerRooms_count].topic, topic);
    chatServers[chatServerRooms_count].port = port;
    strcpy(chatServers[chatServerRooms_count].ip, ip);
    chatServerRooms_count++;

    SSL_write(ssl, "S: Registered successfully\n", strlen("S: Registered successfully\n"));
    printf("Registered chat room: Topic='%s', Port=%d, IP=%s\n", topic, port, ip);
}

void listOfServers(SSL *ssl) {
    char response[RESPONSE_SIZE];
    memset(response, 0, sizeof(response));

    if (chatServerRooms_count == 0) {
        snprintf(response, sizeof(response), "No active chat rooms available.\n");
    } else {
        for (int i = 0; i < chatServerRooms_count; i++) {
            char entry[RESPONSE_SIZE / MAX_CHAT_SERVERS]; // Avoid buffer overflow
            snprintf(entry, sizeof(entry), "Topic: %s, Port: %d\n", chatServers[i].topic, chatServers[i].port);
            strncat(response, entry, sizeof(response) - strlen(response) - 1);
        }
    }

    SSL_write(ssl, response, strlen(response));
}

int main(int argc, char **argv) {
    int port = DEFAULT_PORT;
    if (argc > 1) {
        port = atoi(argv[1]);
        if (port <= 0) {
            fprintf(stderr, "Invalid port number.\n");
            exit(EXIT_FAILURE);
        }
    }

    struct sockaddr_in serv_addr;
    SSL_CTX *ctx;

    signal(SIGINT, handle_sigint);

    // Initialize OpenSSL
    SSL_library_init();
    OpenSSL_add_ssl_algorithms();
    SSL_load_error_strings();

    ctx = create_ssl_context();
    configure_ssl_context(ctx);

    if ((sockfd = socket(AF_INET, SOCK_STREAM, 0)) < 0) {
        perror("Unable to open socket");
        exit(EXIT_FAILURE);
    }

    int opt = 1;
    setsockopt(sockfd, SOL_SOCKET, SO_REUSEADDR, &opt, sizeof(opt));

    memset(&serv_addr, 0, sizeof(serv_addr));
    serv_addr.sin_family = AF_INET;
    serv_addr.sin_addr.s_addr = INADDR_ANY;
    serv_addr.sin_port = htons(port);

    if (bind(sockfd, (struct sockaddr *)&serv_addr, sizeof(serv_addr)) < 0) {
        perror("Unable to bind socket");
        cleanup_and_exit();
    }

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

        if (SSL_read(ssl, buffer, sizeof(buffer)) <= 0) {
            perror("Error reading from client");
            SSL_free(ssl);
            close(client_sock);
            continue;
        }

        if (buffer[0] == 'R') {
            char topic[MAX_TOPIC];
            int port;
            sscanf(buffer + 1, "%s %d", topic, &port);
            register_chatServerRooms(topic, port, inet_ntoa(cli_addr.sin_addr), ssl);
        } else if (buffer[0] == 'L') {
            listOfServers(ssl);
        } else {
            SSL_write(ssl, "Invalid request\n", strlen("Invalid request\n"));
        }

        SSL_shutdown(ssl);
        SSL_free(ssl);
        close(client_sock);
    }

    close(sockfd);
    SSL_CTX_free(ctx);
    EVP_cleanup();

    return 0;
}
