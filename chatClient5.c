#include <openssl/ssl.h>
#include <openssl/err.h>
#include <stdio.h>
#include <string.h>
#include <unistd.h>
#include <arpa/inet.h>
#include <sys/select.h>
#include "inet.h"
#include "common.h"

#define MAX 100
#define MAX_NICKNAME 51


void initialize_ssl_library() {
    SSL_load_error_strings();
    OpenSSL_add_ssl_algorithms();
}

SSL_CTX *create_ssl_context() {
    SSL_CTX *ctx = SSL_CTX_new(TLS_client_method());
    if (!ctx) {
        perror("Unable to create SSL context");
        ERR_print_errors_fp(stderr);
        exit(EXIT_FAILURE);
    }
    return ctx;
}

void verify_certificate(SSL *ssl, const char *expected_name) {
    X509 *cert = SSL_get_peer_certificate(ssl);
    if (!cert) {
        fprintf(stderr, "No certificate presented by server\n");
        exit(EXIT_FAILURE);
    }

    char cert_name[256];
    X509_NAME_get_text_by_NID(X509_get_subject_name(cert), NID_commonName, cert_name, sizeof(cert_name));

    if (strcmp(cert_name, expected_name) != 0) {
        fprintf(stderr, "Certificate name mismatch: expected '%s', got '%s'\n", expected_name, cert_name);
        exit(EXIT_FAILURE);
    }

    X509_free(cert);
}

int connect_to_server(const char *ip, int port) {
    int sockfd;
    struct sockaddr_in serv_addr;

    if ((sockfd = socket(AF_INET, SOCK_STREAM, 0)) < 0) {
        perror("Cannot create socket");
        return -1;
    }

    memset(&serv_addr, 0, sizeof(serv_addr));
    serv_addr.sin_family = AF_INET;
    serv_addr.sin_port = htons(port);
    if (inet_pton(AF_INET, ip, &serv_addr.sin_addr) <= 0) {
        perror("Invalid address");
        close(sockfd);
        return -1;
    }

    if (connect(sockfd, (struct sockaddr *)&serv_addr, sizeof(serv_addr)) < 0) {
        perror("Connection failed");
        close(sockfd);
        return -1;
    }

    return sockfd;
}

int main() {
    initialize_ssl_library();

    SSL_CTX *ctx = create_ssl_context();
    SSL *ssl;
    int server_sock;
    char buffer[MAX];
    char nickname[MAX_NICKNAME];

    // Query the Directory Server for available chat rooms
    printf("Connecting to Directory Server...\n");
    server_sock = connect_to_server(SERV_HOST_ADDR, DIR_SERVER_PORT);
    if (server_sock == -1) {
        fprintf(stderr, "Failed to connect to Directory Server\n");
        return -1;
    }

    // Send 'LIST' request to Directory Server
    char list_request[] = "L";
    write(server_sock, list_request, strlen(list_request));

    // Read response from Directory Server
    int nread = read(server_sock, buffer, sizeof(buffer) - 1);
    if (nread <= 0) {
        perror("Error reading from Directory Server");
        close(server_sock);
        return -1;
    }
    buffer[nread] = '\0';

    // Parse chat room information
    printf("Available Chat Rooms:\n%s\n", buffer);
    close(server_sock);

    // Ask the user to select a chat room by port number
    int port;
    printf("Enter the port number of the chat room to connect to: ");
    scanf("%d", &port);
    getchar();  // Consume the newline character

    printf("Connecting to Chat Server on port %d...\n", port);
    server_sock = connect_to_server(SERV_HOST_ADDR, port);
    if (server_sock == -1) {
        fprintf(stderr, "Failed to connect to Chat Server on port %d\n", port);
        return -1;
    }

    ssl = SSL_new(ctx);
    SSL_set_fd(ssl, server_sock);

    if (SSL_connect(ssl) <= 0) {
        ERR_print_errors_fp(stderr);
        SSL_free(ssl);
        close(server_sock);
        SSL_CTX_free(ctx);
        return -1;
    }

    // Verify the server's certificate
    verify_certificate(ssl, "Chat Server");

    // Get the user's nickname
    printf("What is your nickname (up to %d characters): ", MAX_NICKNAME - 1);
    fgets(nickname, MAX_NICKNAME, stdin);
    nickname[strcspn(nickname, "\n")] = '\0';  // Remove trailing newline

    // Send the nickname to the Chat Server
    if (SSL_write(ssl, nickname, strlen(nickname)) <= 0) {
        perror("Error sending nickname to server");
        SSL_free(ssl);
        close(server_sock);
        SSL_CTX_free(ctx);
        return -1;
    }

    // Main chat loop
    fd_set readset;
    for (;;) {
        FD_ZERO(&readset);
        FD_SET(STDIN_FILENO, &readset);
        FD_SET(server_sock, &readset);

        if (select(server_sock + 1, &readset, NULL, NULL, NULL) > 0) {
            if (FD_ISSET(STDIN_FILENO, &readset)) {
                if (fgets(buffer, MAX, stdin) != NULL) {
                    buffer[strcspn(buffer, "\n")] = '\0';  // Remove trailing newline
                    if (SSL_write(ssl, buffer, strlen(buffer)) <= 0) {
                        perror("Error sending message to server");
                    }
                }
            }

            if (FD_ISSET(server_sock, &readset)) {
                nread = SSL_read(ssl, buffer, sizeof(buffer) - 1);
                if (nread <= 0) {
                    fprintf(stderr, "Server disconnected. Exiting.\n");
                    break;
                }
                buffer[nread] = '\0';
                printf("%s\n", buffer);
            }
        }
    }

    SSL_free(ssl);
    close(server_sock);
    SSL_CTX_free(ctx);
    EVP_cleanup();

    return 0;
}
