#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <arpa/inet.h>
#include <openssl/ssl.h>
#include <openssl/err.h>
#include "inet.h"
#include "common.h"

// structure to hold chat room information
struct chat_room {
    char topic[MAX_NICKNAME];
    int port;
    char ip[INET_ADDRSTRLEN];
};

struct chat_room chat_rooms[MAX_CHAT_ROOMS];
int num_rooms = 0;

// function to create an SSL context
SSL_CTX *create_ssl_context() {
    SSL_CTX *ctx = SSL_CTX_new(TLS_client_method());
    if (!ctx) {
        perror("unable to create SSL context");
        ERR_print_errors_fp(stderr);
        exit(EXIT_FAILURE);
    }

    // set the TLS version to 1.3
    SSL_CTX_set_min_proto_version(ctx, TLS1_3_VERSION);
    SSL_CTX_set_max_proto_version(ctx, TLS1_3_VERSION);

    return ctx;
}

// function to configure the SSL context
void configure_ssl_context(SSL_CTX *ctx) {
    // Load the CA certificate
    if (SSL_CTX_load_verify_locations(ctx, CA_CERT, NULL) <= 0) {
        ERR_print_errors_fp(stderr);
        exit(EXIT_FAILURE);
    }

    // Set verification mode
    SSL_CTX_set_verify(ctx, SSL_VERIFY_PEER, NULL);

    // Set default paths for additional certificate validation
    if (SSL_CTX_set_default_verify_paths(ctx) <= 0) {
        ERR_print_errors_fp(stderr);
        exit(EXIT_FAILURE);
    }
}

// function to query the directory server for chat rooms
void query_chat_rooms() {
    int sockfd;
    struct sockaddr_in dir_addr;
    SSL_CTX *ctx;
    SSL *ssl;
    char message[] = "L";  // request to list chat rooms
    char response[RESPONSE_SIZE];

    // initialize OpenSSL
    ctx = create_ssl_context();
    configure_ssl_context(ctx);

    // create socket
    if ((sockfd = socket(AF_INET, SOCK_STREAM, 0)) < 0) {
        perror("cannot create socket for directory query");
        SSL_CTX_free(ctx);
        return;
    }

    memset(&dir_addr, 0, sizeof(dir_addr));
    dir_addr.sin_family = AF_INET;
    dir_addr.sin_addr.s_addr = inet_addr(SERV_HOST_ADDR);
    dir_addr.sin_port = htons(DIR_SERVER_PORT);

    // connect to the Directory Server
    if (connect(sockfd, (struct sockaddr *)&dir_addr, sizeof(dir_addr)) < 0) {
        perror("cannot connect to directory server");
        close(sockfd);
        SSL_CTX_free(ctx);
        return;
    }

    // create SSL object and attach it to the socket
    ssl = SSL_new(ctx);
    SSL_set_fd(ssl, sockfd);

    // perform SSL handshake
    if (SSL_connect(ssl) <= 0) {
        ERR_print_errors_fp(stderr);
        SSL_free(ssl);
        close(sockfd);
        SSL_CTX_free(ctx);
        return;
    }
    
    // validate CN
    X509 *dirCert = SSL_get_peer_certificate(ssl);
    if (X509_check_host(dirCert, DIRECTORY_NAME, 0, 0, NULL) != 1) {
      fprintf(stderr, "Error: CN of server is not 'DirectoryServer'\n");
      SSL_free(ssl);
      close(sockfd);
      SSL_CTX_free(ctx);
      exit(1);
    }
    X509_free(dirCert);

    // send LIST request
    SSL_write(ssl, message, strnlen(message, sizeof(message)));

    // read response
    ssize_t nread = SSL_read(ssl, response, sizeof(response) - 1);
    if (nread <= 0) {
        perror("error reading from directory server");
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

// function to connect to a chat server
SSL *connect_to_chat_server(const char *ip, int port, const char *selected_topic, SSL_CTX *ctx) {
    int sockfd;
    struct sockaddr_in serv_addr;

    if ((sockfd = socket(AF_INET, SOCK_STREAM, 0)) < 0) {
        perror("client: can't open stream socket");
        return NULL;
    }

    memset(&serv_addr, 0 , sizeof(serv_addr));
    serv_addr.sin_family = AF_INET;
    serv_addr.sin_addr.s_addr = inet_addr(ip);
    serv_addr.sin_port = htons(port);

    // connect to the server
    if (connect(sockfd, (struct sockaddr *)&serv_addr, sizeof(serv_addr)) < 0) {
        perror("client: can't connect to server");
        close(sockfd);
        return NULL;
    }

    SSL *ssl = SSL_new(ctx);
    SSL_set_fd(ssl, sockfd);

    // perform SSL handshake
    if (SSL_connect(ssl) <= 0) {
        ERR_print_errors_fp(stderr);
        SSL_free(ssl);
        close(sockfd);
        return NULL;
    }
    
    // validate CN
    X509 *chatCert = SSL_get_peer_certificate(ssl);
    if (X509_check_host(chatCert, selected_topic, 0, 0, NULL) != 1) {
      fprintf(stderr, "Error: CN of chat server does not match selected topic '%s'\n", selected_topic);
      SSL_free(ssl);
      return NULL;
    }
    X509_free(chatCert);

    return ssl;
}

// main function to run the client
// main function to run the client
int main() {
    char message[MAX] = {'\0'};
    char in_message[MESSAGE_SIZE] = {'\0'};
    char selected_topic[MAX_NICKNAME] = {'\0'};
    fd_set readset;
    SSL_CTX *ctx;
    SSL *ssl;
    char nickname[MAX_NICKNAME];
    char c;

    // initialize OpenSSL
    SSL_library_init();
    OpenSSL_add_ssl_algorithms();
    SSL_load_error_strings();

    // query the Directory Server for available chat rooms
    query_chat_rooms();

    fprintf(stdout, "\nAvailable Chat Rooms:\n");
    for (int i = 0; i < num_rooms; i++) {
        fprintf(stdout, "%d. Topic: %s, Port: %d\n", i + 1, chat_rooms[i].topic, chat_rooms[i].port);
    }

    fprintf(stdout, "Enter the port number of the chat room to connect to: ");
    int port;
    if (scanf("%d", &port) != 1) {
        fprintf(stderr, "Invalid input for port number.\n");
        return -1;
    }
    getchar(); // consume newline character

    char *selected_ip = NULL;
    for (int i = 0; i < num_rooms; i++) {
        if (chat_rooms[i].port == port) {
            selected_ip = chat_rooms[i].ip;
            sprintf(selected_topic, "%s", chat_rooms[i].topic);
            break;
        }
    }

    if (!selected_ip) {
        fprintf(stderr, "No chat room found with port %d.\n", port);
        return -1;
    }

    ctx = create_ssl_context();
    configure_ssl_context(ctx);

    // connect to the selected chat server
    ssl = connect_to_chat_server(selected_ip, port, selected_topic, ctx);
    if (!ssl) {
        fprintf(stderr, "Failed to connect to chat server on port %d.\n", port);
        SSL_CTX_free(ctx);
        return -1;
    }

    fprintf(stdout, "What is your nickname (up to 50 characters): ");
    if (scanf("%49[^\n]", nickname) != 1) { // Use scanf to read the nickname directly
        fprintf(stderr, "Failed to read nickname.\n");
        SSL_shutdown(ssl);
        SSL_free(ssl);
        SSL_CTX_free(ctx);
        return -1;
    }
    scanf("%c", &c);
    if (c != '\n') {
        scanf("%*[^\n]%*c");
        printf("Warning: nickname too long, truncated.\n");
    }

    // send nickname to the server
    SSL_write(ssl, nickname, strnlen(nickname, sizeof(nickname)));

    for (;;) {
        FD_ZERO(&readset);
        FD_SET(STDIN_FILENO, &readset);
        FD_SET(SSL_get_fd(ssl), &readset);

        // wait for activity on sockets
        if (select(SSL_get_fd(ssl) + 1, &readset, NULL, NULL, NULL) > 0) {
            // check for input from the user
            if (FD_ISSET(STDIN_FILENO, &readset)) {
                if (scanf(" %99[^\n]", message) == EOF) { // Read until newline
                    fprintf(stderr, "Error reading message.\n");
                    break;
                }
                scanf("%c", &c);
                if (c != '\n')  {
                    scanf("%*[^\n]%*c");
                    printf("Warning: message too long, truncated.\n");
                }
                SSL_write(ssl, message, strnlen(message, sizeof(message)));
            }

            // check for messages from the server
            if (FD_ISSET(SSL_get_fd(ssl), &readset)) {
                ssize_t nread = SSL_read(ssl, in_message, MESSAGE_SIZE - 1);
                if (nread <= 0) {
                    if (nread == 0) {
                        fprintf(stdout, "Server closed the connection.\n");
                    } else {
                        perror("Error reading from server");
                    }
                    break;
                }
                in_message[nread] = '\0';
                fprintf(stdout, "%s\n", in_message);
            }
        }
    }

    // clean up and close connections
    SSL_shutdown(ssl);
    SSL_free(ssl);
    SSL_CTX_free(ctx);
    return 0;
}