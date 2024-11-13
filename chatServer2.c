//22

#include <stdio.h>
#include <string.h>
#include <strings.h>
#include <sys/types.h>
#include <stdlib.h>
#include <unistd.h>
#include <sys/queue.h>  // For linked lists
#include <signal.h>     // For signal handling
#include "inet.h"
#include "common.h"

#define MAX_NICKNAME 51
#define MESSAGE_SIZE 256
#define MAX_TOPIC 100

void shutdownServer();


// Structure for holding client connection information
struct connection {
    int socket;
    char nickname[MAX_NICKNAME];
    LIST_ENTRY(connection) entries;  // Linked list structure
};

// Head of the connection list for holding the connection sockets
LIST_HEAD(connection_listhead, connection) connection_list;

// Flag to track if the "first user" message has already been sent
int first_user_msg_sent = 0;
int sockfd;  // Global socket variable for the server
int port;    // Global port variable for the server
char current_topic[MAX_TOPIC];  // Topic of the current server

// Function to register the server with the directory server
void register_with_directory(char *topic, int port) {
    int sockfd;
    struct sockaddr_in dir_addr;
    char message[MESSAGE_SIZE];
    char response[MESSAGE_SIZE];

    // Create socket for directory communication
    if ((sockfd = socket(AF_INET, SOCK_STREAM, 0)) < 0) {
        perror("Cannot create socket for directory registration");
        exit(1);
    }

    memset(&dir_addr, 0, sizeof(dir_addr));
    dir_addr.sin_family = AF_INET;
    dir_addr.sin_addr.s_addr = inet_addr(SERV_HOST_ADDR);  // Directory server IP
    dir_addr.sin_port = htons(DIR_SERVER_PORT);

    // Connect to the Directory Server
    if (connect(sockfd, (struct sockaddr *)&dir_addr, sizeof(dir_addr)) < 0) {
        perror("Cannot connect to directory server");
        close(sockfd);
        exit(1);
    }

    // Send registration message
    snprintf(message, sizeof(message), "R %s %d", topic, port);  // 'R' is for Register
    write(sockfd, message, strlen(message));

    // Read the response from the directory server
    ssize_t nread = read(sockfd, response, sizeof(response) - 1);
    if (nread <= 0) {
        perror("Error reading from directory server");
        close(sockfd);
        exit(1);
    }

    response[nread] = '\0';  // Null-terminate the response

    // Check for duplicate topic error
    if (strncmp(response, "E: Duplicate topic", 18) == 0) {
        fprintf(stdout, "Error: Duplicate topic. Server will shut down.\n");
        close(sockfd);
        shutdownServer();  // Shut down the server
        exit(1);
    } else if (strncmp(response, "S:", 2) == 0) {
       // fprintf(stdout, "Server registered successfully.\n");
    } else {
        fprintf(stdout, "Unexpected response: %s\n", response);
    }

    close(sockfd);
}


// Function to deregister the server from the directory server
void shutdownServer() {
    int removeSock;
    struct sockaddr_in dir_addr;
    char message[MESSAGE_SIZE];

    // Create a socket for directory communication
    if ((removeSock = socket(AF_INET, SOCK_STREAM, 0)) < 0) {
        perror("Cannot create socket for directory deregistration");
        return;
    }

    memset(&dir_addr, 0, sizeof(dir_addr));
    dir_addr.sin_family = AF_INET;
    dir_addr.sin_addr.s_addr = inet_addr(SERV_HOST_ADDR);  // Directory server IP
    dir_addr.sin_port = htons(DIR_SERVER_PORT);

    // Connect to the Directory Server
    if (connect(removeSock, (struct sockaddr *)&dir_addr, sizeof(dir_addr)) < 0) {
        perror("Cannot connect to directory server for deregistration");
        close(removeSock);
        return;
    }

    // Send 'D' message for Deregister with the port number
    snprintf(message, sizeof(message), "D %d %s", port, current_topic);  // 'D' is for Deregister
    write(removeSock, message, strlen(message));

    close(removeSock);  // Close the deregistration socket
    close(sockfd);      // Close the main server socket
    fprintf(stdout, "Server on port %d with topic '%s' deregistered and shut down.\n", port, current_topic);
    exit(0);
}

// Signal handler for Ctrl+C (SIGINT)
void handle_sigint(int sig) {
    char buffer[256];
    int len = snprintf(buffer, sizeof(buffer), "\nCaught signal %d (Ctrl+C). Deregistering the server...\n", sig);
    if (len > 0) {
        write(STDOUT_FILENO, buffer, (size_t) len);  // Cast len to size_t to match write's expected type
    }
    shutdownServer();
}

int main(int argc, char **argv) {

    if (argc < 3) {
        fprintf(stderr, "./chatServer2: \"topic\" <port> is the format that it must be entered\nTry again\n");
        exit(1);
    }
    
    char *topic = argv[1];
    port = atoi(argv[2]);  // Assign port to global variable
    strncpy(current_topic, topic, MAX_TOPIC);  // Set the global topic

    unsigned int clientlen;
    struct sockaddr_in client_addr, serv_addr;
    fd_set readset;

    // Initialize the list head
    LIST_INIT(&connection_list);

    // Register the server with the directory
    register_with_directory(topic, port);

    // Register the signal handler for Ctrl+C (SIGINT)
    signal(SIGINT, handle_sigint);

    // Create communication endpoint
    if ((sockfd = socket(AF_INET, SOCK_STREAM, 0)) < 0) {
        perror("server: can't open stream socket");
        exit(1);
    }

    // Bind socket to local address
    memset((char *)&serv_addr, 0, sizeof(serv_addr));
    serv_addr.sin_family = AF_INET;
    serv_addr.sin_addr.s_addr = htonl(INADDR_ANY);
    serv_addr.sin_port = htons((uint16_t)port);

    if (bind(sockfd, (struct sockaddr *)&serv_addr, sizeof(serv_addr)) < 0) {
        perror("server: can't bind local address");
        shutdownServer();
        exit(1);
    }

    listen(sockfd, 5);

    for (;;) {
        FD_ZERO(&readset);
        FD_SET(sockfd, &readset);
        int max_socket = sockfd;

        // Iterate over connections to add their sockets to readset
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

                // Read the nickname from the connection
                char nickname[MAX_NICKNAME];
                ssize_t nread = read(newsockfd, nickname, MAX_NICKNAME - 1);
                if (nread <= 0) {
                    fprintf(stderr, "Error reading from connection\n");
                    close(newsockfd);
                    continue;
                }
                nickname[nread] = '\0';

                // Check for duplicate nickname
                int duplicate = 0;
                LIST_FOREACH(conn, &connection_list, entries) {
                    if (strcmp(conn->nickname, nickname) == 0) {
                        duplicate = 1;
                        break;
                    }
                }

                if (duplicate) {
                    write(newsockfd, "Duplicate nickname, cannot connect\n", strlen("Duplicate nickname, cannot connect\n"));
                    close(newsockfd);
                } else {
                    // Add new connection to the list since it was not a duplicate
                    struct connection *new_conn = malloc(sizeof(struct connection));
                    new_conn->socket = newsockfd;
                    strcpy(new_conn->nickname, nickname);
                    LIST_INSERT_HEAD(&connection_list, new_conn, entries);

                    // Check if the user is the first one to join
                    if (!first_user_msg_sent) {
                        write(new_conn->socket, "You are the first user to join the chat\n", strlen("You are the first user to join the chat\n"));
                        first_user_msg_sent = 1;
                    } else {
                        // Inform all connections of the new user
                        char join_msg[MESSAGE_SIZE];
                        snprintf(join_msg, MESSAGE_SIZE, "%s has joined the chat\n", nickname);
                        LIST_FOREACH(conn, &connection_list, entries) {
                            if (conn->socket != newsockfd) {
                                write(conn->socket, join_msg, strlen(join_msg));
                            }
                        }
                    }
                }
            }

            // Handle connection messages or disconnections
            LIST_FOREACH(conn, &connection_list, entries) {
                if (FD_ISSET(conn->socket, &readset)) {
                    char s[MESSAGE_SIZE];
                    ssize_t nread = read(conn->socket, s, MESSAGE_SIZE - 1);
                    if (nread <= 0) {
                        // Connection closed or error
                        close(conn->socket);

                        // Notify others that the connection has left
                        char leave_msg[MESSAGE_SIZE];
                        snprintf(leave_msg, MESSAGE_SIZE, "%s has left the chat\n", conn->nickname);
                        struct connection *temp;
                        LIST_FOREACH(temp, &connection_list, entries) {
                            if (temp->socket != conn->socket) {
                                write(temp->socket, leave_msg, strlen(leave_msg));
                            }
                        }

                        // Remove the connection from the list
                        LIST_REMOVE(conn, entries);
                        free(conn);
                    } else {
                        s[nread] = '\0';  // Null terminate the string
                        char message[MESSAGE_SIZE];
                        snprintf(message, MESSAGE_SIZE, "%.50s: %.200s", conn->nickname, s);


                        // Broadcast the message to all connections
                        struct connection *temp;
                        LIST_FOREACH(temp, &connection_list, entries) {
                            if (temp->socket != conn->socket) {
                                write(temp->socket, message, strlen(message));
                            }
                        }
                    }
                }
            }
        }
    }

    return 0;
}
