//22

#include <stdio.h>
#include <string.h>
#include <strings.h>
#include <sys/types.h>
#include <stdlib.h>
#include <unistd.h>
#include "inet.h"
#include "common.h"
#include <sys/select.h>

#define MAX_CHAT_SERVERS 10
#define MAX_TOPIC 100
#define RESPONSE_SIZE 512  // made buffer size for debug

// Structure to hold chat room information
struct chatServerRooms {
    char topic[MAX_TOPIC];
    int port;
    char ip[INET_ADDRSTRLEN];  // Storing IP address as string
};

struct chatServerRooms chatServers[MAX_CHAT_SERVERS];  // array of chat rooms
int chatServerRooms_count = 0;

// Function to register a chat room
void register_chatServerRooms(char *topic, int port, char *ip, int client_sockfd)
{
    if (chatServerRooms_count >= MAX_CHAT_SERVERS) {
        fprintf(stdout, "Directory Server: Chat room limit reached.\n");
        write(client_sockfd, "E: Chat room limit reached\n", strlen("E: Chat room limit reached\n"));
        return;
    }

    // Check for duplicate topic (regardless of port)
    for (int i = 0; i < chatServerRooms_count; i++) {
        if (strcmp(chatServers[i].topic, topic) == 0) {
            fprintf(stdout, "Directory Server: Duplicate topic '%s'. Registration failed.\n", topic);
            write(client_sockfd, "E: Duplicate topic\n", strlen("E: Duplicate topic\n"));  // Send error message
            return;
        }
    }

    // Register the new chat room
    strcpy(chatServers[chatServerRooms_count].topic, topic);
    chatServers[chatServerRooms_count].port = port;
    strcpy(chatServers[chatServerRooms_count].ip, ip);
    chatServerRooms_count++;

    fprintf(stdout, "Directory: Registered Server chat room '%s' is on port %d\n", topic, port);
    write(client_sockfd, "S: Registered successfully\n", strlen("S: Registered successfully\n"));  // Send success message
}


// Function to list all active chat rooms
void listOfServers(int client_sockfd) {
    char response[RESPONSE_SIZE];
    memset(response, 0, sizeof(response));

    if (chatServerRooms_count == 0) {
        snprintf(response, sizeof(response), "No active chat rooms available.\n");
    } else {
        for (int i = 0; i < chatServerRooms_count; i++) {
            char entry[RESPONSE_SIZE];
            snprintf(entry, sizeof(entry), "Topic: %.50s, Port: %d\n", chatServers[i].topic, chatServers[i].port);
            strcat(response, entry);
        }
    }

    write(client_sockfd, response, strlen(response));
}

// Function to deregister a chat room (when a server shuts down)
void deregister_chatServerRooms(char *ip, int port, char *topic) {
    for (int i = 0; i < chatServerRooms_count; i++) {
        // Only deregister if both the topic and port match
        if (strcmp(chatServers[i].ip, ip) == 0 && chatServers[i].port == port && strcmp(chatServers[i].topic, topic) == 0) {
            fprintf(stdout, "Directory: Deregistering chat room '%s' on port %d\n", chatServers[i].topic, chatServers[i].port);

            // Shift the array to remove the chat room
            for (int j = i; j < chatServerRooms_count - 1; j++) {
                chatServers[j] = chatServers[j + 1];
            }
            chatServerRooms_count--;  // Decrease the count
            break;
        }
    }
}

int main(int argc, char **argv) {
    int sockfd, newsockfd;
    unsigned int clilen;
    struct sockaddr_in cli_addr, serv_addr;
    fd_set readset;
    char s[RESPONSE_SIZE];

    (void)argc;  // Mark argc as unused
    (void)argv;  // Mark argv as unused

    // Create communication endpoint
    if ((sockfd = socket(AF_INET, SOCK_STREAM, 0)) < 0) {
        perror("server: can't open stream socket");
        exit(1);
    }

    // Add SO_REUSEADDR option to prevent address in use errors
    int true = 1;
    if (setsockopt(sockfd, SOL_SOCKET, SO_REUSEADDR, &true, sizeof(true)) < 0) {
        perror("server: can't set socket address reuse option");
        exit(1);
    }

    // Bind socket to local address
    memset((char *)&serv_addr, 0, sizeof(serv_addr));
    serv_addr.sin_family = AF_INET;
    serv_addr.sin_addr.s_addr = htonl(INADDR_ANY);
    serv_addr.sin_port = htons(DIR_SERVER_PORT);

    if (bind(sockfd, (struct sockaddr *)&serv_addr, sizeof(serv_addr)) < 0) {
        perror("server: can't bind local address");
        exit(1);
    }

    listen(sockfd, 5);
    clilen = sizeof(cli_addr);

    for (;;) {
        FD_ZERO(&readset);
        FD_SET(sockfd, &readset);

        // Accept new connection requests
        if (FD_ISSET(sockfd, &readset)) {
            clilen = sizeof(cli_addr);
            newsockfd = accept(sockfd, (struct sockaddr *)&cli_addr, &clilen);
            if (newsockfd < 0) {
                perror("server: accept error");
                exit(1);
            }

            fprintf(stderr, "%s:%d Accepted connection from %s\n", __FILE__, __LINE__, inet_ntoa(cli_addr.sin_addr));

            // Read the request from the client
            memset(s, 0, sizeof(s));  // Clear the buffer before reading

            if (read(newsockfd, s, sizeof(s)) <= 0) {
                fprintf(stderr, "%s:%d Error reading from client\n", __FILE__, __LINE__);
                exit(1);
            }

            // Process client's request based on the first character
            switch (s[0]) {
                case 'R':  // Registration request (assumed 'R' starts the message for Register)
                {
                    char topic[MAX_TOPIC];
                    int port;
                    sscanf(s + 1, "%s %d", topic, &port);  // Read the topic and port number
                    register_chatServerRooms(topic, port, inet_ntoa(cli_addr.sin_addr), newsockfd);
                    snprintf(s, sizeof(s), "Chat room '%.50s' registered on port %d\n", topic, port);
                    write(newsockfd, s, strlen(s));
                }
                break;

                case 'L':  // List request (assumed 'L' starts the message for listing active chat rooms)
                    listOfServers(newsockfd);  // Send active chat rooms list to the client
                    break;

                case 'D':  // Deregistration request (assumed 'D' starts the message for Deregister)
                {
                    char topic[MAX_TOPIC];
                    int port;
                    sscanf(s + 1, "%d %s", &port, topic);  // Read the port number and topic
                    deregister_chatServerRooms(inet_ntoa(cli_addr.sin_addr), port, topic);  // Deregister the chat room with IP, port, and topic
                }
                break;

                default:
                    snprintf(s, sizeof(s), "Invalid request\n");
                    write(newsockfd, s, strlen(s));
                    break;
            }

            // Send the reply to the client
            close(newsockfd);
        }
    }
}
