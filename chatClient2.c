//22

#include <stdio.h>
#include <sys/select.h>
#include <sys/types.h>
#include <sys/time.h>
#include <unistd.h>
#include <string.h>
#include <stdlib.h>
#include "inet.h"
#include "common.h"

#define MAX_NICKNAME 51
#define MAX_CHAT_ROOMS 10
#define RESPONSE_SIZE 512

// Structure to hold chat room information
struct chat_room {
    char topic[MAX_NICKNAME];
    int port;
    char ip[INET_ADDRSTRLEN];  // IP Address
};

struct chat_room chat_rooms[MAX_CHAT_ROOMS];  // Store chat rooms from the directory
int num_rooms = 0;  // Number of chat rooms returned from the directory

// Function to query the Directory Server for a list of active chat rooms
void query_directory_server() {
    int sockfd;
    struct sockaddr_in dir_addr;
    char message[MAX] = "L";  // 'L' request for listing chat rooms
    char response[RESPONSE_SIZE];

    // Create socket for directory communication
    if ((sockfd = socket(AF_INET, SOCK_STREAM, 0)) < 0) {
        perror("Cannot create socket for directory query");
        return;
    }

    // Set up the address of the Directory Server
    memset(&dir_addr, 0, sizeof(dir_addr));
    dir_addr.sin_family = AF_INET;
    dir_addr.sin_addr.s_addr = inet_addr(SERV_HOST_ADDR);  // Directory server IP
    dir_addr.sin_port = htons(DIR_SERVER_PORT);

    // Connect to the Directory Server
    if (connect(sockfd, (struct sockaddr *)&dir_addr, sizeof(dir_addr)) < 0) {
        perror("Cannot connect to directory server");
        close(sockfd);
        return;
    }

    // Send LIST request
    write(sockfd, message, strlen(message));

    // Read the response from the Directory Server
    ssize_t nread = read(sockfd, response, sizeof(response) - 1);
    if (nread <= 0) {
        perror("Error reading from directory server");
        close(sockfd);
        return;
    }

    response[nread] = '\0';  // Null-terminate the string

    // Parse the response into chat rooms
    char *line = strtok(response, "\n");
    num_rooms = 0;
    while (line != NULL && num_rooms < MAX_CHAT_ROOMS) {
        sscanf(line, "Topic: %50[^,], Port: %d", chat_rooms[num_rooms].topic, &chat_rooms[num_rooms].port);
        strcpy(chat_rooms[num_rooms].ip, SERV_HOST_ADDR);  // Use directory server IP as the chat server IP
        num_rooms++;
        line = strtok(NULL, "\n");
    }

    //printf("Response from Directory Server:\n%s\n", response);
    fprintf(stdout, "\nAvailable Chat Rooms:\n");

    close(sockfd);  // Close the socket connection
}

// Function to connect to the selected server
int connect_to_server(const char *ip, int port) {
    int sockfd;
    struct sockaddr_in serv_addr;

    // Create a socket (an endpoint for communication)
    if ((sockfd = socket(AF_INET, SOCK_STREAM, 0)) < 0) {
        perror("client: can't open stream socket");
        return -1;
    }

    // Set up the address of the server to be contacted
    memset(&serv_addr, 0, sizeof(serv_addr));
    serv_addr.sin_family = AF_INET;
    serv_addr.sin_addr.s_addr = inet_addr(ip);  // Use the provided IP
    serv_addr.sin_port = htons((uint16_t)port);  // Use the port selected by the user

    // Connect to the server
    if (connect(sockfd, (struct sockaddr *)&serv_addr, sizeof(serv_addr)) < 0) {
        perror("client: can't connect to server");
        close(sockfd);
        return -1;
    }

    return sockfd;  // Return the connected socket
}

int main() {
    char s[MAX] = {'\0'};
    fd_set readset;
    int sockfd;
    ssize_t nread;
    char nickname[MAX_NICKNAME];

    // Query the Directory Server to get the list of chat rooms
    query_directory_server();

    // Display the list of chat rooms

    // Display the list of chat rooms only if there are any

    for (int i = 0; i < num_rooms; i++) {
        if (strcmp(chat_rooms[i].topic, "") != 0) {  // Only print if the topic is not an empty string
            fprintf(stdout, "%d. Topic: %s, Port: %d\n", i + 1, chat_rooms[i].topic, chat_rooms[i].port);
        }
    }

    // Ask the user to select a chat room by entering the port number
    int port;
    fprintf(stdout, "Enter the port number of the chat room to connect to: ");
    scanf("%d", &port);
    getchar();  // To consume the newline after the port input

    // Find the chat room with the selected port
    char *selected_ip = NULL;
    for (int i = 0; i < num_rooms; i++) {
        if (chat_rooms[i].port == port) {
            selected_ip = chat_rooms[i].ip;
            break;
        }
    }

    if (!selected_ip) {
        fprintf(stderr, "No chat room found with port %d.\n", port);
        return -1;
    }

    // Connect to the selected chat server
    sockfd = connect_to_server(selected_ip, port);
    if (sockfd == -1) {
        fprintf(stderr, "Failed to connect to chat server on port %d.\n", port);
        return -1;
    }

    // Get the nickname of the user
    fprintf(stdout, "What is your nickname (up to 50 characters): ");
    fgets(nickname, MAX_NICKNAME, stdin);
    nickname[strcspn(nickname, "\n")] = '\0';  // Remove trailing newline

    // Send the nickname to the server
    if (write(sockfd, nickname, strlen(nickname)) < 0) {
        perror("Error sending nickname to server");
        close(sockfd);
        return -1;
    }

    // Main loop for chat communication
    for (;;) {
        FD_ZERO(&readset);
        FD_SET(STDIN_FILENO, &readset);
        FD_SET(sockfd, &readset);

        // Wait for activity on the input or socket
        if (select(sockfd + 1, &readset, NULL, NULL, NULL) > 0) {
            // Check if there is user input to read
            if (FD_ISSET(STDIN_FILENO, &readset)) {
                if (fgets(s, MAX, stdin) != NULL) {
                    // Remove trailing newline from input
                    size_t len = strlen(s);
                    if (s[len - 1] == '\n') s[len - 1] = '\0';

                    // Send the user's message to the server
                    if (write(sockfd, s, len) < 0) {
                        perror("Error sending message to server");
                    }
                }
            }

            // Check if there is a message from the server to read
            if (FD_ISSET(sockfd, &readset)) {
                if ((nread = read(sockfd, s, MAX - 1)) <= 0) {
                    if (nread == 0) {
                        fprintf(stdout, "Server closed the connection. Type ./chatClient2 to start again\n");
                    } else {
                        perror("Error reading from server");
                    }
                    close(sockfd);
                    return -1;
                } else {
                    s[nread] = '\0';  // Null-terminate the string
                    fprintf(stdout, "%s\n", s);
                }
            }
        }
    }

    close(sockfd);
    return 0;
}
