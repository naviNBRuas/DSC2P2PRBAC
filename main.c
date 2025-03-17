// main.c
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <pthread.h>
#include <errno.h>

#ifdef _WIN32
#include <winsock2.h>
#include <ws2tcpip.h>
#pragma comment(lib, "ws2_32.lib")
#else
#include <netinet/in.h>
#include <arpa/inet.h>
#include <netdb.h>
#include <sys/socket.h>
#include <fcntl.h>
#include <signal.h>
#endif

#include <openssl/ssl.h>
#include <openssl/err.h>

#define MAX_PEERS 10
#define BUFFER_SIZE 2048
#define PORT 8080
#define MAX_COMMANDS 100

// Role definitions
typedef enum {
    ROLE_GUEST,
    ROLE_USER,
    ROLE_ADMIN
} Role;

// Peer structure
typedef struct {
    int sockfd;
    struct sockaddr_in addr;
    SSL *ssl; // SSL for encryption
    Role role;
} Peer;

// Global peer list and command list
Peer peers[MAX_PEERS];
int peer_count = 0;
pthread_mutex_t peer_mutex = PTHREAD_MUTEX_INITIALIZER;

// Command structure
typedef struct {
    char name[50];
    Role required_role;
    void (*execute)(Peer *peer);
} Command;

Command command_list[MAX_COMMANDS];
int command_count = 0;

// OpenSSL initialization for encryption
void initialize_ssl() {
    SSL_load_error_strings();
    OpenSSL_add_ssl_algorithms();
}

void cleanup_ssl() {
    EVP_cleanup();
}

SSL_CTX *create_context() {
    const SSL_METHOD *method;
    SSL_CTX *ctx;

    method = TLS_server_method();
    ctx = SSL_CTX_new(method);
    if (!ctx) {
        perror("Unable to create SSL context");
        ERR_print_errors_fp(stderr);
        exit(EXIT_FAILURE);
    }

    return ctx;
}

void configure_context(SSL_CTX *ctx) {
    if (SSL_CTX_use_certificate_file(ctx, "cert.pem", SSL_FILETYPE_PEM) <= 0) {
        ERR_print_errors_fp(stderr);
        exit(EXIT_FAILURE);
    }

    if (SSL_CTX_use_PrivateKey_file(ctx, "key.pem", SSL_FILETYPE_PEM) <= 0) {
        ERR_print_errors_fp(stderr);
        exit(EXIT_FAILURE);
    }
}

// Command execution functions
void execute_admin_cmd(Peer *peer) {
    SSL_write(peer->ssl, "Executing Admin Command\n", strlen("Executing Admin Command\n"));
}

void execute_user_cmd(Peer *peer) {
    SSL_write(peer->ssl, "Executing User Command\n", strlen("Executing User Command\n"));
}

void execute_generic_cmd(Peer *peer) {
    SSL_write(peer->ssl, "Executing General Command\n", strlen("Executing General Command\n"));
}

// Command registration
void register_command(const char *name, Role required_role, void (*execute)(Peer *)) {
    if (command_count >= MAX_COMMANDS) {
        fprintf(stderr, "Command list full\n");
        return;
    }

    strcpy(command_list[command_count].name, name);
    command_list[command_count].required_role = required_role;
    command_list[command_count].execute = execute;
    command_count++;
}

// Permission check
int has_permission(Role role, const char *command) {
    for (int i = 0; i < command_count; i++) {
        if (strcmp(command_list[i].name, command) == 0) {
            return role >= command_list[i].required_role;
        }
    }
    return 0;
}

// Command handler
void handle_command(Peer *peer, const char *command) {
    if (!has_permission(peer->role, command)) {
        SSL_write(peer->ssl, "Access Denied\n", strlen("Access Denied\n"));
        return;
    }

    for (int i = 0; i < command_count; i++) {
        if (strcmp(command_list[i].name, command) == 0) {
            command_list[i].execute(peer);
            return;
        }
    }

    SSL_write(peer->ssl, "Unknown Command\n", strlen("Unknown Command\n"));
}

// Function to handle each peer
void *peer_handler(void *arg) {
    Peer *peer = (Peer *)arg;
    char buffer[BUFFER_SIZE];

    while (1) {
        int bytes_received = SSL_read(peer->ssl, buffer, sizeof(buffer));
        if (bytes_received <= 0) {
            printf("Peer disconnected\n");
            close(peer->sockfd);
            break;
        }
        buffer[bytes_received] = '\0';
        printf("Received command from peer: %s\n", buffer);
        handle_command(peer, buffer);
    }

    return NULL;
}

// Function to add a peer
int add_peer(int sockfd, struct sockaddr_in addr, Role role, SSL *ssl) {
    pthread_mutex_lock(&peer_mutex);
    if (peer_count >= MAX_PEERS) {
        pthread_mutex_unlock(&peer_mutex);
        return -1;
    }

    Peer new_peer;
    new_peer.sockfd = sockfd;
    new_peer.addr = addr;
    new_peer.role = role;
    new_peer.ssl = ssl;

    peers[peer_count++] = new_peer;
    pthread_mutex_unlock(&peer_mutex);
    return 0;
}

// Server initialization and main loop
void start_server() {
    SSL_CTX *ctx;
    initialize_ssl();
    ctx = create_context();
    configure_context(ctx);

    int server_fd;
    struct sockaddr_in address;
    int opt = 1;
    int addrlen = sizeof(address);

#ifdef _WIN32
    WSADATA wsa;
    WSAStartup(MAKEWORD(2, 2), &wsa);
#endif

    if ((server_fd = socket(AF_INET, SOCK_STREAM, 0)) == 0) {
        perror("Socket failed");
        exit(EXIT_FAILURE);
    }

    if (setsockopt(server_fd, SOL_SOCKET, SO_REUSEADDR | SO_REUSEPORT, &opt, sizeof(opt))) {
        perror("Setsockopt failed");
        close(server_fd);
        exit(EXIT_FAILURE);
    }

    address.sin_family = AF_INET;
    address.sin_addr.s_addr = INADDR_ANY;
    address.sin_port = htons(PORT);

    if (bind(server_fd, (struct sockaddr *)&address, sizeof(address)) < 0) {
        perror("Bind failed");
        close(server_fd);
        exit(EXIT_FAILURE);
    }

    if (listen(server_fd, 3) < 0) {
        perror("Listen failed");
        close(server_fd);
        exit(EXIT_FAILURE);
    }

    printf("Server started on port %d\n", PORT);

    while (1) {
        struct sockaddr_in peer_addr;
        int new_socket = accept(server_fd, (struct sockaddr *)&peer_addr, (socklen_t *)&addrlen);
        if (new_socket < 0) {
            perror("Accept failed");
            continue;
        }

        printf("New peer connected\n");

        SSL *ssl = SSL_new(ctx);
        SSL_set_fd(ssl, new_socket);
        if (SSL_accept(ssl) <= 0) {
            ERR_print_errors_fp(stderr);
            close(new_socket);
            continue;
        }

        Role assigned_role = ROLE_GUEST; // Assign default role, dynamic assignment could be added here.
        if (add_peer(new_socket, peer_addr, assigned_role, ssl) == -1) {
            SSL_write(ssl, "Server Full\n", strlen("Server Full\n"));
            SSL_free(ssl);
            close(new_socket);
        } else {
            pthread_t thread_id;
            pthread_create(&thread_id, NULL, peer_handler, &peers[peer_count - 1]);
        }
    }

    cleanup_ssl();
}

int main() {
    // Register commands and assign required roles
    register_command("admin_cmd", ROLE_ADMIN, execute_admin_cmd);
    register_command("user_cmd", ROLE_USER, execute_user_cmd);
    register_command("generic_cmd", ROLE_GUEST, execute_generic_cmd);

    start_server();

    return 0;
}