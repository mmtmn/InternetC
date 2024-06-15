#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <arpa/inet.h>
#include <netinet/in.h>
#include <sys/socket.h>
#include <ldns/ldns.h>
#include <openssl/ssl.h>
#include <openssl/err.h>

#define PORT 12345
#define SECURE_PORT 12346
#define BUF_SIZE 1024

// 1. TCP/IP Communication: Simple TCP Client and Server
void tcp_server() {
    int server_fd, new_socket;
    struct sockaddr_in address;
    int addrlen = sizeof(address);
    char buffer[BUF_SIZE] = {0};
    
    if ((server_fd = socket(AF_INET, SOCK_STREAM, 0)) == 0) {
        perror("socket failed");
        exit(EXIT_FAILURE);
    }
    
    address.sin_family = AF_INET;
    address.sin_addr.s_addr = INADDR_ANY;
    address.sin_port = htons(PORT);
    
    if (bind(server_fd, (struct sockaddr *)&address, sizeof(address)) < 0) {
        perror("bind failed");
        close(server_fd);
        exit(EXIT_FAILURE);
    }
    
    if (listen(server_fd, 3) < 0) {
        perror("listen");
        close(server_fd);
        exit(EXIT_FAILURE);
    }
    
    printf("TCP Server listening on port %d...\n", PORT);
    while ((new_socket = accept(server_fd, (struct sockaddr *)&address, (socklen_t*)&addrlen)) >= 0) {
        read(new_socket, buffer, BUF_SIZE);
        printf("Received: %s\n", buffer);
        send(new_socket, buffer, strlen(buffer), 0);
        close(new_socket);
    }
}

// TCP Client
void tcp_client() {
    struct sockaddr_in serv_addr;
    char buffer[BUF_SIZE] = {0};
    int sock = 0;
    
    if ((sock = socket(AF_INET, SOCK_STREAM, 0)) < 0) {
        printf("\n Socket creation error \n");
        return;
    }
    
    serv_addr.sin_family = AF_INET;
    serv_addr.sin_port = htons(PORT);
    
    if (inet_pton(AF_INET, "127.0.0.1", &serv_addr.sin_addr) <= 0) {
        printf("\nInvalid address/ Address not supported \n");
        return;
    }
    
    if (connect(sock, (struct sockaddr *)&serv_addr, sizeof(serv_addr)) < 0) {
        printf("\nConnection Failed \n");
        return;
    }
    
    send(sock, "Hello from client", strlen("Hello from client"), 0);
    read(sock, buffer, BUF_SIZE);
    printf("Received from server: %s\n", buffer);
    close(sock);
}

// 2. DNS Queries
void perform_dns_query(const char *domain) {
    ldns_resolver *resolver;
    ldns_rdf *domain_name;
    ldns_pkt *packet;
    ldns_rr_list *rr_list;
    ldns_rr *record;
    
    if (ldns_resolver_new_frm_file(&resolver, NULL) != LDNS_STATUS_OK) {
        fprintf(stderr, "Could not create resolver\n");
        return;
    }
    
    domain_name = ldns_dname_new_frm_str(domain);
    packet = ldns_resolver_query(resolver, domain_name, LDNS_RR_TYPE_A, LDNS_RR_CLASS_IN, LDNS_RD);
    
    rr_list = ldns_pkt_answer(packet);
    for (size_t i = 0; i < ldns_rr_list_rr_count(rr_list); i++) {
        record = ldns_rr_list_rr(rr_list, i);
        char *ip = ldns_rdf2str(ldns_rr_rdf(record, 0));
        printf("%s has IP address %s\n", domain, ip);
        free(ip);
    }
    
    ldns_rr_list_deep_free(rr_list);
    ldns_pkt_free(packet);
    ldns_rdf_deep_free(domain_name);
    ldns_resolver_deep_free(resolver);
}

// 3. Secure Communication with TLS
void secure_tcp_server() {
    int server_fd, new_socket;
    struct sockaddr_in address;
    int addrlen = sizeof(address);
    char buffer[BUF_SIZE] = {0};
    SSL_CTX *ctx;
    SSL *ssl;
    
    OpenSSL_add_all_algorithms();
    SSL_load_error_strings();
    SSL_library_init();
    
    ctx = SSL_CTX_new(TLS_server_method());
    if (!ctx) {
        ERR_print_errors_fp(stderr);
        exit(EXIT_FAILURE);
    }
    
    if (!SSL_CTX_use_certificate_file(ctx, "server-cert.pem", SSL_FILETYPE_PEM) ||
        !SSL_CTX_use_PrivateKey_file(ctx, "server-key.pem", SSL_FILETYPE_PEM)) {
        ERR_print_errors_fp(stderr);
        exit(EXIT_FAILURE);
    }
    
    if ((server_fd = socket(AF_INET, SOCK_STREAM, 0)) == 0) {
        perror("socket failed");
        exit(EXIT_FAILURE);
    }
    
    address.sin_family = AF_INET;
    address.sin_addr.s_addr = INADDR_ANY;
    address.sin_port = htons(SECURE_PORT);
    
    if (bind(server_fd, (struct sockaddr *)&address, sizeof(address)) < 0) {
        perror("bind failed");
        close(server_fd);
        exit(EXIT_FAILURE);
    }
    
    if (listen(server_fd, 3) < 0) {
        perror("listen");
        close(server_fd);
        exit(EXIT_FAILURE);
    }
    
    printf("TLS Server listening on port %d...\n", SECURE_PORT);
    while ((new_socket = accept(server_fd, (struct sockaddr *)&address, (socklen_t*)&addrlen)) >= 0) {
        ssl = SSL_new(ctx);
        SSL_set_fd(ssl, new_socket);
        if (SSL_accept(ssl) <= 0) {
            ERR_print_errors_fp(stderr);
        } else {
            SSL_read(ssl, buffer, BUF_SIZE);
            printf("Received: %s\n", buffer);
            SSL_write(ssl, buffer, strlen(buffer));
        }
        SSL_shutdown(ssl);
        SSL_free(ssl);
        close(new_socket);
    }
    SSL_CTX_free(ctx);
}

// Secure TCP Client
void secure_tcp_client() {
    struct sockaddr_in serv_addr;
    char buffer[BUF_SIZE] = {0};
    int sock = 0;
    SSL_CTX *ctx;
    SSL *ssl;
    
    OpenSSL_add_all_algorithms();
    SSL_load_error_strings();
    SSL_library_init();
    
    ctx = SSL_CTX_new(TLS_client_method());
    if (!ctx) {
        ERR_print_errors_fp(stderr);
        return;
    }
    
    if (!SSL_CTX_load_verify_locations(ctx, "server-cert.pem", NULL)) {
        ERR_print_errors_fp(stderr);
        SSL_CTX_free(ctx);
        return;
    }
    
    if ((sock = socket(AF_INET, SOCK_STREAM, 0)) < 0) {
        printf("\n Socket creation error \n");
        return;
    }
    
    serv_addr.sin_family = AF_INET;
    serv_addr.sin_port = htons(SECURE_PORT);
    
    if (inet_pton(AF_INET, "127.0.0.1", &serv_addr.sin_addr) <= 0) {
        printf("\nInvalid address/ Address not supported \n");
        return;
    }
    
    if (connect(sock, (struct sockaddr *)&serv_addr, sizeof(serv_addr)) < 0) {
        printf("\nConnection Failed \n");
        return;
    }
    
    ssl = SSL_new(ctx);
    SSL_set_fd(ssl, sock);
    if (SSL_connect(ssl) <= 0) {
        ERR_print_errors_fp(stderr);
    } else {
        SSL_write(ssl, "Hello from secure client", strlen("Hello from secure client"));
        SSL_read(ssl, buffer, BUF_SIZE);
        printf("Received from server: %s\n", buffer);
    }
    SSL_shutdown(ssl);
    SSL_free(ssl);
    close(sock);
    SSL_CTX_free(ctx);
}

// 4. Simulate BGP Interaction
void simulate_bgp_announce() {
    printf("Simulating BGP route announcement:\n");
    printf("Announcing route: 203.0.113.0/24\n");
}

// Example usage
int main() {
    // Start TCP Server
    if (fork() == 0) {
        tcp_server();
        exit(0);
    }

    // Start Secure TCP Server
    if (fork() == 0) {
        secure_tcp_server();
        exit(0);
    }

    sleep(2); // Give servers time to start

    // Perform DNS Query
    perform_dns_query("example.com");

    // Start TCP Client
    tcp_client();

    // Start Secure TCP Client
    secure_tcp_client();

    // Simulate BGP Route Announcement
    simulate_bgp_announce();

    return 0;
}
