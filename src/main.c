#include <arpa/inet.h>
#include <netinet/in.h>
#include <pthread.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/socket.h>
#include <unistd.h>

#include "convert.h"
#include "struct.h"
#include "utils.h"
#include "config.h"
#include "query.h"

#define LOG_MASK 15

typedef struct {
    int socketFd;
    struct sockaddr_in clt;
    char *buf;
} thread_data_t;

// 初始化服务器套接字
int init_server_socket(struct sockaddr_in *srv) {
    int socketFd = socket(AF_INET, SOCK_DGRAM, 0);
    if (socketFd < 0) {
        log_error("socket error");
        exit(1);
    }

    bzero(srv, sizeof(*srv));
    srv->sin_family = AF_INET;
    srv->sin_port = htons(PORT);
    srv->sin_addr.s_addr = INADDR_ANY;

    int r = bind(socketFd, (struct sockaddr *)srv, sizeof(*srv));
    if (r < 0) {
        log_error("bind error");
        exit(1);
    }

    return socketFd;
}

// 接收客户端数据
int receive_client_data(int socketFd, char *buf, struct sockaddr_in *clt) {
    unsigned int len = sizeof(*clt);
    int r = recvfrom(socketFd, buf, BUFFER_SIZE, 0, (struct sockaddr *)clt, &len);
    if (r < 0) {
        log_error("recvfrom error");
        exit(1);
    }
    return r;
}

// 处理DNS查询
void handle_dns_query(thread_data_t *data) {
    dns_message *message = (dns_message *)malloc(sizeof(dns_message));
    if (message == NULL) {
        log_fatal("内存分配错误");
    }
    byte_to_dns_message(message, data->buf);

    char *domain_name = (char *)malloc(BUFFER_SIZE);
    char *ip = (char *)malloc(IPSIZE);
    strcpy(domain_name, (char *)message->question->qname);
    log_info("收到查询请求：%s", domain_name);

    int find_dn_ip = lookup_int_text(domain_name, ip);
    free(domain_name);

    if (find_dn_ip) {
        log_info("查询到IP地址：%d.%d.%d.%d", ip[0], ip[1], ip[2], ip[3]);
        dns_message response;
        response.header = (dns_header *)malloc(sizeof(dns_header));
        if (response.header == NULL) {
            log_fatal("内存分配错误");
        }
        *response.header = *message->header;
        response.header->qr = 1;  // 响应
        response.header->opcode = 0;  // 标准查询
        response.header->aa = 0;  // 非权威答案
        response.header->tc = 0;  // 非截断
        response.header->rd = 1;  // 期望递归
        response.header->ra = 1;  // 支持递归
        response.header->z = 0;  // 保留字段
        response.header->rcode = 0;  // 没有错误
        response.header->qdcount = htons(1);  // 问题数
        response.header->ancount = htons(1);  // 回答数
        response.header->nscount = htons(0);  // 授权资源记录数
        response.header->arcount = htons(0);  // 附加资源记录数

        if (ip[0] == 0 && ip[1] == 0 && ip[2] == 0 && ip[3] == 0) {
            response.header->rcode = 3;  // NXDOMAIN
        }

        response.question = message->question;

        dns_rr *answer = (dns_rr *)malloc(sizeof(dns_rr));
        if (answer == NULL) {
            log_fatal("内存分配错误");
        }
        answer->name = (uint8_t *)strdup((char *)message->question->qname);
        answer->type = htons(1);  // A记录
        answer->class = htons(1);  // IN类
        answer->ttl = htonl(3600);  // 3600秒
        answer->rdlength = htons(4);  // 4字节
        answer->rdata = (uint8_t *)malloc(4);
        if (answer->rdata == NULL) {
            log_fatal("内存分配错误");
        }
        memcpy(answer->rdata, ip, 4);

        response.rr = answer;

        uint32_t response_len = dns_message_to_byte((uint8_t *)data->buf, &response);

        sendto(data->socketFd, data->buf, response_len, 0, (struct sockaddr *)&data->clt, sizeof(data->clt));

        free(answer->rdata);
        free(answer);
        free(response.header);
    } else {
        struct sockaddr_in DnsSrvAddr;
        int fd = socket(AF_INET, SOCK_DGRAM, 0);
        if (fd < 0) {
            log_error("socket error");
            exit(1);
        }

        bzero(&DnsSrvAddr, sizeof(DnsSrvAddr));
        DnsSrvAddr.sin_family = AF_INET;
        inet_aton(SERVER_IPADDR, &DnsSrvAddr.sin_addr);
        DnsSrvAddr.sin_port = htons(PORT);

        sendto(fd, data->buf, BUFFER_SIZE, 0, (struct sockaddr *)&DnsSrvAddr, sizeof(DnsSrvAddr));
        unsigned int len = sizeof(DnsSrvAddr);
        recvfrom(fd, data->buf, BUFFER_SIZE, 0, (struct sockaddr *)&DnsSrvAddr, &len);
        if (len < 0) {
            log_error("recvfrom error");
            exit(1);
        }
        close(fd);
    }

    free(message);
}

// 线程处理函数
void *thread_func(void *arg) {
    thread_data_t *data = (thread_data_t *)arg;
    handle_dns_query(data);
    free(data->buf);
    free(data);
    pthread_exit(NULL);
}

// 主函数
void dns_run() {
    struct sockaddr_in srv, clt;

    int socketFd = init_server_socket(&srv);

    while (1) {
        thread_data_t *data = (thread_data_t *)malloc(sizeof(thread_data_t));
        if (!data) {
            log_error("内存分配错误");
            exit(1);
        }

        data->buf = (char *)malloc(BUFFER_SIZE);
        if (!data->buf) {
            log_error("内存分配错误");
            free(data);
            exit(1);
        }

        data->socketFd = socketFd;
        int recv_len = receive_client_data(socketFd, data->buf, &data->clt);
        if (recv_len > 0) {
            pthread_t thread;
            int rc = pthread_create(&thread, NULL, thread_func, (void *)data);
            if (rc) {
                log_error("线程创建错误");
                free(data->buf);
                free(data);
                exit(1);
            }
            pthread_detach(thread);
        } else {
            free(data->buf);
            free(data);
        }
    }

    close(socketFd);
}

int main() {

    
    printf("test by hz");
    log_file = stderr;
    dns_run();
    return 0;
}
