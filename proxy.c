#include "csapp.h"
#include "http_parser.h"
#include <ctype.h>
#include <fcntl.h>
#include <netdb.h>
#include <netinet/in.h>
#include <semaphore.h>
#include <stdbool.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/mman.h>
#include <sys/stat.h>
#include <sys/types.h>
#include <sys/wait.h>
#include <unistd.h>

#define HOSTLEN 256
#define SERVLEN 8
#define CACHE_LEN 100
#define MAX_OBJECT_SIZE (100 * 1024)
#define MAX_CACHE_SIZE (1024 * 1024)

int pthread_create(pthread_t *restrict tidp,
                   const pthread_attr_t *restrict attr,
                   void *(*start_rtn)(void *), void *restrict arg);
int pthread_mutex_lock(pthread_mutex_t *mutex);
int pthread_mutex_unlock(pthread_mutex_t *mutex);
int pthread_mutex_init(pthread_mutex_t *restrict mutex,
                       const pthread_mutexattr_t *restrict attr);
/* Typedef for convenience */
typedef struct sockaddr SA;

/* Information about a connected client. */
typedef struct {
    struct sockaddr_in addr; // Socket address
    socklen_t addrlen;       // Socket address length
    int connfd;              // Client connection file descriptor
    char host[HOSTLEN];      // Client host
    char serv[SERVLEN];      // Client service (port)
} client_info;

typedef struct cache_t cache_t;
/* Information about cache. */
struct cache_t {
    char *url;
    char *content;
    int visit_count;
    size_t content_size;

    pthread_mutex_t read_mutex;
    volatile size_t read_count;
};
pthread_mutex_t cache_mutex;
pthread_mutex_t cache_size_mutex;
volatile size_t cur_cache_size;

cache_t DumCacheHead[CACHE_LEN];

/* URI parsing results. */
typedef enum { PARSE_ERROR, PARSE_SUCCESS } parse_result;

static const char *header_user_agent = "Mozilla/5.0"
                                       " (X11; Linux x86_64; rv:3.10.0)"
                                       " Gecko/20220411 Firefox/63.0.1";


/* init_cache - init a cache that keeps recently used Web objects in memory. 
* functions as a key-value storage, saving some block of data with an
* associated key, such that future requests of the key will return the stored data
*/
void init_cache() {
    for (int i = 0; i < CACHE_LEN; i++) {
        DumCacheHead[i].visit_count = 0;
        pthread_mutex_init(&DumCacheHead[i].read_mutex, NULL);
        DumCacheHead[i].read_count = 0;
    }
    cur_cache_size = 0;
    pthread_mutex_init(&cache_size_mutex, NULL);
    pthread_mutex_init(&cache_mutex, NULL);
}


/* add_cache - add the visited url and content to cache. 
 * uri - The buffer containing URI. Must contain a NUL-terminated string.
 * content - The buffer containing content.
 * content_size - The size of content.
 *
*/
void add_cache(char *url, char *content, size_t content_size) {
    sem_wait(&cache_mutex);

    for (int i = 0; i < CACHE_LEN; i++) {
        if (DumCacheHead[i].content == NULL) {
            strcpy(DumCacheHead[i].url, url);
            strcpy(DumCacheHead[i].content, content);
            DumCacheHead[i].content_size = content_size;
            DumCacheHead[i].visit_count = 0;
        }
    }

    sem_post(&cache_mutex);
}

/* delete_cache_LRU - employ a least-recently-used (LRU) eviction policy. */
size_t delete_cache_LRU() {
    pthread_mutex_lock(&cache_mutex);
    cache_t *to_delete = &DumCacheHead[0];
    int visit_count = 0;
    for (int i = 0; i < CACHE_LEN; i++) {
        if (DumCacheHead[i].visit_count > visit_count &&
            DumCacheHead[i].content != NULL && DumCacheHead[i].url != NULL &&
            to_delete->content_size != 0) {
            to_delete = &DumCacheHead[i];
            visit_count = DumCacheHead[i].visit_count;
        }
    }

    size_t content_size = to_delete->content_size;
    if (to_delete->content != NULL && to_delete->url != NULL &&
        to_delete->content_size != 0) {
        while (to_delete->read_count > 0) {
        }
        free(to_delete->content);
        free(to_delete->url);
        to_delete->url = NULL;
        to_delete->content = NULL;
        to_delete->content_size = 0;

    } else {
        pthread_mutex_unlock(&cache_mutex);
        return 0;
    }

    pthread_mutex_unlock(&cache_mutex);
    return content_size;
}


/*
 * find_cache - check and return the cached url
 *
 * url - The buffer containing URL.
 * 
 * Returns the object if the url is found in the given url.
 * Otherwise return null
 */
cache_t *find_cache(char *url) {
    pthread_mutex_lock(&cache_mutex);
    for (int i = 0; i < CACHE_LEN && DumCacheHead[i].url != NULL; i++) {
        if (strcmp(DumCacheHead[i].url, url) == 0) {
            DumCacheHead[i].visit_count = 0;

            pthread_mutex_unlock(&cache_mutex);
            return &DumCacheHead[i];
        }
    }

    pthread_mutex_unlock(&cache_mutex);
    return NULL;
}

/*
 * update_cache_visit_count - update the visit count of cache
 *
 * Visit count is used to track the used status of a specific cached object.
 */
void *update_cache_visit_count() {

    pthread_mutex_lock(&cache_mutex);
    for (int i = 0; i < CACHE_LEN; i++) {
        DumCacheHead[i].visit_count++;
    }

    pthread_mutex_unlock(&cache_mutex);
    return NULL;
}

/*
 * parse_uri - parse URI into filename and CGI args
 *
 * uri - The buffer containing URI. Must contain a NUL-terminated string.
 * filename - The buffer into which the filename will be placed.
 * cgiargs - The buffer into which the CGI args will be placed.
 * NOTE: All buffers must hold MAXLINE bytes, and will contain NUL-terminated
 * strings after parsing.
 *
 * Returns the appropriate parse result for the type of request.
 */
parse_result parse_url(char *url, const char *port, const char *host,
                       const char *path) {
    parser_t *parser = parser_new();
    parser_parse_line(parser, url);
    if (parser_retrieve(parser, PORT, &port) < 0) {
        // handle errors
        return PARSE_ERROR;
    }
    if (parser_retrieve(parser, HOST, &host) < 0) {
        // handle errors
        return PARSE_ERROR;
    }
    if (parser_retrieve(parser, PATH, &path) < 0) {
        // handle errors
        return PARSE_ERROR;
    }

    return PARSE_SUCCESS;
}

/*
 * get_filetype - derive file type from file name
 *
 * filename - The file name. Must be a NUL-terminated string.
 * filetype - The buffer in which the file type will be storaged. Must be at
 * least MAXLINE bytes. Will be a NUL-terminated string.
 */
void get_filetype(char *filename, char *filetype) {
    if (strstr(filename, ".html")) {
        strcpy(filetype, "text/html");
    } else if (strstr(filename, ".gif")) {
        strcpy(filetype, "image/gif");
    } else if (strstr(filename, ".png")) {
        strcpy(filetype, "image/png");
    } else if (strstr(filename, ".jpg")) {
        strcpy(filetype, "image/jpeg");
    } else {
        strcpy(filetype, "text/plain");
    }
}

/*
 * clienterror - returns an error message to the client
 */
void clienterror(int fd, const char *errnum, const char *shortmsg,
                 const char *longmsg) {
    char buf[MAXLINE];
    char body[MAXBUF];
    size_t buflen;
    size_t bodylen;

    /* Build the HTTP response body */
    bodylen = snprintf(body, MAXBUF,
                       "<!DOCTYPE html>\r\n"
                       "<html>\r\n"
                       "<head><title>Tiny Error</title></head>\r\n"
                       "<body bgcolor=\"ffffff\">\r\n"
                       "<h1>%s: %s</h1>\r\n"
                       "<p>%s</p>\r\n"
                       "<hr /><em>The Tiny Web server</em>\r\n"
                       "</body></html>\r\n",
                       errnum, shortmsg, longmsg);
    if (bodylen >= MAXBUF) {
        return; // Overflow!
    }

    /* Build the HTTP response headers */
    buflen = snprintf(buf, MAXLINE,
                      "HTTP/1.0 %s %s\r\n"
                      "Content-Type: text/html\r\n"
                      "Content-Length: %zu\r\n\r\n",
                      errnum, shortmsg, bodylen);
    if (buflen >= MAXLINE) {
        return; // Overflow!
    }

    /* Write the headers */
    if (rio_writen(fd, buf, buflen) < 0) {
        fprintf(stderr, "Error writing error response headers to client\n");
        return;
    }

    /* Write the body */
    if (rio_writen(fd, body, bodylen) < 0) {
        fprintf(stderr, "Error writing error response body to client\n");
        return;
    }
}

/*
 * read_requesthdrs - read HTTP request headers
 * Returns true if an error occurred, or false otherwise.
 */
bool read_requesthdrs(client_info *client, rio_t *rp) {
    char buf[MAXLINE];
    char name[MAXLINE];
    char value[MAXLINE];

    while (true) {
        if (rio_readlineb(rp, buf, sizeof(buf)) <= 0) {
            return true;
        }

        /* Check for end of request headers */
        if (strcmp(buf, "\r\n") == 0) {
            return false;
        }

        /* Parse header into name and value */
        if (sscanf(buf, "%[^:]: %[^\r\n]", name, value) != 2) {
            /* Error parsing header */
            clienterror(client->connfd, "400", "Bad Request parse heaDER",
                        "Tiny could not parse request headers");
            return true;
        }

        /* Convert name to lowercase */
        for (size_t i = 0; name[i] != '\0'; i++) {
            name[i] = tolower(name[i]);
        }

        // printf("%s: %s\n", name, value);
    }
}

bool build_requesthdrs(int client_connfd, rio_t *rp, char *new_request) {
    char buf[MAXLINE];
    char name[MAXLINE];
    char value[MAXLINE];
    while (true) {
        if (rio_readlineb(rp, buf, sizeof(buf)) <= 0) {
            return true;
        }

        /* Check for end of request headers */
        if (strcmp(buf, "\r\n") == 0) {
            return false;
        }

        /* Parse header into name and value */
        if (sscanf(buf, "%[^:]: %[^\r\n]", name, value) != 2) {
            /* Error parsing header */
            clienterror(client_connfd, "400", "Bad Request parse heaDER",
                        "Tiny could not parse request headers");
            return true;
        }

        /* Convert name to lowercase */
        for (size_t i = 0; name[i] != '\0'; i++) {
            name[i] = tolower(name[i]);
        }

        if (strcmp(name, "user-agent") == 0 || strcmp(name, "host") == 0 ||
            strcmp(name, "connection") == 0 ||
            strcmp(name, "proxy-connection") == 0) {
            continue;
        }
        strcat(new_request, buf);
    }
}
/*
 * serve - handle one HTTP request/response transaction
 */
void serve(int client_connfd) {
    printf("Accepted connection from %d\n", client_connfd);

    rio_t from_client, to_server;

    rio_readinitb(&from_client, client_connfd);

    /* Read request line */
    char buf[MAXLINE];
    if (rio_readlineb(&from_client, buf, sizeof(buf)) <= 0) {
        printf("read request line error");
        return;
    }

    /* Parse the request line and check if it's well-formed */
    char method[MAXLINE];
    char uri[MAXLINE];
    char version;

    /* sscanf must parse exactly 3 things for request line to be well-formed */
    /* version must be either HTTP/1.0 or HTTP/1.1 */
    if (sscanf(buf, "%s %s HTTP/1.%c", method, uri, &version) != 3 ||
        (version != '0' && version != '1')) {

        clienterror(client_connfd, "400", "Bad Request",
                    "Tiny received a malformed request");
        return;
    }

    // search in cache
    cache_t *c = find_cache(uri);
    if (c != NULL && c->content != NULL) {
        printf("find cache, content len %ld", strlen(c->content));
        pthread_mutex_lock(&c->read_mutex);
        c->read_count++;
        pthread_mutex_unlock(&c->read_mutex);

        rio_writen(client_connfd, c->content, c->content_size);
        c->visit_count = 0;

        pthread_mutex_lock(&c->read_mutex);
        c->read_count--;
        pthread_mutex_unlock(&c->read_mutex);
        return;
    }

    /* Parse URI from GET request */
    const char *path, *host, *port;
    parser_t *parser = parser_new();
    if (parser_parse_line(parser, buf) < 0) {
        printf("parse line error");
        return;
    }
    parser_parse_line(parser, buf);
    if (parser_retrieve(parser, PORT, &port) < 0) {
        // handle errors
        printf("fail parse port");
        return;
    }
    if (parser_retrieve(parser, HOST, &host) < 0) {
        // handle errors
        printf("fail parse host");
        return;
    }
    if (parser_retrieve(parser, PATH, &path) < 0) {
        // handle errors
        printf("fail parse path");
        return;
    }
    if (strlen(port) == 0)
        port = "80";

    // connect to server
    int clientfd = open_clientfd(host, port);
    if (clientfd < 0) {
        printf("open clientfd failed");
        return;
    }
    rio_readinitb(&to_server, clientfd);

    char new_request[MAXLINE];
    sprintf(new_request,
            "GET %s HTTP/1.0\r\nuser-agent: %s\r\nhost: %s:%s\r\nconnection: "
            "close\r\nproxy-Connection: close\r\n",
            path, header_user_agent, host, port);
    if (build_requesthdrs(client_connfd, &from_client, new_request)) {
        printf("build_requesthdrs failed \n");
        return;
    }
    strcat(new_request, "\r\n");

    // construct header
    if (strcmp(method, "GET") != 0) {
        clienterror(client_connfd, "501", "Not Implemented",
                    "Tiny does not implement this method");
        return;
    }

    if (rio_writen(clientfd, new_request, MAXLINE) < 0) {
        printf("write clientfd failed");
        close(clientfd);
        return;
    }

    /* parse and get the url and content */ 
    size_t linenum = 0, cache_linenum = 0;
    char *cache_buf = malloc(sizeof(char) * MAX_OBJECT_SIZE);
    while ((linenum = rio_readnb(&to_server, buf, MAXLINE)) > 0) {
        rio_writen(client_connfd, buf, linenum);
        if (cache_linenum + linenum < MAX_OBJECT_SIZE)
            memcpy(cache_buf + cache_linenum, buf, linenum);
        cache_linenum += linenum;
    }

    if (cache_linenum < MAX_OBJECT_SIZE) {
        if (find_cache(uri)) {
            free(cache_buf);
            close(clientfd);
            return;
        }

        pthread_mutex_lock(&cache_size_mutex);
        cur_cache_size += cache_linenum;
        printf("cur cache size %ld\n", cur_cache_size);

        while (cur_cache_size > MAX_CACHE_SIZE) {
            size_t delete_size = delete_cache_LRU();
            if (delete_size == 0)
                break;
            cur_cache_size -= delete_size;
        }
        pthread_mutex_unlock(&cache_size_mutex);

        /* add the object to cache */ 
        pthread_mutex_lock(&cache_mutex);
        for (int i = 0; i < CACHE_LEN; i++) {
            if (DumCacheHead[i].content == NULL) {
                DumCacheHead[i].url = malloc(sizeof(uri));
                DumCacheHead[i].content = malloc(cache_linenum);
                strcpy(DumCacheHead[i].url, uri);
                memcpy(DumCacheHead[i].content, cache_buf, cache_linenum);

                DumCacheHead[i].content_size = cache_linenum;
                DumCacheHead[i].visit_count = 0;
                break;
            }
        }

        pthread_mutex_unlock(&cache_mutex);
    }
    free(cache_buf);
    close(clientfd);
}

void *thread(void *vargp) {
    int client_connfd = (int)(long)vargp;
    serve(client_connfd);
    close(client_connfd);
    return NULL;
}

int main(int argc, char **argv) {
    int listenfd;
    /* Check command line args */
    if (argc != 2) {
        fprintf(stderr, "usage: %s <port>\n", argv[0]);
        exit(1);
    }

    Signal(SIGPIPE, SIG_IGN);

    // init cache
    init_cache();

    listenfd = open_listenfd(argv[1]);
    if (listenfd < 0) {
        fprintf(stderr, "Failed to listen on port: %s\n", argv[1]);
        exit(1);
    }

    while (1) {
        /* Allocate space on the stack for client info */
        client_info client_data;
        client_info *client = &client_data;

        /* Initialize the length of the address */
        client->addrlen = sizeof(client->addr);

        /* accept() will block until a client connects to the port */
        client->connfd =
            accept(listenfd, (SA *)&client->addr, &client->addrlen);
        if (client->connfd < 0) {
            perror("accept");
            continue;
        }

        pthread_t tid;
        int connfd = client->connfd;
        pthread_create(&tid, NULL, thread, (void *)(long)connfd);
        /* Connection is established; serve client */
        update_cache_visit_count();
    }
}