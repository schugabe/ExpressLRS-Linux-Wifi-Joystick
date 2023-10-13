#include <stdio.h>
#include <string.h>
#include <unistd.h>
#include <fcntl.h>
#include <linux/uinput.h>

#include<stdlib.h>
#include<arpa/inet.h>
#include<sys/socket.h>
#include <sys/time.h>
#include <errno.h>

#include <signal.h>

#include <curl/curl.h>

#include "mdns.h"

#define BUFLEN 128
#define PORT 11000

void setup_abs(int fd, unsigned chan, int min, int max);

int setup_uintput();

int setup_connection();

void receive_data();

int send_joystick_data();

typedef struct {
    uint16_t channel1;
    uint16_t channel2;
    uint16_t channel3;
    uint16_t channel4;
    uint16_t channel5;
    uint16_t channel6;
    uint16_t channel7;
    uint16_t channel8;
} channels_t;

channels_t channel_data;

int uinput_fd;
int s;
struct sockaddr_in si_other;
int slen;
static volatile sig_atomic_t keep_running = 1;
char joystick_ip[45];
int enable_time_output = 1;

static void sig_handler(int _) {
    (void) _;
    keep_running = 0;
}


// Callback handling parsing answers to queries sent
static int query_callback(int sock, const struct sockaddr *from, size_t addrlen, mdns_entry_type_t entry,
                          uint16_t query_id, uint16_t rtype, uint16_t rclass, uint32_t ttl, const void *data,
                          size_t size, size_t name_offset, size_t name_length, size_t record_offset,
                          size_t record_length, void *user_data) {
    if (rtype == MDNS_RECORDTYPE_A) {
        memset(joystick_ip, '\0', sizeof(joystick_ip));

        switch (from->sa_family) {
            case AF_INET:
                inet_ntop(AF_INET, &(((struct sockaddr_in *) from)->sin_addr), joystick_ip, sizeof(joystick_ip));
                break;

            case AF_INET6:
                inet_ntop(AF_INET6, &(((struct sockaddr_in6 *) from)->sin6_addr), joystick_ip, sizeof(joystick_ip));
                break;

            default:
                printf("Unknown AF");
        }
    }

    return 0;
}

// Send a mDNS query
static int send_mdns_query() {
    mdns_query_t query[1];
    size_t count = 1;

    query[0].name = "_elrs._udp.local";
    query[0].length = strlen(query[0].name);

    int socket = mdns_socket_open_ipv4(NULL);
    int query_id;

    if (socket <= 0) {
        printf("Failed to open any client sockets\n");
        return -1;
    }

    size_t capacity = 2048;
    void *buffer = malloc(capacity);
    void *user_data = 0;

    printf("Sending mDNS query");
    for (size_t iq = 0; iq < count; ++iq) {
        const char *record_name = "PTR";
        if (query[iq].type == MDNS_RECORDTYPE_SRV)
            record_name = "SRV";
        else if (query[iq].type == MDNS_RECORDTYPE_A)
            record_name = "A";
        else if (query[iq].type == MDNS_RECORDTYPE_AAAA)
            record_name = "AAAA";
        else
            query[iq].type = MDNS_RECORDTYPE_PTR;
        printf(" : %s %s", query[iq].name, record_name);
    }

    printf("Reading mDNS query replies\n");
    int records = 0;

    while (keep_running && strlen(joystick_ip) == 0) {
        query_id = mdns_multiquery_send(socket, query, count, buffer, capacity, 0);
        if (query_id < 0) {
            printf("Failed to send mDNS query: %s\n", strerror(errno));
        }

        sleep(2);

        records += mdns_query_recv(socket, buffer, capacity, query_callback, user_data, query_id);
    }

    printf("Read %d records\n", records);

    free(buffer);
    mdns_socket_close(socket);
    return EXIT_SUCCESS;
}


int setup_uintput() {
    uinput_fd = open("/dev/uinput", O_WRONLY | O_NONBLOCK);

    if (uinput_fd < 0) {
        perror("open /dev/uinput");
        return EXIT_FAILURE;
    }

    ioctl(uinput_fd, UI_SET_EVBIT, EV_KEY); // enable button/key handling

    ioctl(uinput_fd, UI_SET_KEYBIT, BTN_A);
    ioctl(uinput_fd, UI_SET_KEYBIT, BTN_B);
    ioctl(uinput_fd, UI_SET_KEYBIT, BTN_C);
    ioctl(uinput_fd, UI_SET_KEYBIT, BTN_X);

    ioctl(uinput_fd, UI_SET_EVBIT, EV_ABS); // enable analog absolute position handling

    setup_abs(uinput_fd, ABS_X, 0, 32767);
    setup_abs(uinput_fd, ABS_Y, 0, 32767);
    setup_abs(uinput_fd, ABS_RX, 0, 32767);
    setup_abs(uinput_fd, ABS_RY, 0, 32767);

    struct uinput_setup setup = {
            .name = "ELRS Wifi Joystick",
            .id =
                    {
                            .bustype = BUS_USB,
                            .vendor  = 0x3,
                            .product = 0x3,
                            .version = 2,
                    }
    };

    if (ioctl(uinput_fd, UI_DEV_SETUP, &setup)) {
        perror("UI_DEV_SETUP");
        return EXIT_FAILURE;
    }

    if (ioctl(uinput_fd, UI_DEV_CREATE)) {
        perror("UI_DEV_CREATE");
        return EXIT_FAILURE;
    }

    return EXIT_SUCCESS;
}

int setup_connection() {
    struct sockaddr_in si_me;
    slen = sizeof(si_other);
    s = socket(AF_INET, SOCK_DGRAM, IPPROTO_UDP);
    if (s == -1) {
        printf("udp socket\n");
        return EXIT_FAILURE;
    }

    memset((char *) &si_me, 0, sizeof(si_me));

    si_me.sin_family = AF_INET;
    si_me.sin_port = htons(PORT);
    si_me.sin_addr.s_addr = htonl(INADDR_ANY);

    //bind socket to port
    if (bind(s, (struct sockaddr *) &si_me, sizeof(si_me)) == -1) {
        printf("bind\n");
        return EXIT_FAILURE;
    }

    struct timeval read_timeout;
    read_timeout.tv_sec = 1;
    read_timeout.tv_usec = 0;
    setsockopt(s, SOL_SOCKET, SO_RCVTIMEO, &read_timeout, sizeof read_timeout);

    return EXIT_SUCCESS;
}

void receive_data() {
    uint8_t buffer[BUFLEN];
    memset(buffer, 0, BUFLEN);

    //try to receive some data, this is a blocking call
    ssize_t rec_len = recvfrom(s, buffer, BUFLEN, 0, (struct sockaddr *) &si_other, &slen);

    if (buffer[0] == 1 && buffer[1] == 8) {
        uint16_t *channel_ptr = (uint16_t *) &channel_data;
        uint8_t offset = 2;
        for (int i = 0; i < 8; i++) {
            channel_ptr[i] = *(uint16_t *) (buffer + offset);
            channel_ptr[i] /= 2;
            offset += 2;
        }
    }
}

int start_joystick() {
    CURL *curl = curl_easy_init();
    char url_buffer[256];
    uint8_t success = EXIT_FAILURE;

    sprintf(url_buffer, "http://%s/udpcontrol", joystick_ip);
    printf("\nrequest joystick %s\n", url_buffer);
    curl_easy_setopt(curl, CURLOPT_URL, url_buffer);
    curl_easy_setopt(curl, CURLOPT_POSTFIELDS, "action=joystick_begin&interval=10000&channels=8");
    curl_easy_perform(curl);

    long http_code = 0;
    curl_easy_getinfo(curl, CURLINFO_RESPONSE_CODE, &http_code);
    if (http_code == 200) {
        success = EXIT_SUCCESS;
    } else {
        printf("status code %ld\n", http_code);
    }

    curl_easy_cleanup(curl);

    return success;
}

int send_joystick_data() {
    struct input_event ev[9];
    memset(&ev, 0, sizeof(ev));

    ev[0].type = EV_KEY;
    ev[0].code = BTN_A;
    ev[0].value = channel_data.channel5 >= 800;

    ev[1].type = EV_KEY;
    ev[1].code = BTN_B;
    ev[1].value = channel_data.channel6 >= 800;

    ev[2].type = EV_KEY;
    ev[2].code = BTN_C;
    ev[2].value = channel_data.channel7 >= 800;

    ev[3].type = EV_KEY;
    ev[3].code = BTN_X;
    ev[3].value = channel_data.channel8 >= 800;

    ev[4].type = EV_ABS;
    ev[4].code = ABS_X;
    ev[4].value = channel_data.channel1;

    ev[5].type = EV_ABS;
    ev[5].code = ABS_Y;
    ev[5].value = channel_data.channel2;

    ev[6].type = EV_ABS;
    ev[6].code = ABS_RX;
    ev[6].value = channel_data.channel3;

    ev[7].type = EV_ABS;
    ev[7].code = ABS_RY;
    ev[7].value = channel_data.channel4;

    // sync event tells input layer we're done with a "batch" of
    // updates

    ev[8].type = EV_SYN;
    ev[8].code = SYN_REPORT;
    ev[8].value = 0;

    if (write(uinput_fd, &ev, sizeof ev) < 0) {
        perror("write");
        return EXIT_FAILURE;
    }

    return EXIT_SUCCESS;
}

void timespec_diff(struct timespec *a, struct timespec *b, struct timespec *result) {
    result->tv_sec = a->tv_sec - b->tv_sec;
    result->tv_nsec = a->tv_nsec - b->tv_nsec;
    if (result->tv_nsec < 0) {
        --result->tv_sec;
        result->tv_nsec += 1000000000L;
    }
}


int main(void) {
    FILE *fp;
    struct timeval tval_before, tval_after, tval_result;

    signal(SIGINT, sig_handler);


    send_mdns_query();

    if (strlen(joystick_ip) == 0) {
        printf("joystick not found\n");
        return EXIT_FAILURE;
    }

    if (setup_uintput() != EXIT_SUCCESS) {
        printf("uinput setup failed\n");
        return EXIT_FAILURE;
    }

    if (setup_connection() != EXIT_SUCCESS) {
        printf("setup connection failed\n");
        return EXIT_FAILURE;
    }

    if (start_joystick() != EXIT_SUCCESS) {
        printf("start joystick failed\n");
        return EXIT_FAILURE;
    }

    printf("\njoystick running\n");

    gettimeofday(&tval_before, NULL);

    if (enable_time_output) {
        fp = fopen("output.csv", "w+");
    }


    while (keep_running) {
        receive_data();

        if (send_joystick_data() != EXIT_SUCCESS) {
            break;
        }

        if (enable_time_output) {
            gettimeofday(&tval_after, NULL);

            timersub(&tval_after, &tval_before, &tval_result);
            tval_before = tval_after;
            fprintf(fp, "%ld,%06ld\n", (long int) tval_result.tv_sec, (long int) tval_result.tv_usec);
        }
    }

    ioctl(uinput_fd, UI_DEV_DESTROY);
    close(uinput_fd);
    close(s);
    if (enable_time_output) {
        fclose(fp);
    }

    return EXIT_SUCCESS;
}


// enable and configure an absolute "position" analog channel
void setup_abs(int fd, unsigned chan, int min, int max) {
    if (ioctl(fd, UI_SET_ABSBIT, chan)) {
        perror("UI_SET_ABSBIT");
    }

    struct uinput_abs_setup s = {.code = chan, .absinfo = {.minimum = min, .maximum = max},};

    if (ioctl(fd, UI_ABS_SETUP, &s)) {
        perror("UI_ABS_SETUP");
    }
}
