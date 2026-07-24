#include <fcntl.h>
#include <stdlib.h>
#include <stdio.h>
#include <unistd.h>
#include <poll.h>
#include <string.h>
#include <sys/fanotify.h>
#include <sys/mount.h>
#include <sys/stat.h>
#include <sys/types.h>
#include <limits.h>
#include <errno.h>

static int is_pdf_magic(int fd) {
    printf("[DEBUG] Checking PDF magic for fd %d\n", fd);
    const char pdf_magic[] = "%PDF-";
    char buf[sizeof(pdf_magic)];
    if (lseek(fd, 0, SEEK_SET) < 0) {
        perror("lseek failed");
        return 0;
    }
    ssize_t n = read(fd, buf, sizeof(buf) - 1);
    if (n < (ssize_t)(sizeof(buf) - 1)) {
        printf("[DEBUG] Read too few bytes: %zd\n", n);
        return 0;
    }
    buf[sizeof(buf) - 1] = '\0';
    int result = (memcmp(buf, pdf_magic, sizeof(pdf_magic) - 1) == 0);
    printf("[DEBUG] Magic check result: %d\n", result);
    return result;
}

static int add_usb_mounts(int fan_fd) {
    printf("[DEBUG] Adding USB mounts to watch\n");
    FILE *mtab = fopen("/proc/mounts", "r");
    if (!mtab) { perror("fopen /proc/mounts"); return -1; }
    char dev[256], mnt[PATH_MAX], type[32], opts[256];
    while (fscanf(mtab, "%255s %4095s %31s %255s %*d %*d\n", dev, mnt, type, opts) == 4) {
        printf("[DEBUG] Found mount: device=%s mnt=%s type=%s\n", dev, mnt, type);
        if (strcmp(type, "vfat")==0 || strcmp(type,"ntfs")==0 || strcmp(type,"exfat")==0) {
            printf("[DEBUG] Attempting to watch mount: %s\n", mnt);
            if (fanotify_mark(fan_fd,
                              FAN_MARK_ADD | FAN_MARK_MOUNT,
                              FAN_OPEN_PERM | FAN_OPEN_EXEC_PERM,
                              AT_FDCWD, mnt) < 0) {
                fprintf(stderr, "fanotify_mark %s failed: %s\n", mnt, strerror(errno));
            } else {
                printf("▶ watching mount %s\n", mnt);
            }
        }
    }
    fclose(mtab);
    return 0;
}

int main(void) {
    printf("[DEBUG] Initializing fanotify\n");
    int fan_fd = fanotify_init(FAN_CLASS_CONTENT | FAN_CLOEXEC | FAN_NONBLOCK,
                               O_RDONLY);
    if (fan_fd < 0) { perror("fanotify_init"); exit(1); }

    add_usb_mounts(fan_fd);

    printf("[DEBUG] Starting event loop\n");
    struct pollfd pfd = { .fd = fan_fd, .events = POLLIN };
    while (1) {
        if (poll(&pfd, 1, -1) <= 0) {
            perror("poll failed or interrupted");
            continue;
        }

        printf("[DEBUG] Event received\n");
        struct fanotify_event_metadata buf[200];
        ssize_t len = read(fan_fd, buf, sizeof(buf));
        if (len <= 0) {
            perror("read failed");
            continue;
        }
        printf("[DEBUG] Read %zd bytes of event data\n", len);

        for (char *ptr = (char*)buf;
             ptr < (char*)buf + len;
             ptr += ((struct fanotify_event_metadata*)ptr)->event_len)
        {
            struct fanotify_event_metadata *evt = (void*)ptr;
            printf("[DEBUG] Processing event mask=0x%llx fd=%d\n", (unsigned long long)evt->mask, evt->fd);
            if (evt->mask & FAN_Q_OVERFLOW) {
                printf("[DEBUG] Queue overflow event\n");
                continue;
            }
            if (!(evt->mask & FAN_OPEN_PERM)) {
                printf("[DEBUG] Not an open permission event\n");
                continue;
            }

            // int fd = openat(evt->fd, "", O_RDONLY );
            // if (fd < 0) {
            //     perror("openat failed");
            //     close(evt->fd);
            //     continue;
            // }

            printf("[DEBUG] Opened fd %d to check magic\n", evt->fd);
            int is_pdf = is_pdf_magic(evt->fd);

            struct fanotify_response resp = {
                .fd = evt->fd,
                .response = is_pdf ? FAN_DENY : FAN_ALLOW
            };
            if (write(fan_fd, &resp, sizeof(resp)) < 0) {
                perror("write fanotify_response failed");
            }

            if (is_pdf) {
                printf("[NOTICE] Detected PDF (by magic) on fd %d\n", evt->fd);
            } else {
                printf("[DEBUG] Not a PDF, allowed fd %d\n", evt->fd);
            }

            close(evt->fd);
        }
    }
    close(fan_fd);
    return 0;
}

