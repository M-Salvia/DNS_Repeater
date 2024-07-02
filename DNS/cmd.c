#include "cmd.h"
#include "struct.h"

int debug_mode = 0;
int log_mode = 0;
int block_mode = 0;

char* HOST_PATH = "D:\\DNS\\DNS\\dnsrelay2.txt";
char* LOG_PATH = "D:\\DNS\\DNS\\log.txt";


void init(int argc, char* argv[]) {
    int mode = 0;
    int is_listen = 0;

    get_config(argc, argv);

    init_socket();

    init_id_list();

    init_cache();

    read_host();
}
//初始化一个ID映射表
void init_id_list() {
    for (int i = 0; i < ID_LIST_SIZE; i++)
    {
        ID_list[i].client_ID = 0;
        ID_list[i].expire_time = 0;
        memset(&(ID_list[i].client_addr), 0, sizeof(struct sockaddr_in));
    }
}

static void handle_option_d() {
    debug_mode = 1;
}

static void handle_option_l() {
    log_mode = 1;
}

static void handle_option_i() {
    printf("Hosts path: %s\n", HOST_PATH);
    printf("Remote DNS server address: %s  \n", remote_dns);
    printf("mode: %s\n", mode == 0 ? "nonblock" : "poll");
}

static void handle_option_s(char* address) {
    if (address) {
        char* addr = malloc(16);
        if (addr) {
            strncpy(addr, address, 15);
            addr[15] = '\0'; // Ensure null termination
            remote_dns = addr;
        }
    }
}

static void get_config(int argc, char* argv[]) {

    info();
    for (int index = 1; index < argc; index++) {
        if (!strcmp(argv[index], "-d")) {
            handle_option_d();
        }
        else if (!strcmp(argv[index], "-l")) {
            handle_option_l();
        }
        else if (!strcmp(argv[index], "-s") && index + 1 < argc) {
            handle_option_s(argv[++index]);
        }
        else if (!strcmp(argv[index], "-m") && index + 1 < argc) {
            index++;
            mode = (strcmp(argv[index], "0") == 0) ? 0 : 1;
        }
    }

    for (int index = 1; index < argc; index++) {
        if (!strcmp(argv[index], "-i")) {
            handle_option_i();
        }
    }
}

void info() {
    printf("================================================================================\n");
    printf("                         Welcome to use DNS Repeater!\n");
    printf("--------------------------------------------------------------------------------\n");
    printf("Usage: Submit your query via terminal and view the response in your terminal.\n");
    printf("Example: nslookup www.baidu.com 127.0.0.1\n");
    printf("\n");
    printf("Options:\n");
    printf("  -i\t\tPrint basic information\n");
    printf("  -d\t\tPrint debug information\n");
    printf("  -l\t\tPrint log\n");
    printf("  -s <server>\tSet remote DNS server address\n");
    printf("  -m <mode>\tSet mode (0: nonblock, 1: poll)\n");
    printf("================================================================================\n");
}



void write_log(char* domain, uint8_t* ip_addr)
{
    FILE* fp = fopen(LOG_PATH, "a");
    if (fp == NULL)
    {
        if (debug_mode == 1) {
            printf("File open failed.\n");
        }
    }
    else
    {
        if (debug_mode == 1) {
            printf("File open succeed.\n");
        }
        // 获取当前时间
        time_t currentTime = time(NULL);
        // 将时间转换为本地时间
        struct tm* localTime = localtime(&currentTime);
        // 格式化并打印时间
        char timeString[100];
        strftime(timeString, sizeof(timeString), "%Y-%m-%d %H:%M:%S", localTime);
        fprintf(fp, "%s  ", timeString);

        fprintf(fp, "%s  ", domain);
        if (ip_addr != NULL)
            fprintf(fp, "%d.%d.%d.%d\n", ip_addr[0], ip_addr[1], ip_addr[2], ip_addr[3]);
        else
            fprintf(fp, "Not found in local. Returned from remote DNS server.\n");

        // 刷新缓冲区并关闭文件
        fflush(fp);
        fclose(fp);
    }
}