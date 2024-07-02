#include "struct.h"

ID_conversion ID_list[ID_LIST_SIZE];

trie list_trie[MAX_NUM];
int list_size = 0;
int cache_size = 0;

lru_node* head;
lru_node* tail;

//字符串形式的IP地址转换为一个4字节的整型数组形式
static void transfer_ip(uint8_t* this_IP, char* IP_addr) {
    int i;
    int tmp = 0;
    int IP_pos = 0;
    char* ptr = IP_addr;

    for (i = 0; i < strlen(IP_addr); i++) {
        if (*ptr != '.') {
            tmp = tmp * 10 + (*ptr - '0');
        }
        else {
            this_IP[IP_pos++] = tmp;
            tmp = 0;
        }
        ptr++;
    }

    this_IP[3] = tmp;
}

//返回每个字符对应的序号
int get_num(uint8_t val) {
    int num = 0;

    if (val >= '0' && val <= '9') {
        num = val - '0';
    }

    else if (val >= 'a' && val <= 'z') {
        num = val - 'a' + 10;
    }

    else if (val >= 'A' && val <= 'Z') {
        num = val - 'A' + 10;
    }

    else if (val == '-') {
        num = 36;
    }

    else if (val == '.') {
        num = 37;
    }

    return num;
}

//在字典树上添加节点
void add_node(trie* root, uint8_t* IP, char* domain) {
    int index = 0;
    int i;
    //给每个字符找前驱后继
    for (i = 0; i < strlen(domain); i++) {
        int num = get_num(domain[i]);

        if (list_trie[index].val[num] == 0) {
            list_size++;
            list_trie[index].val[num] = list_size;
        }
        list_trie[list_trie[index].val[num]].pre = index;
        index = list_trie[index].val[num];
    }

    //如果找到头，存入对应的字符串
    for (i = 0; i < 4; i++) {
        list_trie[index].IP[i] = IP[i];
    }

    list_trie[index].isEnd = 1;
}

//在字典树中查找
int query_node(trie* root, char* domain, uint8_t* ip_addr) {
    int index = 0, i;
    int flag = 0;
    //从根节点逐步向下
    for (i = 0; i < strlen(domain); i++) {
        int num = get_num(domain[i]);

        if (list_trie[index].val[num] == 0) {
            return flag;
        }

        index = list_trie[index].val[num];
    }
    //如果不是叶节点
    if (list_trie[index].isEnd == 0) {

        if (debug_mode == 1) {
            printf("Address not found in hosts.\n");
        }

        return flag;
    }
    //如果找到
    if (debug_mode == 1) {
        printf("Address found in hosts: ");
        for (i = 0; i < 3; i++) {
            printf("%d.", list_trie[index].IP[i]);
        }
        printf("%d\n", list_trie[index].IP[3]);
    }

    update_cache(list_trie[index].IP, domain);
    memcpy(ip_addr, list_trie[index].IP, 4);

    return 1;
}


//链表初始化
void init_cache() {
    head = malloc(sizeof(lru_node));
    tail = malloc(sizeof(lru_node));
    head->next = tail;
    tail->prev = head;
    head->prev = NULL;
    tail->next = NULL;
}

//在cache中查询
int query_cache(char* domain, uint8_t* ip_addr) {
    lru_node* ptr = head->next;
    lru_node* result = NULL;
    int flag = 0;

    // 从头开始遍历
    while (ptr != tail) {
        if (strcmp(ptr->domain, domain) == 0) { // 找到了域名
            flag = 1;
            if (debug_mode == 1) {
                printf("Address found in cache: ");
                printf("%d %d %d %d\n", ptr->IP[0], ptr->IP[1], ptr->IP[2], ptr->IP[3]);
            }
            memcpy(ip_addr, ptr->IP, sizeof(ptr->IP));
            result = ptr;

            // 将找到的节点移动到链表头部
            result->prev->next = result->next;
            result->next->prev = result->prev;
            result->next = head->next;
            result->prev = head;
            head->next->prev = result;
            head->next = result;

            break;
        }
        ptr = ptr->next;
    }

    // 如果没有找到域名
    if (!flag) {
        return 0;
    }
    else {
        return 1;
    }
}

//更新cache
void update_cache(uint8_t ip_addr[4], char* domain) {
    lru_node* newNode = malloc(sizeof(lru_node)); // 新节点
    if (cache_size > MAX_CACHE) {
        delete_cache();
    } // 删掉最老的节点

    memcpy(newNode->IP, ip_addr, sizeof(uint8_t) * 4);
    memcpy(newNode->domain, domain, strlen(domain) + 1);

    // 插入新节点到链表头部
    newNode->next = head->next;
    newNode->prev = head;
    head->next->prev = newNode;
    head->next = newNode;
    cache_size++;
}

//删除尾节点
void delete_cache() {
    lru_node* toDelete = tail->prev;
    toDelete->prev->next = tail;
    tail->prev = toDelete->prev;
    free(toDelete);
    cache_size--;
}

uint16_t update_id(uint16_t client_ID, struct sockaddr_in client_addr) {
    uint16_t i;
    for (i = 0; i < ID_LIST_SIZE; i++) {
        if (ID_list[i].expire_time < time(NULL)) {
            ID_list[i].client_ID = client_ID;
            ID_list[i].client_addr = client_addr;
            ID_list[i].expire_time = ID_EXPIRE_TIME + time(NULL); // 预期过期时间
        }
        break;
    }
    return i;
}

//打开文件
void read_host() {
    FILE* host_ptr = fopen(HOST_PATH, "r");
    int num = 0;

    if (!host_ptr) {
        printf("Error! Can not open hosts file!\n");
        exit(1);
    }

    // 从HOST文件中读取域名和IP地址
    while (!feof(host_ptr)) { // 循环读取文件直到结束
        uint8_t this_ip[4];

        fscanf(host_ptr, "%s", IPAddr);
        fscanf(host_ptr, "%s", domain);
        num++;
        transfer_ip(this_ip, IPAddr); // 转换IP地址
        add_node(list_trie, this_ip, domain); // 添加域名节点
    }

    if (debug_mode == 1) {
        printf("%d domain name address info has been loaded.\n\n", num);
    }
}
