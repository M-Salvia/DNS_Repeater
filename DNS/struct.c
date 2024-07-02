#include "struct.h"

ID_conversion ID_list[ID_LIST_SIZE];

trie list_trie[MAX_NUM];
int list_size = 0;
int cache_size = 0;

lru_node* head;
lru_node* tail;

//�ַ�����ʽ��IP��ַת��Ϊһ��4�ֽڵ�����������ʽ
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

//����ÿ���ַ���Ӧ�����
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

//���ֵ�������ӽڵ�
void add_node(trie* root, uint8_t* IP, char* domain) {
    int index = 0;
    int i;
    //��ÿ���ַ���ǰ�����
    for (i = 0; i < strlen(domain); i++) {
        int num = get_num(domain[i]);

        if (list_trie[index].val[num] == 0) {
            list_size++;
            list_trie[index].val[num] = list_size;
        }
        list_trie[list_trie[index].val[num]].pre = index;
        index = list_trie[index].val[num];
    }

    //����ҵ�ͷ�������Ӧ���ַ���
    for (i = 0; i < 4; i++) {
        list_trie[index].IP[i] = IP[i];
    }

    list_trie[index].isEnd = 1;
}

//���ֵ����в���
int query_node(trie* root, char* domain, uint8_t* ip_addr) {
    int index = 0, i;
    int flag = 0;
    //�Ӹ��ڵ�������
    for (i = 0; i < strlen(domain); i++) {
        int num = get_num(domain[i]);

        if (list_trie[index].val[num] == 0) {
            return flag;
        }

        index = list_trie[index].val[num];
    }
    //�������Ҷ�ڵ�
    if (list_trie[index].isEnd == 0) {

        if (debug_mode == 1) {
            printf("Address not found in hosts.\n");
        }

        return flag;
    }
    //����ҵ�
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


//�����ʼ��
void init_cache() {
    head = malloc(sizeof(lru_node));
    tail = malloc(sizeof(lru_node));
    head->next = tail;
    tail->prev = head;
    head->prev = NULL;
    tail->next = NULL;
}

//��cache�в�ѯ
int query_cache(char* domain, uint8_t* ip_addr) {
    lru_node* ptr = head->next;
    lru_node* result = NULL;
    int flag = 0;

    // ��ͷ��ʼ����
    while (ptr != tail) {
        if (strcmp(ptr->domain, domain) == 0) { // �ҵ�������
            flag = 1;
            if (debug_mode == 1) {
                printf("Address found in cache: ");
                printf("%d %d %d %d\n", ptr->IP[0], ptr->IP[1], ptr->IP[2], ptr->IP[3]);
            }
            memcpy(ip_addr, ptr->IP, sizeof(ptr->IP));
            result = ptr;

            // ���ҵ��Ľڵ��ƶ�������ͷ��
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

    // ���û���ҵ�����
    if (!flag) {
        return 0;
    }
    else {
        return 1;
    }
}

//����cache
void update_cache(uint8_t ip_addr[4], char* domain) {
    lru_node* newNode = malloc(sizeof(lru_node)); // �½ڵ�
    if (cache_size > MAX_CACHE) {
        delete_cache();
    } // ɾ�����ϵĽڵ�

    memcpy(newNode->IP, ip_addr, sizeof(uint8_t) * 4);
    memcpy(newNode->domain, domain, strlen(domain) + 1);

    // �����½ڵ㵽����ͷ��
    newNode->next = head->next;
    newNode->prev = head;
    head->next->prev = newNode;
    head->next = newNode;
    cache_size++;
}

//ɾ��β�ڵ�
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
            ID_list[i].expire_time = ID_EXPIRE_TIME + time(NULL); // Ԥ�ڹ���ʱ��
        }
        break;
    }
    return i;
}

//���ļ�
void read_host() {
    FILE* host_ptr = fopen(HOST_PATH, "r");
    int num = 0;

    if (!host_ptr) {
        printf("Error! Can not open hosts file!\n");
        exit(1);
    }

    // ��HOST�ļ��ж�ȡ������IP��ַ
    while (!feof(host_ptr)) { // ѭ����ȡ�ļ�ֱ������
        uint8_t this_ip[4];

        fscanf(host_ptr, "%s", IPAddr);
        fscanf(host_ptr, "%s", domain);
        num++;
        transfer_ip(this_ip, IPAddr); // ת��IP��ַ
        add_node(list_trie, this_ip, domain); // ��������ڵ�
    }

    if (debug_mode == 1) {
        printf("%d domain name address info has been loaded.\n\n", num);
    }
}
