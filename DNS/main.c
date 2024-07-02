#include "header.h"
#include "cmd.h"

int main(int argc, char* argv[]) {

    init(argc, argv);

    //适合IO频繁而且操作短暂的情况,没有读或写的时候也能继续运行，不会停在某个线程上。
    if (mode == 0) {
        nonblock();
    }
    //适合在少数连接上等待较长时间的操作
    if (mode == 1) {
        poll();
    }

    close_server();
    return 0;
}