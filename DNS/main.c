#include "header.h"
#include "cmd.h"

int main(int argc, char* argv[]) {

    init(argc, argv);

    //�ʺ�IOƵ�����Ҳ������ݵ����,û�ж���д��ʱ��Ҳ�ܼ������У�����ͣ��ĳ���߳��ϡ�
    if (mode == 0) {
        nonblock();
    }
    //�ʺ������������ϵȴ��ϳ�ʱ��Ĳ���
    if (mode == 1) {
        poll();
    }

    close_server();
    return 0;
}