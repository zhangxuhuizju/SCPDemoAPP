#include <jni.h>
#include <string>
// #include "../TCPTest/getTime.cc"
#include <thread>
#include <unordered_map>
#include <fstream>
#include "libs/include/scp_interface.h"
#include "libs/include/log.h"
#include <random>

#define LOCAL_PORT_USED 17000
#define REMOTE_PORT_USED 17001

#define LOCAL_ADDR "0.0.0.0"
static bool rst_flag = false;

static const int packet[7] = {99, 99, 11, 11, 999, 999, 9};

void update();
void finish();

void rst_handle(){
    FakeConnection* fc = ConnManager::get_conn(ConnidManager::local_conn_id);
    if (!fc) return;
    rst_flag = true;
    int count = 10;
    while (rst_flag && count-- > 0) {
        scp_send_keep_alive(fc);
        std::this_thread::sleep_for(std::chrono::milliseconds(50));
    }
    LOGI("reconnect ok!!");
    //do resend, send heart beat is ok
}

void end_scp() {
    std::this_thread::sleep_for(std::chrono::seconds(15));
    scp_close();
}

void service_thread(int op){
    int stat;
    ssize_t n;
    char recvbuf[4096];
    uint32_t this_conn_id;
    int recv_packets = 0;
//    testData.clear();
    int headlen = ConnManager::tcp_enable ? 70 : 8;

    addr_port src;
    bool tcpenable = ConnManager::tcp_enable;
    struct sockaddr_in fromAddr;
    socklen_t fromAddrLen = sizeof(fromAddr);
    int recvCount = 0;
    std::string filename = std::string("/data/data/com.example.scptestapp/result") + std::to_string(op) + ".txt";
    FILE* file = fopen(filename.c_str(), "w+");
    std::unordered_set<std::string> record;

    while(ConnManager::local_recv_fd){
        uint64_t recvTime = getMillis();
        if(tcpenable){
            n = recvfrom(ConnManager::local_recv_fd,recvbuf,4096,0,NULL,NULL);
            stat = parse_frame(recvbuf + 14,n-14,this_conn_id,src);
        }else{
            n = recvfrom(ConnManager::local_recv_fd,recvbuf,4096,0,(struct sockaddr*)&fromAddr,&fromAddrLen);
            src.sin = fromAddr.sin_addr.s_addr;
            src.port = fromAddr.sin_port;
            stat = parse_frame(recvbuf ,n,this_conn_id,src);
        }
        if(stat == 7){
            if(n < 30) continue;
            int padding = 0;
            if(n > 1900) padding = 1900;
            std::string data = std::string(recvbuf + headlen, n-headlen-padding);
            if (record.find(data) != record.end())
                continue;
            record.insert(data);
            //LOGI("%s", data.c_str());
            //data += " recvTime:" + std::to_string(recvTime);
            //fprintf(file, "%s\n", data.c_str());
            update();
            //std::cout << i->first << "   " << past << std::endl;
            //uint64_t time = recvTime - std::stoull(past);
            ++recvCount;
//            if (recvCount % 5 == 0)
//                fflush(file);
            if (recvCount > packet[op]) {
                LOGI("test finished!");
                //fclose(file);
                finish();
                std::thread finish_thr(end_scp);
                finish_thr.detach();
            }
        } else if (stat == 9) {
            rst_flag = false;
        }
    }
}

extern "C" JNIEXPORT void JNICALL
Java_com_example_scptestapp_NetworkChangeReceiver_reset(JNIEnv* env, jobject /* this */thiz) {
    LOGI("before reconnect!");
    rst_handle();
}

static JavaVM* jvm = nullptr;
static jobject object = nullptr;

extern "C" JNIEXPORT jint JNICALL
Java_com_example_scptestapp_FirstTest_startTest(JNIEnv* env, jobject /* this */thiz,
                                                jstring ip, jint op, jint time){
    env->GetJavaVM(&jvm);
    object = env->NewGlobalRef(thiz);

    const char* REMOTE_IP = env->GetStringUTFChars(ip, nullptr);

    int ret = init_rawsocket(false, false);
    if(ret)
        LOGI("init raw socket error!");
    else LOGI("init raw socket ok!");

    scp_bind(inet_addr(LOCAL_ADDR),LOCAL_PORT_USED);

    if (time > 180*1000)
        ConnManager::heartBeatTime = time * 1000;

    std::thread ser(service_thread, op);

    ser.detach();

    //std::this_thread::sleep_for(std::chrono::seconds(1));

    ret = scp_connect(inet_addr(REMOTE_IP),REMOTE_PORT_USED);
    LOGI("connect result: %d", ret);
    char msgbuffer[8];
    msgbuffer[0] = '0' + op;
    scp_send(msgbuffer,2,ConnManager::get_conn(ConnidManager::local_conn_id));

    return 0;
}

void update() {
    JNIEnv* env;
    jvm->AttachCurrentThread(&env, nullptr);

    if (env == nullptr) {
        LOGI("env null!!!\n");
        return;
    }
    jclass clazz = env->GetObjectClass(object);

    if (clazz == nullptr) {
        LOGI("class null!\n");
        return;
    }

    jmethodID callBackMethod = env->GetStaticMethodID(clazz, "updateInfo", "()V");
    if (callBackMethod == nullptr) {
        LOGI("method null!\n");
        return;
    }

    env->CallStaticVoidMethod(clazz, callBackMethod);
}

void finish() {
    JNIEnv *env;
    jvm->AttachCurrentThread(&env, nullptr);

    if (env == nullptr) {
        LOGI("env null!!!\n");
        return;
    }
    jclass clazz = env->GetObjectClass(object);

    if (clazz == nullptr) {
        LOGI("class null!\n");
        return;
    }

    jmethodID callBackMethod = env->GetStaticMethodID(clazz, "finishTest", "()V");
    if (callBackMethod == nullptr) {
        LOGI("method null!\n");
        return;
    }

    env->CallStaticVoidMethod(clazz, callBackMethod);
    jvm->DetachCurrentThread();
}
