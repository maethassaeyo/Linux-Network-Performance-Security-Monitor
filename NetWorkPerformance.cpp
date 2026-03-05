#include <iostream>
#include <fstream>
#include <string>
#include <sstream>
#include <unistd.h>
#include <iomanip>
#include <thread>
#include <chrono>
#include <pcap.h>
#include <netinet/ip.h>
#include <arpa/inet.h>


using namespace std;

double speed_Mbps(int current_recv,int prev_recv){
    double speed = 0;
    
    speed = ((current_recv - prev_recv)*8) / 1048576.0;

    return speed;
}

void packet_handler(u_char *user, const struct pcap_pkthdr *pkthdr, const u_char *packet) {
    // โครงสร้าง: Ethernet Header (14 bytes) -> IP Header
    struct iphdr *ip_header = (struct iphdr *)(packet + 14);

    // แปลง IP จากตัวเลขเป็น String ที่คนอ่านออก
    struct in_addr src_addr, dst_addr;
    src_addr.s_addr = ip_header->saddr;
    dst_addr.s_addr = ip_header->daddr;

    cout << "From: " << inet_ntoa(src_addr) 
         << " -> To: " << inet_ntoa(dst_addr) 
         << " | Size: " << pkthdr->len << " bytes" << endl;
}

void calculate_speed_Net(){
    string line;
    long long prev_recv_down = 0;
    long long prev_recv_up = 0;
    bool first_run = true;

    cout << fixed << setprecision(3);

    while(true){

        ifstream file("/proc/net/dev");
        long long current_recv_down = 0;
        long long current_recv_up = 0;
        string name = "";
        // ตรวจสอบว่าเปิดไฟล์ได้หรือไม่
        if (file.is_open()) {
                // อ่านไฟล์ทีละบรรทัด
            while (getline(file, line)) {
            
                if(line.find("wlp") != string::npos){
                    stringstream ss(line);
                    string iface,junk;
                    long long recv_bytes,uplode_bytes;
                    
                    ss >> iface;
                    ss >> recv_bytes;
                    for(int i = 0;i < 7;i++){
                        ss >> junk;
                    } 
                    ss >> uplode_bytes;

                    name = iface;
                    current_recv_down = recv_bytes;
                    current_recv_up = uplode_bytes;
                }

            }  
            // ปิดไฟล์
            file.close();
            double down_speed_Mbps = 0;
            double up_speed_Mbps = 0;
            
            if(!first_run){
        
                down_speed_Mbps = speed_Mbps(current_recv_down,prev_recv_down);
                up_speed_Mbps = speed_Mbps(current_recv_up,prev_recv_up);

            }
            cout << "Downlond Speed : " << down_speed_Mbps << " Mbps\nUplode Speed : " << up_speed_Mbps << " Mbps" << endl;
            prev_recv_down = current_recv_down;
            prev_recv_up = current_recv_up;
            first_run = false;

            sleep(1);
        } else {
            cerr << "Unable to open file";
        }
    }


}

void Sniffing_Ip(){

char errbuf[PCAP_ERRBUF_SIZE];
    pcap_t *handle;

    // 1. เลือก Interface (ในเครื่องคุณอาจเป็น wlp... หรือ eth0)
    string device = "wlp0s20f3"; // แก้ชื่อให้ตรงกับเครื่องคุณ
    while(true){
        // 2. เปิดการดักจับ (Open live capture)
        handle = pcap_open_live(device.c_str(), BUFSIZ, 1, 1000, errbuf);
    
        if (handle == NULL) {
            cerr << "Error: " << errbuf << endl;
        }

        cout << "Sniffing on " << device << "..." << endl;

        // 3. เริ่มวนลูปดักจับ (ดักจับ 10 packets แล้วเลิก)
        pcap_loop(handle, 100, packet_handler, NULL);
        sleep(3);
        cout << "\033[2J\033[1;1H";
    }
    pcap_close(handle);


}

int main() {
    thread t1(calculate_speed_Net);
    thread t2(Sniffing_Ip);
    t1.join();
    t2.join();
    return 0;
}

