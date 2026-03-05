#include <iostream>
#include <pcap.h>
#include <netinet/ip.h>
#include <arpa/inet.h>
#include <unistd.h>
using namespace std;

// ฟังก์ชันที่จะถูกเรียกทุกครั้งที่มี Packet วิ่งเข้ามา
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

int main() {
    char errbuf[PCAP_ERRBUF_SIZE];
    pcap_t *handle;

    // 1. เลือก Interface (ในเครื่องคุณอาจเป็น wlp... หรือ eth0)
    string device = "wlp0s20f3"; // แก้ชื่อให้ตรงกับเครื่องคุณ
    while(true){
        // 2. เปิดการดักจับ (Open live capture)
        handle = pcap_open_live(device.c_str(), BUFSIZ, 1, 1000, errbuf);
    
        if (handle == NULL) {
            cerr << "Error: " << errbuf << endl;
            return 1;
        }

        cout << "Sniffing on " << device << "..." << endl;

        // 3. เริ่มวนลูปดักจับ (ดักจับ 10 packets แล้วเลิก)
        pcap_loop(handle, 10, packet_handler, NULL);
        sleep(3);
        cout << "\033[2J\033[1;1H";
    }
    pcap_close(handle);
    return 0;
}
