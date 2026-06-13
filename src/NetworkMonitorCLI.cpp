#include <iostream>
#include <fstream>
#include <string>
#include <sstream>
#include <unistd.h>
#include <iomanip>
#include <thread>
#include <mutex>
#include <string>
#include <vector>
#include <pcap.h>
#include <netinet/ip.h>
#include <arpa/inet.h>
#include <maxminddb.h>
#include <map>
#include <set>
using namespace std;

struct SharedData{
    double down_speed = 0;
    double up_speed = 0;
    vector<vector<string>> ip_scan;
    double latency_ms = 0;
    set<string> blacklist;

    mutex mtx;
};

SharedData shared_info;
double speed_Mbps(int current_recv,int prev_recv){
    double speed = 0;
    
    speed = ((current_recv - prev_recv)*8) / 1048576.0;

    return speed;
}

map<string,string> geo_cache;

string get_country(string ip){
    if(geo_cache.count(ip)) return geo_cache[ip];

    int gai_error, mmdb_error;
    MMDB_s mmdb;
    mmdb_error = MMDB_open("data/GeoLite2-Country.mmdb", MMDB_MODE_MMAP, &mmdb);
    
    MMDB_lookup_result_s result = MMDB_lookup_string(&mmdb, ip.c_str(), &gai_error, &mmdb_error);
    if (result.found_entry) {
        MMDB_entry_data_s entry_data;
        MMDB_get_value(&result.entry, &entry_data, "country", "names", "en", NULL);
        if (entry_data.has_data) {
            geo_cache[ip] = string(entry_data.utf8_string,entry_data.data_size);
            return string(entry_data.utf8_string, entry_data.data_size);
        }
    }
    geo_cache[ip] = "Unknown";
    return "Unknown";

}


void load_blacklist() {
    ifstream file("data/blacklist.txt");
    if (file.is_open()) {
        lock_guard<mutex> lock(shared_info.mtx);
        string ip;
        while (getline(file, ip)) {
            if (!ip.empty()) shared_info.blacklist.insert(ip);
        }
        file.close();
    }
}

void packet_handler(u_char *user, const struct pcap_pkthdr *pkthdr, const u_char *packet) {
    struct iphdr *ip_header = (struct iphdr *)(packet + 14);
    
    struct in_addr src_addr, dst_addr;
    src_addr.s_addr = ip_header->saddr;
    dst_addr.s_addr = ip_header->daddr;
    string dst_str = inet_ntoa(dst_addr);
    
    lock_guard<mutex> lock(shared_info.mtx);
    string malicious_tag = "";
    if (shared_info.blacklist.count(dst_str)) {
        malicious_tag = " [!]";
    }

    shared_info.ip_scan.push_back({
        inet_ntoa(src_addr),
        dst_str + malicious_tag,
        get_country(dst_str),
        to_string(pkthdr->len)
    });
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
        // Check if file opened successfully
        if (file.is_open()) {
            // Read file line by line
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
            file.close();
            
            if(!first_run){
                lock_guard<mutex> lock(shared_info.mtx); 
                shared_info.down_speed = speed_Mbps(current_recv_down,prev_recv_down);
                shared_info.up_speed = speed_Mbps(current_recv_up,prev_recv_up);

            }
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

    string device = "wlp0s20f3"; 
    
    handle = pcap_open_live(device.c_str(), BUFSIZ, 1, 1000, errbuf);
    if(handle == NULL) {
        cerr << "Error opening device " << device << ": " << errbuf << endl;
        return;
    }

    while(true){
        pcap_loop(handle, 10, packet_handler, NULL);
    }
    pcap_close(handle);
}

void ping(){
    string command = "ping -c 1 8.8.8.8 | grep -oP 'time=\\K[^ ]+'";
    while(true){
        FILE* pipe = popen(command.c_str(), "r");
        if (pipe){
            char buffer[128];
            if(fgets(buffer,sizeof(buffer),pipe) != NULL){
                try{
                    double ms = stod(buffer);;
                    lock_guard<mutex> lock(shared_info.mtx);
                    shared_info.latency_ms  = ms;;
                }catch(...){
                    cerr << "No Internet Connection";
                }
            }
            pclose(pipe);
        }
        sleep(2);
    }



}

int main() {
    load_blacklist();
    thread t1(calculate_speed_Net);
    thread t2(Sniffing_Ip);
    thread t3(ping);
    while(true){
        cout << "\033[2J\033[1;1H";
        {
            lock_guard<mutex> lock(shared_info.mtx);
            cout << "=== KMITL PORTFOLIO: NETWORK MONITOR ===" << endl;
            if (!shared_info.blacklist.empty()) {
                cout << "[Status] Security Database: Loaded (" << shared_info.blacklist.size() << " malicious IPs)" << endl;
            }
            cout << fixed << setprecision(2);
            cout << "DOWNLOAD: " << shared_info.down_speed << " Mbps" << endl;
            cout << "UPLOAD:   " << shared_info.up_speed << " Mbps" << endl;
            cout << "Latency:  " << shared_info.latency_ms << " ms" << endl;
            cout << "----------------------------------------" << endl;
            cout << left << setw(18) << "SOURCE" 
     << setw(22) << "DEST" 
     << setw(15) << "LOCATION" 
     << "SIZE" << endl;
            for(const auto& pkt : shared_info.ip_scan) {
                cout << left << setw(18) << pkt[0] << setw(22) << pkt[1] << setw(15) << pkt[2] << pkt[3] << endl;
            }
            shared_info.ip_scan.clear(); 
            cout << "========================================" << endl;
        }
        sleep(1);
    }

    t1.join();
    t2.join();
    t3.join();
    return 0;
}
