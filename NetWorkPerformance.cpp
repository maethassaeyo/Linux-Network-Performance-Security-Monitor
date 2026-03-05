#include <iostream>
#include <fstream>
#include <string>
#include <sstream>
#include <unistd.h>
#include <iomanip>   // สำหรับจัดรูปแบบตาราง
using namespace std;

int main() {
    string line;
    long long prev_recv = 0;
    bool first_run = true;

    cout << fixed << setprecision(2);

    while(true){

        ifstream file("/proc/net/dev");
        long long current_recv = 0;
        string name = "";
        // ตรวจสอบว่าเปิดไฟล์ได้หรือไม่
        if (file.is_open()) {
                // อ่านไฟล์ทีละบรรทัด
            while (getline(file, line)) {
            
                if(line.find("wlp") != string::npos){
                    stringstream ss(line);
                    string iface;
                    long long recv_bytes;

                    ss >> iface;
                    ss >> recv_bytes;
                     

                    name = iface;
                    current_recv = recv_bytes;
                }

            }  
            // ปิดไฟล์
            file.close();
            double speed_kb = 0;
            
            if(!first_run){
        
                speed_kb = (current_recv - prev_recv) / 1024.0;

            }
            cout << speed_kb << endl;
            prev_recv = current_recv;
            first_run = false;

            sleep(1);
        } else {
            cerr << "Unable to open file";
        }
    }

    return 0;
}

