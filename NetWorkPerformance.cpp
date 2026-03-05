#include <iostream>
#include <fstream>
#include <string>
#include <sstream>
#include <unistd.h>
#include <iomanip>   // สำหรับจัดรูปแบบตาราง
using namespace std;

double speed_kb(int current_recv,int prev_recv){
    double speed = 0;
    
    speed = (current_recv - prev_recv) / 1024.0;

    return speed;
}

int main() {
    string line;
    long long prev_recv_down = 0;
    long long prev_recv_up = 0;
    bool first_run = true;

    cout << fixed << setprecision(2);

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

                    cout << uplode_bytes << endl;

                    name = iface;
                    current_recv_down = recv_bytes;
                    current_recv_up = uplode_bytes;
                }

            }  
            // ปิดไฟล์
            file.close();
            double down_speed_kb = 0;
            double up_speed_kb = 0;
            
            if(!first_run){
        
                down_speed_kb = speed_kb(current_recv_down,prev_recv_down);
                up_speed_kb = speed_kb(current_recv_up,prev_recv_up);

            }
            cout << "Downlond Speed : " << down_speed_kb << "\nUplode Speed : " << up_speed_kb << endl;
            prev_recv_down = current_recv_down;
            prev_recv_up = current_recv_up;
            first_run = false;

            sleep(1);
        } else {
            cerr << "Unable to open file";
        }
    }

    return 0;
}

