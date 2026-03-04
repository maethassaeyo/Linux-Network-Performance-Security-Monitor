#include <iostream>
#include <fstream>
#include <string>
#include <sstream>
#include <unistd.h>

using namespace std;

int main() {
    string line;
    while(true){

        // เปิดไฟล์สำหรับอ่าน
        ifstream file("/proc/net/dev");
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
                        cout << iface << " " << recv_bytes / 1024 << "KB" << endl;
                }

            }   
            // ปิดไฟล์
            file.close();
            sleep(1);
        } else {
            cerr << "Unable to open file";
        }
    }

    return 0;
}

