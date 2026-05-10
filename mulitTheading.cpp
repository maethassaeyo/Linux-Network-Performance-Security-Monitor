#include <iostream>
#include <thread>
#include <chrono>

using namespace std;

// ฟังก์ชันที่จะให้พนักงานคนที่ 1 ทำ
void capture_packets() {
    while(true) {
        cout << "[Thread 1] ดักจับ Packet อยู่..." << endl;
        this_thread::sleep_for(chrono::milliseconds(500));
    }
}

// ฟังก์ชันที่จะให้พนักงานคนที่ 2 ทำ
void calculate_speed() {
    while(true) {
        cout << "[Thread 2] กำลังคำนวณความเร็วเน็ต..." << endl;
        this_thread::sleep_for(chrono::seconds(1));
    }
}

int main() {
    // สร้างพนักงาน (Thread) และสั่งให้เริ่มงานทันที
    thread t1(capture_packets);
    thread t2(calculate_speed);

    // .join() คือการบอกให้ main() รอให้ thread นั้นๆ ทำงานเสร็จก่อนถึงจะจบโปรแกรม
    t1.join();
    t2.join();

    return 0;
}
