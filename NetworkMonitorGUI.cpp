#include <QApplication>
#include <QMainWindow>
#include <QVBoxLayout>
#include <QHBoxLayout>
#include <QLabel>
#include <QTableWidget>
#include <QHeaderView>
#include <QTimer>
#include <QThread>
#include <mutex>
#include <vector>
#include <string>
#include <fstream>
#include <sstream>
#include <iomanip>
#include <pcap.h>
#include <netinet/ip.h>
#include <arpa/inet.h>
#include <maxminddb.h>
#include <map>
#include <unistd.h>

using namespace std;

// --- Data Structures ---
struct SharedData {
    double down_speed = 0;
    double up_speed = 0;
    double latency_ms = 0;
    struct PacketInfo {
        string src;
        string dst;
        string location;
        string size;
    };
    vector<PacketInfo> packets;
    mutex mtx;
};

SharedData shared_info;
map<string, string> geo_cache;

// --- Helper Functions ---
string get_country(string ip) {
    if (geo_cache.count(ip)) return geo_cache[ip];
    int gai_error, mmdb_error;
    MMDB_s mmdb;
    mmdb_error = MMDB_open("GeoLite2-Country.mmdb", MMDB_MODE_MMAP, &mmdb);
    if (mmdb_error != MMDB_SUCCESS) return "Unknown";

    MMDB_lookup_result_s result = MMDB_lookup_string(&mmdb, ip.c_str(), &gai_error, &mmdb_error);
    if (result.found_entry) {
        MMDB_entry_data_s entry_data;
        MMDB_get_value(&result.entry, &entry_data, "country", "names", "en", NULL);
        if (entry_data.has_data) {
            string country = string(entry_data.utf8_string, entry_data.data_size);
            MMDB_close(&mmdb);
            geo_cache[ip] = country;
            return country;
        }
    }
    MMDB_close(&mmdb);
    geo_cache[ip] = "Unknown";
    return "Unknown";
}

void packet_handler(u_char *user, const struct pcap_pkthdr *pkthdr, const u_char *packet) {
    struct iphdr *ip_header = (struct iphdr *)(packet + 14);
    struct in_addr src_addr, dst_addr;
    src_addr.s_addr = ip_header->saddr;
    dst_addr.s_addr = ip_header->daddr;

    lock_guard<mutex> lock(shared_info.mtx);
    shared_info.packets.push_back({
        inet_ntoa(src_addr),
        inet_ntoa(dst_addr),
        get_country(inet_ntoa(dst_addr)),
        to_string(pkthdr->len)
    });
    if (shared_info.packets.size() > 100) shared_info.packets.erase(shared_info.packets.begin());
}

// --- Worker Threads ---
class NetworkWorker : public QObject {
    Q_OBJECT
public slots:
    void calculateSpeed() {
        string line;
        long long prev_recv_down = 0, prev_recv_up = 0;
        bool first_run = true;
        while (true) {
            ifstream file("/proc/net/dev");
            if (file.is_open()) {
                long long current_down = 0, current_up = 0;
                while (getline(file, line)) {
                    if (line.find("wlp") != string::npos || line.find("eth") != string::npos || line.find("enp") != string::npos) {
                        stringstream ss(line);
                        string iface, junk;
                        long long recv, send;
                        ss >> iface >> recv;
                        for (int i = 0; i < 7; i++) ss >> junk;
                        ss >> send;
                        current_down = recv;
                        current_up = send;
                        break;
                    }
                }
                file.close();
                if (!first_run) {
                    lock_guard<mutex> lock(shared_info.mtx);
                    shared_info.down_speed = ((current_down - prev_recv_down) * 8) / 1048576.0;
                    shared_info.up_speed = ((current_up - prev_recv_up) * 8) / 1048576.0;
                }
                prev_recv_down = current_down;
                prev_recv_up = current_up;
                first_run = false;
            }
            QThread::msleep(1000);
        }
    }

    void sniffPackets() {
        char errbuf[PCAP_ERRBUF_SIZE];
        pcap_if_t *alldevs;
        if (pcap_findalldevs(&alldevs, errbuf) == -1) return;
        string device = alldevs->name; // Pick first device
        pcap_freealldevs(alldevs);

        pcap_t *handle = pcap_open_live(device.c_str(), BUFSIZ, 1, 1000, errbuf);
        if (handle) {
            pcap_loop(handle, -1, packet_handler, NULL);
            pcap_close(handle);
        }
    }

    void pingTest() {
        string command = "ping -c 1 8.8.8.8 | grep -oP 'time=\\K[^ ]+'";
        while (true) {
            FILE* pipe = popen(command.c_str(), "r");
            if (pipe) {
                char buffer[128];
                if (fgets(buffer, sizeof(buffer), pipe) != NULL) {
                    try {
                        double ms = stod(buffer);
                        lock_guard<mutex> lock(shared_info.mtx);
                        shared_info.latency_ms = ms;
                    } catch (...) {}
                }
                pclose(pipe);
            }
            QThread::msleep(2000);
        }
    }
};

// --- Main Window ---
class MainWindow : public QMainWindow {
    Q_OBJECT
    QLabel *speedLabel;
    QTableWidget *packetTable;
    QTimer *updateTimer;

public:
    MainWindow() {
        setWindowTitle("KMITL Network Monitor (Qt)");
        resize(800, 600);

        QWidget *central = new QWidget;
        QVBoxLayout *layout = new QVBoxLayout(central);

        speedLabel = new QLabel("Initializing...");
        speedLabel->setStyleSheet("font-size: 18px; font-weight: bold; color: #2c3e50;");
        layout->addWidget(speedLabel);

        packetTable = new QTableWidget(0, 4);
        packetTable->setHorizontalHeaderLabels({"Source", "Destination", "Location", "Size (B)"});
        packetTable->horizontalHeader()->setSectionResizeMode(QHeaderView::Stretch);
        layout->addWidget(packetTable);

        setCentralWidget(central);

        updateTimer = new QTimer(this);
        connect(updateTimer, &QTimer::timeout, this, &MainWindow::updateUI);
        updateTimer->start(1000);

        startWorkers();
    }

private slots:
    void updateUI() {
        lock_guard<mutex> lock(shared_info.mtx);
        speedLabel->setText(QString("Download: %1 Mbps | Upload: %2 Mbps | Latency: %3 ms")
                            .arg(shared_info.down_speed, 0, 'f', 2)
                            .arg(shared_info.up_speed, 0, 'f', 2)
                            .arg(shared_info.latency_ms, 0, 'f', 2));

        packetTable->setRowCount(0);
        for (const auto& p : shared_info.packets) {
            int row = packetTable->rowCount();
            packetTable->insertRow(row);
            packetTable->setItem(row, 0, new QTableWidgetItem(p.src.c_str()));
            packetTable->setItem(row, 1, new QTableWidgetItem(p.dst.c_str()));
            packetTable->setItem(row, 2, new QTableWidgetItem(p.location.c_str()));
            packetTable->setItem(row, 3, new QTableWidgetItem(p.size.c_str()));
        }
        packetTable->scrollToBottom();
    }

    void startWorkers() {
        QThread *t1 = new QThread, *t2 = new QThread, *t3 = new QThread;
        NetworkWorker *w1 = new NetworkWorker, *w2 = new NetworkWorker, *w3 = new NetworkWorker;

        w1->moveToThread(t1);
        connect(t1, &QThread::started, w1, &NetworkWorker::calculateSpeed);
        t1->start();

        w2->moveToThread(t2);
        connect(t2, &QThread::started, w2, &NetworkWorker::sniffPackets);
        t2->start();

        w3->moveToThread(t3);
        connect(t3, &QThread::started, w3, &NetworkWorker::pingTest);
        t3->start();
    }
};

int main(int argc, char *argv[]) {
    QApplication app(argc, argv);
    MainWindow win;
    win.show();
    return app.exec();
}

#include "NetworkMonitorGUI.moc"
