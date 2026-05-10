#include <QApplication>
#include <QMainWindow>
#include <QVBoxLayout>
#include <QHBoxLayout>
#include <QLabel>
#include <QTableWidget>
#include <QHeaderView>
#include <QTimer>
#include <QThread>
#include <QProgressBar>
#include <QPushButton>
#include <QProcess>
#include <QJsonDocument>
#include <QJsonObject>
#include <mutex>
#include <vector>
#include <string>
#include <fstream>
#include <sstream>
#include <iomanip>
#include <pcap.h>
#include <netinet/ip.h>
#include <netinet/tcp.h>
#include <netinet/udp.h>
#include <arpa/inet.h>
#include <maxminddb.h>
#include <map>
#include <set>
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
        int size;
        string protocol;
        bool is_malicious;
    };
    vector<PacketInfo> packets;
    map<string, int> proto_stats; // Protocol distribution
    set<string> blacklist;
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
    string dst_str = inet_ntoa(dst_addr);

    string proto = "OTHER";
    if (ip_header->protocol == IPPROTO_TCP) proto = "TCP";
    else if (ip_header->protocol == IPPROTO_UDP) {
        struct udphdr *udp_header = (struct udphdr *)(packet + 14 + (ip_header->ihl * 4));
        if (ntohs(udp_header->dest) == 53 || ntohs(udp_header->source) == 53) proto = "DNS";
        else proto = "UDP";
    }
    else if (ip_header->protocol == IPPROTO_ICMP) proto = "ICMP";

    lock_guard<mutex> lock(shared_info.mtx);
    shared_info.proto_stats[proto]++;
    
    bool malicious = shared_info.blacklist.count(dst_str);

    shared_info.packets.push_back({
        inet_ntoa(src_addr),
        dst_str,
        get_country(dst_str),
        (int)pkthdr->len,
        proto,
        malicious
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
        string device = alldevs->name;
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

    void loadBlacklist() {
        lock_guard<mutex> lock(shared_info.mtx);
        shared_info.blacklist.insert("1.1.1.1");
        shared_info.blacklist.insert("8.8.4.4");
    }
};

// --- Main Window ---
class MainWindow : public QMainWindow {
    Q_OBJECT
    QLabel *speedLabel;
    QLabel *statsLabel;
    QLabel *speedTestResultLabel;
    QPushButton *speedTestButton;
    QTableWidget *packetTable;
    QTimer *updateTimer;

public:
    MainWindow() {
        setWindowTitle("KMITL All-in-one Network Dashboard");
        resize(1000, 800);

        QWidget *central = new QWidget;
        QVBoxLayout *layout = new QVBoxLayout(central);

        // Speed Dashboard
        speedLabel = new QLabel("Initializing...");
        speedLabel->setStyleSheet("font-size: 20px; font-weight: bold; color: #ffffff; background-color: #34495e; padding: 15px; border-radius: 10px;");
        layout->addWidget(speedLabel);

        // Speed Test Section
        QHBoxLayout *speedTestLayout = new QHBoxLayout();
        speedTestButton = new QPushButton("🚀 Run Speed Test");
        speedTestButton->setStyleSheet("padding: 10px; font-weight: bold; background-color: #e67e22; color: white; border-radius: 5px;");
        speedTestResultLabel = new QLabel("Last Test: N/A");
        speedTestResultLabel->setStyleSheet("font-size: 14px; color: #7f8c8d; font-style: italic;");
        speedTestLayout->addWidget(speedTestButton);
        speedTestLayout->addWidget(speedTestResultLabel);
        layout->addLayout(speedTestLayout);
        
        connect(speedTestButton, &QPushButton::clicked, this, &MainWindow::runSpeedTest);

        // Protocol Stats
        statsLabel = new QLabel("Protocols: TCP: 0% | UDP: 0% | DNS: 0% | ICMP: 0%");
        statsLabel->setStyleSheet("font-size: 14px; color: #2c3e50; font-weight: bold; margin-top: 5px;");
        layout->addWidget(statsLabel);

        // Packet Table
        packetTable = new QTableWidget(0, 5);
        packetTable->setHorizontalHeaderLabels({"Protocol", "Source IP", "Destination IP", "Location", "Size"});
        packetTable->horizontalHeader()->setSectionResizeMode(QHeaderView::Stretch);
        packetTable->setAlternatingRowColors(true);
        layout->addWidget(packetTable);

        setCentralWidget(central);

        updateTimer = new QTimer(this);
        connect(updateTimer, &QTimer::timeout, this, &MainWindow::updateUI);
        updateTimer->start(1000);

        startWorkers();
    }

private slots:
    void runSpeedTest() {
        speedTestButton->setEnabled(false);
        speedTestButton->setText("⌛ Testing...");
        speedTestResultLabel->setText("Running official speed test (this may take 30s)...");

        QProcess *process = new QProcess(this);
        connect(process, QOverload<int, QProcess::ExitStatus>::of(&QProcess::finished), 
            [this, process](int exitCode, QProcess::ExitStatus exitStatus){
                if (exitCode == 0) {
                    QString output = process->readAllStandardOutput();
                    QJsonDocument doc = QJsonDocument::fromJson(output.toUtf8());
                    QJsonObject obj = doc.object();
                    double down = obj["download"].toDouble() / 1000000.0;
                    double up = obj["upload"].toDouble() / 1000000.0;
                    double ping = obj["ping"].toDouble();
                    
                    speedTestResultLabel->setText(QString("✅ Result: DL: %1 Mbps | UL: %2 Mbps | Ping: %3 ms")
                        .arg(down, 0, 'f', 2).arg(up, 0, 'f', 2).arg(ping, 0, 'f', 1));
                } else {
                    speedTestResultLabel->setText("❌ Speed test failed. Try again.");
                }
                speedTestButton->setEnabled(true);
                speedTestButton->setText("🚀 Run Speed Test");
                process->deleteLater();
        });
        process->start("speedtest-cli", QStringList() << "--json");
    }

    void updateUI() {
        lock_guard<mutex> lock(shared_info.mtx);
        
        speedLabel->setText(QString("⬇ %1 Mbps  |  ⬆ %2 Mbps  |  Latency: %3 ms")
                            .arg(shared_info.down_speed, 0, 'f', 2)
                            .arg(shared_info.up_speed, 0, 'f', 2)
                            .arg(shared_info.latency_ms, 0, 'f', 2));

        long long total = 0;
        for (auto const& [p, count] : shared_info.proto_stats) total += count;
        if (total > 0) {
            auto getP = [&](string n) { return (shared_info.proto_stats[n] * 100.0) / total; };
            statsLabel->setText(QString("Protocol Distribution: TCP: %1% | UDP: %2% | DNS: %3% | ICMP: %4%")
                                .arg(getP("TCP"), 0, 'f', 1)
                                .arg(getP("UDP"), 0, 'f', 1)
                                .arg(getP("DNS"), 0, 'f', 1)
                                .arg(getP("ICMP"), 0, 'f', 1));
        }

        vector<SharedData::PacketInfo> sortedPackets = shared_info.packets;
        sort(sortedPackets.begin(), sortedPackets.end(), [](const SharedData::PacketInfo& a, const SharedData::PacketInfo& b) {
            return a.size > b.size;
        });

        packetTable->setRowCount(0);
        int displayCount = qMin((int)sortedPackets.size(), 5);
        for (int i = 0; i < displayCount; ++i) {
            const auto& p = sortedPackets[i];
            int row = packetTable->rowCount();
            packetTable->insertRow(row);
            
            QTableWidgetItem *protoItem = new QTableWidgetItem(p.protocol.c_str());
            QTableWidgetItem *srcItem = new QTableWidgetItem(p.src.c_str());
            QTableWidgetItem *dstItem = new QTableWidgetItem(p.dst.c_str());
            QTableWidgetItem *locItem = new QTableWidgetItem(p.location.c_str());
            QTableWidgetItem *sizeItem = new QTableWidgetItem(QString::number(p.size));

            if (p.is_malicious) {
                QColor dangerColor(255, 200, 200);
                protoItem->setBackground(dangerColor);
                srcItem->setBackground(dangerColor);
                dstItem->setBackground(dangerColor);
                dstItem->setText(dstItem->text() + " [⚠ BLACKLIST]");
            }

            packetTable->setItem(row, 0, protoItem);
            packetTable->setItem(row, 1, srcItem);
            packetTable->setItem(row, 2, dstItem);
            packetTable->setItem(row, 3, locItem);
            packetTable->setItem(row, 4, sizeItem);
        }
    }

    void startWorkers() {
        QThread *t1 = new QThread, *t2 = new QThread, *t3 = new QThread;
        NetworkWorker *w1 = new NetworkWorker, *w2 = new NetworkWorker, *w3 = new NetworkWorker;

        w1->loadBlacklist();

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
