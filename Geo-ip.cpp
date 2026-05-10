#include <maxminddb.h>
#include <iostream>

using namespace std;

string get_country(string ip_str) {
    int gai_error, mmdb_error;
    MMDB_s mmdb;
    mmdb_error = MMDB_open("GeoLite2-Country.mmdb" , MMDB_MODE_MMAP, &mmdb);
    
    MMDB_lookup_result_s result = MMDB_lookup_string(&mmdb, ip_str.c_str(), &gai_error, &mmdb_error);
    
    if (result.found_entry) {
        MMDB_entry_data_s entry_data;
        MMDB_get_value(&result.entry, &entry_data, "country", "names", "en", NULL);
        if (entry_data.has_data) {
            return string(entry_data.utf8_string, entry_data.data_size);
        }
    }
    return "Unknown";
}

int main(){
    string ip;
    while(true){
        cin >> ip;
        cout << get_country(ip) << endl;
    }
    return 0;
}
