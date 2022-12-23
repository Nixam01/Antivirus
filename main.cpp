//
// Created by nixam on 2.05.22.
//
#include <iostream>
#include <filesystem>
#include <string>
#include <vector>
#include <iomanip>
#include <typeinfo>
#include <algorithm>
#include <utility>
#include <fstream>
#include <openssl/sha.h>
#include <unistd.h>

using namespace std;

/*todo czesc zaawansowana:
    -dzialanie w tle
    -wielowatkowosc
    -aplikacja nie powinna obciazac systemu niewspolmiernie do wykonywanej pracy
*/
void options();
int fileLength(const char *filename);
bool getFileContent(const std::string &filename);
void unquarantine(const std::string &filename);
void removefromquarantinefile(const std::string &filename);
int recursiveScan(const string &pathToFolder, const vector<string> &vec);
int recursiveScanAll(const string &pathToFolder, const vector<string> &vec);
void print_list();
int scan(const char *const path, vector<string> vector);
bool is_root();
void quarantine(const string &filePath);
string file_perms(filesystem::perms p);
void removeFileFromOS(const string &filename);
void deleteFilenameQuarantine(const string &filename);
void addHashtoBase(const string &filename, const string& hash);



using namespace std;

vector<string> file_hash_vector(fileLength("database.txt"));
string projectPath = filesystem::current_path().remove_filename();

int main(){
    getFileContent(projectPath + "database.txt");
    bool end = false;
    do{
        cout << endl;
        options();

        int n;
        cin >> n;
        switch (n) {
            case 1: {
                string path;
                cout << "Enter the path to the file you want to scan." << endl;
                cin >> path;
                cout << endl;
                scan(path.c_str(), file_hash_vector);
                break;

            }

            case 2: {
                print_list();
                break;

            }
            case 3: {
                if (!is_root()) {
                    cout << "You don't have root privileges. \n"
                            "Use \"sudo\" in order to continue this action." << endl;
                    break;
                }

                string filename;
                cout << "Enter the file name to unquarantine." << endl;
                cin >> filename;
                cout << endl;
                unquarantine(filename);
                break;
            }
            case 4: {
                string dir;
                cout << "Enter the path to the folder you want to scan." << endl;
                cin >> dir;
                cout << endl;
                if (dir != "/")
                    recursiveScan(dir, file_hash_vector);
                else
                    recursiveScanAll(dir, file_hash_vector);
                break;
            }
            case 5: {
                if (!is_root()) {
                    cout << "You don't have root privileges. \n"
                            "Use \"sudo\" in order to continue this action." << endl;
                    break;
                }
                string filename;
                char yes_no;
                cout << "Enter the file name (with its extension) that you want to remove from OS." << endl;
                cin >> filename;
                cout << endl;
                cout << "Are you sure you want to delete this file?\nYou cannot undo this operation [Y/N]." << endl;
                do {
                    cin >> yes_no;
                    if (tolower(yes_no) == 'y') {
                        removeFileFromOS(filename);
                        break;
                    } else if (tolower(yes_no) == 'n') {
                        cout << "Removing has been cancelled." << endl;
                        break;
                    }
                    cout << "Wrong input. Choose correct option [Y/N]." << endl;
                } while (tolower(yes_no) != 'y' && tolower(yes_no) != 'n');

                break;
            }
            case 6: {
                string filename;
                cout << "Enter the file name which perms you want to show." << endl;
                cin >> filename;
                cout << endl << file_perms(filesystem::status(filename).permissions());
                cout << getuid();
                break;
            }
            case 7: {
                string hash;
                cout << "Enter the hash you want to add to database." << endl;
                cin >> hash;
                addHashtoBase(projectPath + "database.txt", hash);
                break;
            }
            case 0: {
                end = true;
                break;
            }
            default: {
                options();
                break;
            }

        }
    }while(end==false);
    return 0;
}

void options() {

    cout << "Choose what you want to do:" << endl
         << " [1] Scan specified file" << endl
         << " [2] List all quarantine files" << endl
         << " [3] Restore file from quarantine" << endl
         << " [4] Recursive scan from specified folder" << endl
         << " [5] Remove file from the System" << endl
         << " [6] Show the type of specified file" << endl
         << " [7] Add Hash to the database" << endl
         << " [0] EXIT" << endl
         << endl;
}

bool is_root() {

    if (getuid() == 0)
        return true;
    else
        return false;
}

int fileLength(const char *filename) {

    int counter = 0;
    fstream fs(filename);
    string line;

    while (getline(fs, line))
        counter++;

    fs.close();
    return counter;
}

bool getFileContent(const string &filename) {

    fstream fs(filename);
    if (!fs) {
        cerr << "Cannot open the file" << filename << endl;
        return false;
    }

    string line;
    while (getline(fs, line))
        file_hash_vector.push_back(line);

    fs.close();
    return true;
}

string SHA(const char *const path) {
    ifstream fp(path, ios::in | ios::binary);

    constexpr const std::size_t buffer_size{1 << 12};
    char buffer[buffer_size];

    unsigned char digest[SHA256_DIGEST_LENGTH] = {0};

    SHA256_CTX ctx;
    SHA256_Init(&ctx);

    while (fp.good()) {
        fp.read(buffer, buffer_size);
        SHA256_Update(&ctx, buffer, fp.gcount());
    }

    SHA256_Final(digest, &ctx);
    fp.close();

    std::ostringstream os;
    os << std::hex << std::setfill('0');

    for (unsigned char i: digest) {
        os << std::setw(2) << static_cast<unsigned int>(i);
    }

    return os.str();
}
bool checkHash(const string &fileHash, vector<string> vec) {

    if (std::find(vec.begin(), vec.end(), fileHash) != vec.end())
        return true;
    else
        return false;
}

int scan(const char *const path, vector<string> vector) {
    if (!filesystem::exists(path))
        cout << "There is no such path." << endl;
    else {
        if (filesystem::is_regular_file(filesystem::status(path))) {

            if (checkHash(SHA(path), std::move(vector))) {

                quarantine(path);

                cout << path << " is a virus." << endl;
            } else
                cout << "No viruses found." << endl;
        }
    }
    return 0;

}

void quarantine(const string &filePath) {

    string newPath;

    ifstream ifs(filePath, ios::in | ios::binary);
    newPath += projectPath + "quarantine/" + filesystem::path(filePath).filename().string();
    ofstream ofs(newPath, ios::out | ios::binary);
    ofs << ifs.rdbuf();
    remove(filePath.c_str());

    filesystem::permissions(newPath, filesystem::perms::none);
    std::ostringstream tmp;
    tmp << filePath << endl;
    ofstream saveFile;
    saveFile.open(projectPath + "quarantine/files_on_quarantine.txt", std::ios::app);
    saveFile << tmp.str();
    saveFile.close();
}


void print_list()
{
    string filename = projectPath + "quarantine/files_on_quarantine.txt";
    filesystem::permissions(filename, filesystem::perms::all);
    fstream fs(filename.c_str());


    if (!filesystem::exists(filename)) {
        cout << "There is no such file" << endl;
    }

    string line;
    int i = 0;
    cout << "Files on quarantine: " << endl << endl;
    while (getline(fs, line)) {
        cout << ++i << ". " << filesystem::path(line).filename() << endl;
    }

    fs.close();
}
void removeFileFromOS(const string &filename) {
    string filePath;
    filePath += projectPath + "quarantine/" + filename;

    if (filesystem::exists(filePath)) {
        filesystem::permissions(filePath, filesystem::perms::all);
        deleteFilenameQuarantine(filename);
        remove(filePath.c_str());
        cout << "File successfully removed from OS." << endl;
    } else
        cout << "There is no such file in quarantine directory." << endl;
}
void deleteFilenameQuarantine(const string &filename) {

    string q_file = projectPath + "quarantine/files_on_quarantine.txt";
    string q_file_temp = projectPath + "quarantine/files_on_quarantine_temp.txt";

    string line;
    ifstream in(q_file);
    if (!in.is_open()) {
        cout << "Input file failed to open.\n" << endl;
    }
    ofstream out(q_file_temp);

    string filenameFromLine;
    while (getline(in, line)) {
        filenameFromLine = filesystem::path(line).filename().string();
        if (filename != filenameFromLine)
            out << line << "\n";
    }
    in.close();
    out.close();

    remove(q_file.c_str());
    rename(q_file_temp.c_str(), q_file.c_str());
}

void unquarantine(const string &filename) {
    string filePath;
    string oldFilePath;
    filePath += projectPath + "quarantine/" + filename;

    string q_file = projectPath + "quarantine/files_on_quarantine.txt";
    string line;
    string filenameFromLine;
    ifstream in(q_file);
    while (getline(in, line)) {
        filenameFromLine = filesystem::path(line).filename().string();
        if (filename == filenameFromLine) {
            oldFilePath = line;
            break;
        }
    }
    in.close();

    if (filesystem::exists(filePath)) {

        removefromquarantinefile(filename);
        filesystem::permissions(filePath, filesystem::perms::owner_read | filesystem::perms::owner_write |
                                          filesystem::perms::group_read | filesystem::perms::others_read);

        ifstream ifs(filePath, ios::in | ios::binary);
        ofstream ofs(oldFilePath, ios::out | ios::binary);
        ofs << ifs.rdbuf();
        remove(filePath.c_str());

        cout << "File successfully removed from quarantine and moved to previous localisation." << endl;
    } else
        cout << "There is no such file in quarantine directory " << endl;
}
void removefromquarantinefile(const string &filename) {

    string q_file = projectPath + "quarantine/files_on_quarantine.txt";
    string q_file_temp = projectPath + "quarantine/files_on_quarantine_temp.txt";

    string line;
    ifstream in(q_file);
    if (!in.is_open()) {
        cout << "Input file failed to open.\n" << endl;
    }
    ofstream out(q_file_temp);

    string filenameFromLine;
    while (getline(in, line)) {
        filenameFromLine = filesystem::path(line).filename().string();
        if (filename != filenameFromLine)
            out << line << "\n";
    }
    in.close();
    out.close();

    remove(q_file.c_str());
    rename(q_file_temp.c_str(), q_file.c_str());
}

int recursiveScan(const string &pathToFolder, const vector<string> &vec) {

    long regular_files_counter = 0;
    long dir_counter = 0;
    long block_files_counter = 0;
    long character_files_counter = 0;
    long fifo_counter = 0;
    long socket_counter = 0;
    long symlink_counter = 0;
    long virus_counter = 0;

    try {
        for (auto const &dir_entry: filesystem::recursive_directory_iterator(pathToFolder,
                                                                             filesystem::directory_options::skip_permission_denied)) {
            string full_path = dir_entry.path();

            cout << full_path << endl;
            if(filesystem::is_block_file(full_path)) block_files_counter++;
            else if(filesystem::is_character_file(full_path)) character_files_counter++;
            else if(filesystem::is_fifo(full_path)) fifo_counter++;
            else if(filesystem::is_socket(full_path)) socket_counter++;
            else if(filesystem::is_symlink(full_path)) symlink_counter++;
            else if (filesystem::is_regular_file(filesystem::status(dir_entry))) {

                if (checkHash(SHA(full_path.c_str()), vec))
                {
                    quarantine(full_path);
                    virus_counter++;
                }
                regular_files_counter++;
            }
            else if(filesystem::is_directory(full_path)) dir_counter++;

        }
    }
    catch (const std::filesystem::__cxx11::filesystem_error::runtime_error &) {
    }

    cout << "Regular files scanned:         " << regular_files_counter << endl;
    cout << "Directories scanned:           " << dir_counter << endl;
    cout << "Block files:                   " << block_files_counter << endl;
    cout << "Character files:               " << character_files_counter << endl;
    cout << "Fifo files:                    " << fifo_counter << endl;
    cout << "Sockets:                       " << socket_counter << endl;
    cout << "Symlinks:                      " << symlink_counter << endl;
    cout << "Suspicious files (moved to quarantine): " << virus_counter << endl;

    return 1;
}
int recursiveScanAll(const string &pathToFolder, const vector<string> &vec) {

    long regular_files_counter = 0;
    long dir_counter = 0;
    long block_files_counter = 0;
    long character_files_counter = 0;
    long fifo_counter = 0;
    long socket_counter = 0;
    long symlink_counter = 0;
    long virus_counter = 0;

    for (auto const& dir1_entry : filesystem::directory_iterator(pathToFolder))
    {
        try {
            for (auto const &dir_entry: filesystem::recursive_directory_iterator(dir1_entry,
                                                                                 filesystem::directory_options::skip_permission_denied)) {
                string full_path = dir_entry.path();

                if(filesystem::is_block_file(full_path)) block_files_counter++;
                else if(filesystem::is_character_file(full_path)) character_files_counter++;
                else if(filesystem::is_fifo(full_path)) fifo_counter++;
                else if(filesystem::is_socket(full_path)) socket_counter++;
                else if(filesystem::is_symlink(full_path)) symlink_counter++;
                else if (filesystem::is_regular_file(filesystem::status(dir_entry))) {

                    if (checkHash(SHA(full_path.c_str()), vec))
                    {
                        quarantine(full_path);
                        virus_counter++;
                    }
                    regular_files_counter++;
                }
                else if(filesystem::is_directory(full_path)) dir_counter++;

            }
        }
        catch (const std::filesystem::__cxx11::filesystem_error::runtime_error &) {
        }
    }

    cout << "Regular files scanned:         " << regular_files_counter << endl;
    cout << "Directories scanned:           " << dir_counter << endl;
    cout << "Block files:                   " << block_files_counter << endl;
    cout << "Character files:               " << character_files_counter << endl;
    cout << "Fifo files:                    " << fifo_counter << endl;
    cout << "Sockets:                       " << socket_counter << endl;
    cout << "Symlinks:                      " << symlink_counter << endl;
    cout << "Suspicious files (moved to quarantine): " << virus_counter << endl;

    return 1;
}

string file_perms(filesystem::perms p)
{
    string file_perm;
    file_perm += ((p & filesystem::perms::owner_read) != filesystem::perms::none ? "read" : "-");
    file_perm += ((p & filesystem::perms::owner_write) != filesystem::perms::none ? "write" : "-");
    file_perm += ((p & filesystem::perms::owner_exec) != filesystem::perms::none ? "executable" : "-");
    file_perm += ((p & filesystem::perms::group_read) != filesystem::perms::none ? "gread" : "-");
    file_perm += ((p & filesystem::perms::group_write) != filesystem::perms::none ? "gwrite" : "-");
    file_perm += ((p & filesystem::perms::group_exec) != filesystem::perms::none ? "gexecutable" : "-");
    file_perm += ((p & filesystem::perms::others_read) != filesystem::perms::none ? "oread" : "-");
    file_perm += ((p & filesystem::perms::others_write) != filesystem::perms::none ? "owrite" : "-");
    file_perm += ((p & filesystem::perms::others_exec) != filesystem::perms::none ? "oexecutable" : "-");

    return file_perm;
}
void addHashtoBase(const string &filename, const string& hash) {

    fstream fs;
    fs.open(filename, std::fstream::in | std::fstream::out | std::ofstream::app);
    fs << endl << hash;
    fs.close();
    file_hash_vector.push_back(hash);
}







