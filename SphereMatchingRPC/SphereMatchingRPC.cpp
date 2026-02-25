#include <windows.h>
#include <TlHelp32.h>
#include <shellapi.h>
#include <vector>
#include <string>
#include <thread>
#include <mutex>
#include <chrono>
#include <cstdint> 
#include <psapi.h>
#include <sstream>
#include <algorithm>
#include <map>

#include "resource.h" 
#ifndef IDI_ICON1
#define IDI_ICON1 101 
#endif

#define DISCORDPP_IMPLEMENTATION
#include "discordpp.h"

#define WM_TRAYICON (WM_USER + 1)
constexpr auto ID_TRAY_APP_ICON = 1001;
constexpr auto ID_TRAY_EXIT = 1002;

#define APPLICATION_ID 1234567890

HWND g_hWnd = NULL;
NOTIFYICONDATA g_nid = {};
std::wstring g_luxorPath = L"Waiting for Luxor to launch...";
std::wstring g_statusText = L"Status: Searching for process...";
std::mutex g_dataMutex;


uintptr_t g_hookLocation = 0;
uintptr_t g_codeCave = 0;
uintptr_t g_lastStringPtrAddr = 0;
bool g_isHooked = false;

// Game Data
std::string g_persistentMapName = "In Menus";
int g_lastScore = 0;
int g_lastCoins = 0;
int g_currentLevel = 1;
int g_currentStage = 1;

enum class GameVersion
{
    Unknown,
    Luxor1_Std, // Steam / GH
    Luxor1_BFG, // BFG
    Amun_Std,   // Steam / GH
    Amun_BFG    // BFG
};

GameVersion g_currentGameVersion = GameVersion::Unknown;

// OFFSETS
const uintptr_t OFFSET_LUXOR1_STD = 0x289D8;
const uintptr_t OFFSET_LUXOR1_BFG = 0x29AC8;
const uintptr_t OFFSET_AMUN_STD = 0x2B4E8;
const uintptr_t OFFSET_AMUN_BFG = 0x2F5E8;

struct ProcessInfo 
{
    DWORD id;
    std::wstring name;
    std::string windowTitle;
    GameVersion version;
};

struct EnumData 
{
    DWORD pid;
    std::string title;
};

const std::vector<const wchar_t*> POSSIBLE_PROCESS_NAMES = {
    L"game_dec.dmg",        // Steam (Wrapper Engine)
    L"Luxor AR.exe",        // Amun Rising (Steam)
    L"luxor ar.exe",        // Amun Rising (Big Fish Games)
    L"LuxorAmun.exe",       // Amun Rising (GH)
    L"Luxor.exe",           // Luxor 1 (GH)
    L"luxor.exe"            // Luxor 1 (Big Fish Games)
};

GameVersion IdentifyVersion(const std::string& title)
{
    // --- LUXOR 1 ---
    if (title == "Luxor 1.0.5.34 GH") return GameVersion::Luxor1_Std;
    if (title == "Luxor 1.0.5.34 S")  return GameVersion::Luxor1_Std;
    if (title == "Luxor 1.0.5.36 SBA") return GameVersion::Luxor1_BFG;

    // --- AMUN RISING ---
    if (title == "Luxor: Amun Rising 1.5.5.9 G")  return GameVersion::Amun_Std;
    if (title == "Luxor: Amun Rising 1.5.5.8 GH") return GameVersion::Amun_Std;
    if (title == "Luxor: Amun Rising 1.5.5.9 SBA") return GameVersion::Amun_BFG;

    return GameVersion::Unknown;
}

BOOL CALLBACK EnumWindowsProc(HWND hwnd, LPARAM lParam)
{
    EnumData* data = (EnumData*)lParam;
    DWORD procId = 0;
    GetWindowThreadProcessId(hwnd, &procId);

    if (procId == data->pid)
    {
        if (IsWindowVisible(hwnd))
        {
            char titleBuf[256];
            GetWindowTextA(hwnd, titleBuf, sizeof(titleBuf));
            if (strlen(titleBuf) > 0) 
            {
                data->title = titleBuf;
                return FALSE;
            }
        }
    }
    return TRUE;
}

ProcessInfo GetTargetProcess() 
{
    HANDLE hSnap = CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, 0);
    if (hSnap == INVALID_HANDLE_VALUE) return { 0, L"", "", GameVersion::Unknown };

    PROCESSENTRY32W procEntry;
    procEntry.dwSize = sizeof(procEntry);

    ProcessInfo bestMatch = { 0, L"", "", GameVersion::Unknown };

    if (Process32FirstW(hSnap, &procEntry)) 
    {
        do {
            bool isKnownProcess = false;
            for (const auto& procName : POSSIBLE_PROCESS_NAMES) 
            {
                if (!_wcsicmp(procEntry.szExeFile, procName))
                {
                    isKnownProcess = true;
                    break;
                }
            }

            if (isKnownProcess)
            {
                // Get Window Title to identify Version
                EnumData wndData = { procEntry.th32ProcessID, "" };
                EnumWindows(EnumWindowsProc, (LPARAM)&wndData);

                GameVersion ver = GameVersion::Unknown;

                // Try Exact Title Match first
                if (!wndData.title.empty())
                {
                    ver = IdentifyVersion(wndData.title);
                }

                // Fallback: If title unknown, guess based on EXE name
                if (ver == GameVersion::Unknown)
                    if (!_wcsicmp(procEntry.szExeFile, L"LuxorAmun.exe")) ver = GameVersion::Amun_Std;

                // If we found game_dec.dmg, this is the steam engine
                if (!_wcsicmp(procEntry.szExeFile, L"game_dec.dmg")) 
                {
                    bestMatch = { procEntry.th32ProcessID, procEntry.szExeFile, wndData.title, ver };
                    // If we identified the version via title, stop scanning.
                    if (ver != GameVersion::Unknown) break;
                }

                // If this is a Launcher/Executable, store it as a candidate.
                // We keep looping in case we find game_dec.dmg later.
                if (bestMatch.id == 0 || ver != GameVersion::Unknown)
                    bestMatch = { procEntry.th32ProcessID, procEntry.szExeFile, wndData.title, ver };
            }

        } while (Process32NextW(hSnap, &procEntry));
    }
    CloseHandle(hSnap);
    return bestMatch;
}

uintptr_t GetModuleBaseAddress(HANDLE hProc, const wchar_t* modName)
{
    HMODULE hMods[1024];
    DWORD cbNeeded;
    if (EnumProcessModulesEx(hProc, hMods, sizeof(hMods), &cbNeeded, LIST_MODULES_32BIT | LIST_MODULES_64BIT))
    {
        for (unsigned int i = 0; i < (cbNeeded / sizeof(HMODULE)); i++)
        {
            wchar_t szModName[MAX_PATH];
            if (GetModuleBaseNameW(hProc, hMods[i], szModName, sizeof(szModName) / sizeof(wchar_t))) 
            {
                if (!_wcsicmp(szModName, modName))
                {
                    MODULEINFO modInfo;
                    GetModuleInformation(hProc, hMods[i], &modInfo, sizeof(modInfo));
                    return (uintptr_t)modInfo.lpBaseOfDll;
                }
            }
        }
    }
    return 0;
}

uintptr_t FindPattern(HANDLE hProc, const unsigned char* pattern, const char* mask)
{
    SYSTEM_INFO sysInfo;
    GetSystemInfo(&sysInfo);
    uintptr_t currentAddr = (uintptr_t)sysInfo.lpMinimumApplicationAddress;
    uintptr_t maxAddr = (uintptr_t)sysInfo.lpMaximumApplicationAddress;
    size_t patternLen = strlen(mask);

    MEMORY_BASIC_INFORMATION mbi;
    while (currentAddr < maxAddr && VirtualQueryEx(hProc, (LPCVOID)currentAddr, &mbi, sizeof(mbi)))
    {
        if (mbi.State == MEM_COMMIT && (mbi.Protect & PAGE_EXECUTE_READ || mbi.Protect & PAGE_EXECUTE_READWRITE || mbi.Protect & PAGE_READWRITE)) 
        {
            std::vector<unsigned char> buffer(mbi.RegionSize);
            SIZE_T bytesRead;
            if (ReadProcessMemory(hProc, mbi.BaseAddress, buffer.data(), mbi.RegionSize, &bytesRead)) 
            {
                for (size_t i = 0; i < bytesRead - patternLen; i++) {
                    bool found = true;
                    for (size_t j = 0; j < patternLen; j++) {
                        if (mask[j] != '?' && buffer[i + j] != pattern[j]) 
                        {
                            found = false;
                            break;
                        }
                    }
                    if (found) return currentAddr + i;
                }
            }
        }
        currentAddr += mbi.RegionSize;
    }
    return 0;
}

void InjectMapHook(HANDLE hProcess, uintptr_t basePtr)
{
    if (g_isHooked) return;

    // Pattern V1: Steam/Wrapper (Offset 0x1A4)
    const unsigned char patternV1[] = { 0x88, 0x9E, 0xA4, 0x01, 0x00, 0x00 };
    // Pattern V2: LuxorAmun.exe / BFG (Offset 0x1A0)
    const unsigned char patternV2[] = { 0x88, 0x9E, 0xA0, 0x01, 0x00, 0x00 };
    const char* mask = "xxxxxx";

    unsigned char targetOffsetByte = 0xA4;
    uintptr_t scanResult = FindPattern(hProcess, patternV1, mask);

    if (scanResult == 0) 
    {
        scanResult = FindPattern(hProcess, patternV2, mask);
        targetOffsetByte = 0xA0;
    }

    if (scanResult != 0) 
    {
        g_hookLocation = scanResult;
        g_codeCave = (uintptr_t)VirtualAllocEx(hProcess, nullptr, 128, MEM_COMMIT | MEM_RESERVE, PAGE_EXECUTE_READWRITE);
        if (g_codeCave == 0) return;

        g_lastStringPtrAddr = g_codeCave + 100;

        std::vector<unsigned char> caveBytes;
        caveBytes.push_back(0x50); // push eax
        caveBytes.push_back(0x9C); // pushfd 

        // lea eax, [esi+OFFSET]
        caveBytes.push_back(0x8D); caveBytes.push_back(0x86);
        caveBytes.push_back(targetOffsetByte); caveBytes.push_back(0x01); caveBytes.push_back(0x00); caveBytes.push_back(0x00);

        // mov dword ptr [LastStringPtr], eax
        caveBytes.push_back(0x89); caveBytes.push_back(0x05);
        uint32_t varAddr = (uint32_t)g_lastStringPtrAddr;
        caveBytes.insert(caveBytes.end(), (unsigned char*)&varAddr, (unsigned char*)&varAddr + 4);

        caveBytes.push_back(0x9D); // popfd
        caveBytes.push_back(0x58); // pop eax

        // Original Code
        caveBytes.push_back(0x88); caveBytes.push_back(0x9E);
        caveBytes.push_back(targetOffsetByte); caveBytes.push_back(0x01); caveBytes.push_back(0x00); caveBytes.push_back(0x00);

        // JMP Back
        caveBytes.push_back(0xE9);
        uintptr_t currentCavePos = g_codeCave + caveBytes.size();
        uintptr_t returnLoc = g_hookLocation + 6;
        uint32_t relativeJump = (uint32_t)(returnLoc - (currentCavePos + 4));
        caveBytes.insert(caveBytes.end(), (unsigned char*)&relativeJump, (unsigned char*)&relativeJump + 4);

        WriteProcessMemory(hProcess, (LPVOID)g_codeCave, caveBytes.data(), caveBytes.size(), nullptr);

        unsigned char hookBytes[6];
        hookBytes[0] = 0xE9;
        uint32_t relativeHook = (uint32_t)(g_codeCave - (g_hookLocation + 5));
        memcpy(&hookBytes[1], &relativeHook, 4);
        hookBytes[5] = 0x90; // NOP

        WriteProcessMemory(hProcess, (LPVOID)g_hookLocation, hookBytes, 6, nullptr);

        g_isHooked = true;
        std::lock_guard<std::mutex> lock(g_dataMutex);
        g_statusText = L"Status: Universal UI Hook Injected!";
        InvalidateRect(g_hWnd, NULL, TRUE);
        return;
    }

    // Reconnection logic remains implicit via AOB scan failure if modified
    std::lock_guard<std::mutex> lock(g_dataMutex);
    g_statusText = L"Status: Hook Pattern scan pending...";
    InvalidateRect(g_hWnd, NULL, TRUE);
}

void MemoryReaderThread()
{
    auto client = std::make_shared<discordpp::Client>();
    client->SetApplicationId(APPLICATION_ID);

    bool gameRunning = false;
    HANDLE hProcess = NULL;
    std::wstring currentProcName = L"";
    uintptr_t cachedBasePtr = 0;

    std::string lastSentMap = "";
    int lastSentScore = -1;
    int lastSentCoins = -1;
    int lastSentLevel = -1;
    int lastSentStage = -1;

    auto lastMemoryRead = std::chrono::steady_clock::now();
    auto timeProcessFound = std::chrono::steady_clock::now();

    while (true)
    {
        discordpp::RunCallbacks();

        auto now = std::chrono::steady_clock::now();
        auto msPassed = std::chrono::duration_cast<std::chrono::milliseconds>(now - lastMemoryRead).count();

        if (msPassed >= 2000)
        {
            lastMemoryRead = now;

            ProcessInfo pInfo = GetTargetProcess();
            DWORD procId = pInfo.id;

            if (!procId) 
            {
                if (gameRunning)
                {
                    g_isHooked = false;
                    gameRunning = false;
                    g_currentGameVersion = GameVersion::Unknown;
                    cachedBasePtr = 0;
                    if (hProcess) CloseHandle(hProcess);
                    hProcess = NULL;

                    g_persistentMapName = "In Menus";
                    g_lastScore = 0;
                    g_lastCoins = 0;
                    g_currentLevel = 1;
                    g_currentStage = 1;

                    std::lock_guard<std::mutex> lock(g_dataMutex);
                    g_statusText = L"Status: Waiting for game...";
                    g_luxorPath = L"Waiting for Luxor to launch...";
                    InvalidateRect(g_hWnd, NULL, TRUE);

                    discordpp::Activity emptyActivity;
                    client->UpdateRichPresence(emptyActivity, [](const discordpp::ClientResult& result) {});
                }
            }
            else 
            {
                if (!gameRunning) 
                {
                    gameRunning = true;
                    currentProcName = pInfo.name;
                    g_currentGameVersion = pInfo.version;
                    timeProcessFound = std::chrono::steady_clock::now();

                    hProcess = OpenProcess(PROCESS_VM_READ | PROCESS_VM_WRITE | PROCESS_VM_OPERATION | PROCESS_QUERY_INFORMATION, FALSE, procId);

                    std::lock_guard<std::mutex> lock(g_dataMutex);
                    if (hProcess)
                    {
                        wchar_t exePath[MAX_PATH];
                        DWORD pathSize = MAX_PATH;
                        if (QueryFullProcessImageNameW(hProcess, 0, exePath, &pathSize))
                        {
                            g_luxorPath = exePath;
                        }
                        else 
                        {
                            g_luxorPath = currentProcName;
                        }
                    }
                    g_statusText = L"Status: Game found! Waiting for safety delay...";
                    InvalidateRect(g_hWnd, NULL, TRUE);
                }

                auto loadTime = std::chrono::duration_cast<std::chrono::seconds>(now - timeProcessFound).count();

                if (hProcess && cachedBasePtr == 0)
                {
                    cachedBasePtr = GetModuleBaseAddress(hProcess, L"game_dec.dmg");
                    if (cachedBasePtr == 0) 
                        cachedBasePtr = GetModuleBaseAddress(hProcess, currentProcName.c_str());
                }

                if (hProcess && !g_isHooked && loadTime >= 5)
                    InjectMapHook(hProcess, cachedBasePtr);

                if (hProcess && g_isHooked && cachedBasePtr != 0)
                {
                    // 1. Read Map Name
                    uint32_t mapPtr = 0;
                    if (ReadProcessMemory(hProcess, (LPCVOID)g_lastStringPtrAddr, &mapPtr, 4, nullptr) && mapPtr != 0) 
                    {
                        char nameBuf[128] = { 0 };
                        if (ReadProcessMemory(hProcess, (LPCVOID)mapPtr, &nameBuf, 127, nullptr)) 
                        {
                            std::string rawName = nameBuf;
                            g_persistentMapName = rawName;
                        }
                    }

                    // 2. Read Game Stats
                    uintptr_t playerOffset = 0;

                    switch (g_currentGameVersion)
                    {
                    case GameVersion::Luxor1_Std: playerOffset = OFFSET_LUXOR1_STD; break;
                    case GameVersion::Luxor1_BFG: playerOffset = OFFSET_LUXOR1_BFG; break;
                    case GameVersion::Amun_BFG:   playerOffset = OFFSET_AMUN_BFG;   break;
                    default:                      playerOffset = OFFSET_AMUN_STD;   break; // Default to AR STD
                    }

                    uintptr_t scorePtr = cachedBasePtr + playerOffset;
                    uint32_t readPtr = 0;

                    if (ReadProcessMemory(hProcess, (LPCVOID)scorePtr, &readPtr, 4, nullptr) && readPtr != 0)
                    {
                        ReadProcessMemory(hProcess, (LPCVOID)(readPtr + 0x14), &g_lastScore, 4, nullptr);
                        ReadProcessMemory(hProcess, (LPCVOID)(readPtr + 0x20), &g_lastCoins, 4, nullptr);
                        ReadProcessMemory(hProcess, (LPCVOID)(readPtr + 0x10), &g_currentLevel, 4, nullptr);
                        ReadProcessMemory(hProcess, (LPCVOID)(readPtr + 0x0C), &g_currentStage, 4, nullptr);
                    }

                    if (g_persistentMapName != lastSentMap ||
                        g_lastScore != lastSentScore ||
                        g_lastCoins != lastSentCoins ||
                        g_currentLevel != lastSentLevel ||
                        g_currentStage != lastSentStage)
                    {
                        lastSentMap = g_persistentMapName;
                        lastSentScore = g_lastScore;
                        lastSentCoins = g_lastCoins;
                        lastSentLevel = g_currentLevel;
                        lastSentStage = g_currentStage;

                        discordpp::Activity activity;
                        discordpp::ActivityAssets assets;

                        activity.SetType(discordpp::ActivityTypes::Playing);

                        bool isLuxor1 = (g_currentGameVersion == GameVersion::Luxor1_Std || g_currentGameVersion == GameVersion::Luxor1_BFG);

                        if (isLuxor1)
                        {
                            activity.SetName("Luxor");
                            assets.SetLargeImage("luxor");
                            assets.SetLargeText("Luxor");
                        }
                        else 
                        {
                            activity.SetName("Luxor AR");
                            assets.SetLargeImage("luxorar");
                            assets.SetLargeText("Luxor Amun Rising");
                        }

                        //3. Display in Discord and UI

                        std::string detailsStr = "Stage " + std::to_string(g_currentStage) + " - " + std::to_string(g_currentLevel);
                        if (g_persistentMapName != "In Menus") 
                        {
                            detailsStr += " | " + g_persistentMapName;
                        }
                        activity.SetDetails(detailsStr);

                        std::string stateStr = "Score: " + std::to_string(g_lastScore) + " | Coins: " + std::to_string(g_lastCoins);
                        activity.SetState(stateStr);

                        activity.SetAssets(assets);
                        client->UpdateRichPresence(activity, [](const discordpp::ClientResult& result) {});

                        std::lock_guard<std::mutex> lock(g_dataMutex);
                        std::wstringstream ws;
                        ws << (isLuxor1 ? L"[Luxor 1] " : L"[Amun Rising] ")
                            << L"Map: " << std::wstring(g_persistentMapName.begin(), g_persistentMapName.end())
                            << L" | Score: " << g_lastScore << L" | Coins: " << g_lastCoins;

                        if (g_currentGameVersion == GameVersion::Unknown) 
                            ws << L" (Unknown Version)";

                        g_statusText = ws.str();
                        InvalidateRect(g_hWnd, NULL, TRUE);
                    }
                }
            }
        }
        std::this_thread::sleep_for(std::chrono::milliseconds(16));
    }
}

const COLORREF COL_BG = RGB(32, 34, 37);
const COLORREF COL_TEXT_HEADER = RGB(255, 255, 255);
const COLORREF COL_TEXT_BODY = RGB(185, 187, 190);
const COLORREF COL_ACCENT = RGB(88, 101, 242);

HFONT hFontTitle = NULL;
HFONT hFontBody = NULL;
HBRUSH hBrushBg = NULL;

void InitResources()
{
    if (!hFontTitle) 
    {
        hFontTitle = CreateFontW(28, 0, 0, 0, FW_SEMIBOLD, FALSE, FALSE, FALSE, DEFAULT_CHARSET,
            OUT_DEFAULT_PRECIS, CLIP_DEFAULT_PRECIS, CLEARTYPE_QUALITY,
            DEFAULT_PITCH | FF_SWISS, L"Segoe UI");
    }
    if (!hFontBody) 
    {
        hFontBody = CreateFontW(19, 0, 0, 0, FW_NORMAL, FALSE, FALSE, FALSE, DEFAULT_CHARSET,
            OUT_DEFAULT_PRECIS, CLIP_DEFAULT_PRECIS, CLEARTYPE_QUALITY,
            DEFAULT_PITCH | FF_SWISS, L"Segoe UI");
    }
    if (!hBrushBg) 
    {
        hBrushBg = CreateSolidBrush(COL_BG);
    }
}

LRESULT CALLBACK WndProc(HWND hWnd, UINT message, WPARAM wParam, LPARAM lParam) {
    switch (message)
    {
    case WM_CREATE:
        InitResources();
        memset(&g_nid, 0, sizeof(NOTIFYICONDATA));
        g_nid.cbSize = sizeof(NOTIFYICONDATA);
        g_nid.hWnd = hWnd;
        g_nid.uID = ID_TRAY_APP_ICON;
        g_nid.uFlags = NIF_ICON | NIF_MESSAGE | NIF_TIP;
        g_nid.uCallbackMessage = WM_TRAYICON;
        g_nid.hIcon = LoadIcon(GetModuleHandle(NULL), MAKEINTRESOURCE(IDI_ICON1));
        if (!g_nid.hIcon) g_nid.hIcon = LoadIcon(NULL, IDI_APPLICATION);
        wcscpy_s(g_nid.szTip, L"Luxor Discord RPC");
        Shell_NotifyIcon(NIM_ADD, &g_nid);
        break;

    case WM_TRAYICON:
        if (lParam == WM_LBUTTONUP)
        {
            ShowWindow(hWnd, SW_RESTORE);
            SetForegroundWindow(hWnd);
        }
        else if (lParam == WM_RBUTTONUP)
        {
            POINT pt;
            GetCursorPos(&pt);
            HMENU hMenu = CreatePopupMenu();
            AppendMenu(hMenu, MF_STRING, ID_TRAY_EXIT, L"Exit Luxor RPC");
            SetForegroundWindow(hWnd);
            TrackPopupMenu(hMenu, TPM_BOTTOMALIGN | TPM_LEFTALIGN, pt.x, pt.y, 0, hWnd, NULL);
            DestroyMenu(hMenu);
        }
        break;

    case WM_COMMAND:
        if (LOWORD(wParam) == ID_TRAY_EXIT)
        {
            DestroyWindow(hWnd);
        }
        break;

    case WM_ERASEBKGND:
        return 1;

    case WM_PAINT:
    {
        PAINTSTRUCT ps;
        HDC hdc = BeginPaint(hWnd, &ps);
        RECT rc;
        GetClientRect(hWnd, &rc);

        FillRect(hdc, &rc, hBrushBg);
        SetBkMode(hdc, TRANSPARENT);

        RECT rcHeader = { 25, 20, rc.right - 25, 60 };
        SelectObject(hdc, hFontTitle);
        SetTextColor(hdc, COL_TEXT_HEADER);
        DrawTextW(hdc, L"Luxor Discord RPC", -1, &rcHeader, DT_LEFT | DT_SINGLELINE | DT_VCENTER);

        RECT rcBar = { 0, 0, 6, rc.bottom };
        HBRUSH hAccent = CreateSolidBrush(COL_ACCENT);
        FillRect(hdc, &rcBar, hAccent);
        DeleteObject(hAccent);

        std::lock_guard<std::mutex> lock(g_dataMutex);
        RECT rcStatus = { 25, 60, rc.right - 25, 90 };
        SelectObject(hdc, hFontBody);
        SetTextColor(hdc, COL_ACCENT);
        DrawTextW(hdc, g_statusText.c_str(), -1, &rcStatus, DT_LEFT | DT_SINGLELINE | DT_VCENTER);

        std::wstring pathStr = L"Path: " + g_luxorPath;
        RECT rcPath = { 25, 95, rc.right - 25, rc.bottom - 20 };
        SetTextColor(hdc, COL_TEXT_BODY);
        DrawTextW(hdc, pathStr.c_str(), -1, &rcPath, DT_LEFT | DT_WORDBREAK);

        EndPaint(hWnd, &ps);
    }
    break;

    case WM_CTLCOLORSTATIC:
    {
        HDC hdcStatic = (HDC)wParam;
        SetTextColor(hdcStatic, COL_TEXT_BODY);
        SetBkMode(hdcStatic, TRANSPARENT);
        return (LRESULT)hBrushBg;
    }

    case WM_CLOSE:
        ShowWindow(hWnd, SW_HIDE);
        break;

    case WM_DESTROY:
        Shell_NotifyIcon(NIM_DELETE, &g_nid);
        if (hFontTitle) DeleteObject(hFontTitle);
        if (hFontBody) DeleteObject(hFontBody);
        if (hBrushBg) DeleteObject(hBrushBg);
        PostQuitMessage(0);
        break;

    default:
        return DefWindowProc(hWnd, message, wParam, lParam);
    }
    return 0;
}

int APIENTRY WinMain(_In_ HINSTANCE hInstance, _In_opt_ HINSTANCE hPrevInstance, _In_ LPSTR lpCmdLine, _In_ int nCmdShow)
{
    const wchar_t* className = L"LuxorRPCClass";

    WNDCLASSW wc = {};
    wc.lpfnWndProc = WndProc;
    wc.hInstance = hInstance;
    wc.lpszClassName = className;
    wc.hCursor = LoadCursor(NULL, IDC_ARROW);
    wc.hbrBackground = NULL;
    wc.style = CS_HREDRAW | CS_VREDRAW;

    RegisterClassW(&wc);

    RECT rc = { 0, 0, 600, 220 };
    AdjustWindowRect(&rc, WS_OVERLAPPEDWINDOW, FALSE);

    g_hWnd = CreateWindowW(className, L"Luxor Discord RPC",
        WS_OVERLAPPED | WS_CAPTION | WS_SYSMENU | WS_MINIMIZEBOX,
        CW_USEDEFAULT, CW_USEDEFAULT,
        rc.right - rc.left, rc.bottom - rc.top,
        NULL, NULL, hInstance, NULL);

    std::thread rpcThread(MemoryReaderThread);
    rpcThread.detach();

    ShowWindow(g_hWnd, SW_HIDE);
    UpdateWindow(g_hWnd);

    MSG msg;
    while (GetMessage(&msg, NULL, 0, 0)) 
    {
        TranslateMessage(&msg);
        DispatchMessage(&msg);
    }

    return (int)msg.wParam;
}