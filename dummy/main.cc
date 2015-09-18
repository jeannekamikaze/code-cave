#define WIN32_LEAN_AND_MEAN
#include <Windows.h>

#include <sstream>

int WINAPI WinMain(HINSTANCE, HINSTANCE, LPSTR, int)
{
    FARPROC p_LoadLibrary = GetProcAddress(GetModuleHandleA("kernel32.dll"), "LoadLibraryA");

    std::ostringstream os;
    os << "Dummy program initialised\n";
    os << "LoadLibrary: 0x" << p_LoadLibrary << "\n";

    MessageBoxA(NULL, os.str().c_str(), "Dummy", MB_OK);
    for (;;)
    {
        Sleep(100); // simulate work
    }
    return 0;
}
