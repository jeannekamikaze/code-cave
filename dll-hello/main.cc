#define WIN32_LEAN_AND_MEAN
#include <Windows.h>

#include <sstream>
#include <fstream>

BOOL init ()
{
    char filename[MAX_PATH];
    GetModuleFileNameA(NULL, filename, MAX_PATH);

    std::ostringstream os;
    os << "Hello from " << filename << "!";

    MessageBoxA(NULL, os.str().c_str(), "Hello", MB_OK);

    std::ofstream f("C:\\Users\\Marc\\Desktop\\hello.txt");
    f << "Hello!" << std::endl;
    f.close();

    return TRUE;
}

BOOL quit ()
{
    return TRUE;
}

BOOL WINAPI DllMain (HINSTANCE, DWORD fwdReason, LPVOID)
{
    if (fwdReason == DLL_PROCESS_ATTACH)
        return init();
    else if (fwdReason == DLL_PROCESS_DETACH)
        return quit();
    else
        return TRUE;
}
