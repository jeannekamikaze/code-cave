#define WIN32_LEAN_AND_MEAN
#include <Windows.h>

int WINAPI WinMain(HINSTANCE, HINSTANCE, LPSTR, int)
{
    MessageBoxA(NULL, "Hello!", "Hello", MB_OK);
    return 0;
}
