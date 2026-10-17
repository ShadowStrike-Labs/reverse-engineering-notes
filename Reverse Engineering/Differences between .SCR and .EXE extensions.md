
- .EXE and .SCR both uses the PE(Portable Executable) format
- Double click --> .EXE starts normally , .SCR starts at screen saver mode.
- Entry points -> in .EXE its mostly WinMain/Main while in .SRC its almost always WinMain

- /s  mode(Screen Saver):
	 /s mode : opens at fullscreen, hides the mouse, Sets a timer for the animation, closes by mouse movement and clicking.
- /c mode(Config):
	 Opens the settings dialog, changes the user settings,
- /p mode(Preview):
	Opens a small window, connects to the parent window. 
	Preview mode shows the small preview of the screen saver at the control panel.


- Typical .SCR winmain code pattern:
	int WinMain(HINSTANCE hInstance, ...)
	{
    // 1. Check the Parameters
    if (lpCmdLine == "/c") {
        // Config dialog
        DialogBoxParamW(...);
        return 0;
    }
    if (lpCmdLine == "/p") {
        // Preview
        CreateWindowExW(..., hWndParent, ...);
        return 0;
    }
    if (lpCmdLine == "/s") {
        // Screen saver
        CreateWindowExW(..., nullptr, ...);
        // setup the timer
        SetTimer(...);
        // message loop
        while (GetMessage(...)) { ... }
        return 0;
    }
    // with no parameters → config
    DialogBoxParamW(...);
    return 0;
	}