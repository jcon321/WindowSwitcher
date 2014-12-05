#include <stdio.h>
#include <tchar.h>
#include <windows.h>
#include <winuser.h>
#include <string>
#include <sstream>


void SetForegroundWindowInternal(HWND hWnd)
{
 if(!::IsWindow(hWnd)) return;

 BYTE keyState[256] = {0};
 //to unlock SetForegroundWindow we need to imitate Alt pressing
 if(::GetKeyboardState((LPBYTE)&keyState))
 {
  if(!(keyState[VK_MENU] & 0x80))
  {
   ::keybd_event(VK_MENU, 0, KEYEVENTF_EXTENDEDKEY | 0, 0);
  }
 }

 ::SetForegroundWindow(hWnd);

 if(::GetKeyboardState((LPBYTE)&keyState))
 {
  if(!(keyState[VK_MENU] & 0x80))
  {
   ::keybd_event(VK_MENU, 0, KEYEVENTF_EXTENDEDKEY | KEYEVENTF_KEYUP, 0);
  }
 }
}


void EnableDebugPriv( )
 {
  HANDLE hToken;
  LUID sedebugnameValue;
  TOKEN_PRIVILEGES tkp;
  OpenProcessToken( GetCurrentProcess( ), TOKEN_ADJUST_PRIVILEGES |TOKEN_QUERY, &hToken );
  LookupPrivilegeValue( NULL, SE_DEBUG_NAME, &sedebugnameValue );
  tkp.PrivilegeCount = 1;tkp.Privileges[0].Luid = sedebugnameValue;
  tkp.Privileges[0].Attributes = SE_PRIVILEGE_ENABLED;
  AdjustTokenPrivileges( hToken, false, &tkp, sizeof( tkp ), NULL, NULL );
  CloseHandle( hToken );
 } 


int main()
{        
 //Find each EQ Window and set to appropriate name 
 //1. First ask how many EQ windows will be open
 DWORD pId;
 int x = 0;
 int numOfWindows = 0;
 printf("Please enter # of EQ instances");
 scanf ("%d",&numOfWindows);
 EnableDebugPriv();
 
 //Loop through each instance and set all but first new names
 //x<numOfWindows - 1 so you always leave 1 with original name
 for(x=0; x<numOfWindows-1; x++)
 {
  HWND hWindow = FindWindow(NULL,"EQW beta 2.32");
  if(!hWindow)
  {
   printf("EQ window not found\n");
   system( "pause" );
   return 0;
  }
  else
  {
     GetWindowThreadProcessId(hWindow, &pId);
     HANDLE hOpen = OpenProcess( PROCESS_ALL_ACCESS, false, pId );
     if(!hOpen)
     {
      printf("Cannot open process.");
 system( "pause" );
 return 1;
     }
     else
     {
      std::string name = "EQWindow";
      std::ostringstream convert;
      convert << x+1;
      name += convert.str();
      char *charName = new char[name.size()+1];
      charName[name.size()] = 0;
      memcpy(charName,name.c_str(),name.size());
      SetWindowText(hWindow, charName);
     } 
  }
 } 
   
 
 
 enum{ZERO_KEYID = 0, ONE_KEYID = 1, TWO_KEYID = 2, THREE_KEYID = 3, FOUR_KEYID = 4, FIVE_KEYID = 5};
 RegisterHotKey(0, ZERO_KEYID, 0, 0x60); // register NumPad0 key as hotkey
 RegisterHotKey(0, ONE_KEYID, 0, 0x61); // register NumPad1 key as hotkey
 RegisterHotKey(0, TWO_KEYID, 0, 0x64); // register NumPad4 key as hotkey
 RegisterHotKey(0, THREE_KEYID, 0, 0x67); // register NumPad4 key as hotkey
 RegisterHotKey(0, FOUR_KEYID, 0, 0x62); // register NumPad2 key as hotkey
 RegisterHotKey(0, FIVE_KEYID, 0, 0x68); // register NumPad8 key as hotkey
 MSG msg;
        
 HWND eqWindow0 = FindWindow(NULL, "EQW beta 2.32");//Change window title name here
 HWND eqWindow1 = FindWindow(NULL, "EQWindow1");//example: "Untitled - Notepad"
 HWND eqWindow2 = FindWindow(NULL, "EQWindow2");
 HWND eqWindow3 = FindWindow(NULL, "EQWindow3");
 HWND eqWindow4 = FindWindow(NULL, "EQWindow4");
 HWND eqWindow5 = FindWindow(NULL, "EQWindow5");
   
 //The while loop which waits for a keypress to then switch windows
 while(GetMessage(&msg, 0, 0, 0))
 {
  PeekMessage(&msg, 0, 0, 0, 0x0001);
  switch(msg.message)
  {
  case WM_HOTKEY:
   if(msg.wParam == ZERO_KEYID)
   {
    SetForegroundWindowInternal(eqWindow0);
    printf("Activated Window 0\n");
   }
   if(msg.wParam == ONE_KEYID)
   {
    SetForegroundWindowInternal(eqWindow1);
    printf("Activated Window 1\n");
   }
   if(msg.wParam == TWO_KEYID)
   {
    SetForegroundWindowInternal(eqWindow2);
    printf("Activated Window 2\n");
   }
   if(msg.wParam == THREE_KEYID)
   {
    SetForegroundWindowInternal(eqWindow3);
    printf("Activated Window 3\n");
   }
   if(msg.wParam == FOUR_KEYID)
   {
    SetForegroundWindowInternal(eqWindow4);
    printf("Activated Window 4\n");
   }
   if(msg.wParam == FIVE_KEYID)
   {
    SetForegroundWindowInternal(eqWindow5);
    printf("Activated Window 5\n");
   }
  }
 }
 return 0;
}
