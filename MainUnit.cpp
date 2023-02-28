
#include "MainUnit.h"

volatile HINSTANCE hInstance; 

// Config
static const int MaxRead  = 256;
static const int MaxTries = 9;
static const char CmdEnter = {0x0D};

bool AnsiCSupp = false;
long StayDelay = -1;  // Infinite // In seconds
UINT PortNum = 0;
UINT PortSpd = 0;
UINT MFlags  = 0;
UINT64 RAddr = 0;
UINT32 RSize = 0;
UINT32 ROffs = 0;

HANDLE hConIn  = NULL;
HANDLE hConOut = NULL;

char GoArgs[512];
wchar_t  ExePath[MAX_PATH];
wchar_t  FilePath[MAX_PATH];
wchar_t  ConfigPath[MAX_PATH];
wchar_t  StartUpDir[MAX_PATH];


//wchar_t  DmpPath[MAX_PATH];  // REMOVE


/*
The return value of a command can be found in environment variable $?
gpio input 50; echo $?
-----
*/
//====================================================================================
//
//------------------------------------------------------------------------------------
void ConLogFromUBoot(char* Msg, UINT Size)
{
 SetConsoleTextAttribute(hConOut, FOREGROUND_BLUE|FOREGROUND_GREEN|FOREGROUND_INTENSITY);     // Blue
 LOGTXT(Msg, Size);
 SetConsoleTextAttribute(hConOut, FOREGROUND_BLUE|FOREGROUND_GREEN|FOREGROUND_RED);   // White
}
//------------------------------------------------------------------------------------
// For md.l and md.q  // Any md  // Supports incomplete lines  
// md.q - '02000000: 1122334455667788 000000000000fff0    .wfUD3".........'
// md.l - '02000000: 55667788 11223344 0000fff0 00000000    .wfUD3".........'
//
int ParseUBootDump(CMiniStr& Dump, CMiniStr& Result) 
{
 PBYTE Data = Dump.c_data();
 for(int offs=0,gctr=0,tot=Dump.Length();offs < tot;gctr++)
  {
   if(!gctr)offs = Dump.Pos(':',CMiniStr::ComparatorE, offs);   // Start of line, find addr separator
   if(offs <= 0)break;
   BYTE Tmp[16];
   int SpaceCtr = 0;
   while(Data[++offs] == 0x20)SpaceCtr++;  // Skip spaces before the value
   if(!Data[offs])break;  // Unexpected end of text
   if(SpaceCtr > 2)  // Before text dump block
    {
     offs = Dump.Pos(0x0A,CMiniStr::ComparatorE, offs); // To end of line
     gctr = -1;
     continue;
    }
   int len = HexStrToByteArray(Tmp, &Data[offs], -1, 0x1F);  
   if(len <= 0)break;
   ReverseBytes(Tmp, len);  // Decode from LE format
   Result.cAppend((char*)&Tmp,len);  
   offs += len * 2;  // Skip size of recognized HEX chars
  }
 return Result.Length();
}
//------------------------------------------------------------------------------------
// \x0D (CR) moves the print head back to the beginning of the line. (Unicode encodes this as U+000D CARRIAGE RETURN.)
// \x0A (LF) moves the print head down to the next line. (Unicode encodes this as U+000A LINE FEED.)
// NOTE: PuTTY send chars one by one as you type them. Enter is 0x0D char but UBOOT seems to accept any of two as a line terminator
//
int RunCommandOnUBoot(CComPort* Port, char* Cmd, CMiniStr* Rsp) 
{
 UINT res = 0;
 char CmdBuf[256];
 char RspBuf[256];
 int  CmdLen  = NSTR::StrCopy(CmdBuf, Cmd, sizeof(CmdBuf)-(sizeof(CmdEnter)+1));
 bool IsPurge = (CmdLen==4) && (Cmd[1]==0x0A) && (Cmd[0]==0x20);
 LOGMSG("Response for '%s':",(IsPurge)?("*PURGE*"):(Cmd));
 memcpy(&CmdBuf[CmdLen], &CmdEnter, sizeof(CmdEnter));
 UINT WrLen = CmdLen + sizeof(CmdEnter);
 for(int TryCtr=MaxTries;Port->Write((PBYTE)&CmdBuf, WrLen, &res) < 0;TryCtr--){LOGMSG("Failed to write COM!"); if(TryCtr <= 0)return -1;}
 if(WrLen != res){LOGMSG("Write size mismatch: got %u, expected %u",res,WrLen);}
 if(!Rsp)return 0;
 for(bool First=true;;)     // Read the command response   // NOTE: Lines come separated with 0D 0A except last one
  {
   res = 0;
   UINT Offs = 0;
   for(int TryCtr=MaxTries;Port->Read((PBYTE)&RspBuf, MaxRead, &res) < 0;TryCtr--){LOGMSG("Failed to read COM!"); if(TryCtr <= 0)return -2;}
   if(!res)break;
   ConLogFromUBoot((char*)&RspBuf, res);   //LOGTXT((char*)&RspBuf, res);
   if(First)      // NOTE: Last sent LINE is echoed back here
    {
     First = false;
     Rsp->Clear();
     if(!memcmp(&RspBuf, &CmdBuf, WrLen))
      {
       res -= WrLen;
       Offs = WrLen;
       while((res > 0) && (RspBuf[Offs] < 0x20)){Offs++;res--;}
      }
    }
   Rsp->cAppend((char*)&RspBuf[Offs], res);   
  }
 OUTMSG(" ");   // Start a new line
 return Rsp->Length();
}
//------------------------------------------------------------------------------------
int PurgeCommBuffers(CComPort* Port)
{
 CMiniStr Result;
 Port->Purge(true, true);
 UINT res = RunCommandOnUBoot(Port, " \x0a \x0d", &Result);    // Sending ENTER just repeats a last command, put SPACE to remove it  " \x0a\x0d"
 Port->Purge(true, true);
 return res;
}
//------------------------------------------------------------------------------------
int CacheCtrlOnUBoot(CComPort* Port, bool Enable)
{
 CMiniStr Result;   
 if(PurgeCommBuffers(Port) < 0)return -1;
 if(RunCommandOnUBoot(Port, Enable?"icache on":"icache off", &Result) < 0)return -2;
 if(RunCommandOnUBoot(Port, Enable?"dcache on":"dcache off", &Result) < 0)return -3;
 return 0;
}
//------------------------------------------------------------------------------------
int CalcCrcOnUBoot(CComPort* Port, UINT64 Addr, UINT Size, UINT32* CrcOut)
{
 CMiniStr Dump; 
 char Cmd[128];
 wsprintfA(Cmd, "crc32 0x%08x 0x%08x",Addr,Size);
 if(RunCommandOnUBoot(Port, Cmd, &Dump) < 0)return -2;
 int pval = Dump.Pos("crc32 for");
 if(pval < 0)pval = Dump.Pos("...");
 if(pval < 0)pval = Dump.Pos("==>");
 if(pval >= 0)
  {
   char* BPtr = Dump.c_str(); 
   char* VPtr = BPtr;
   char* EPtr = BPtr + Dump.Length();
   for(;(BPtr < EPtr)&&(*BPtr >= 0x20);BPtr++){if(*BPtr == 0x20)VPtr=BPtr+1;}
   UINT32 InMemCrc = HexStrToNum<UINT32>(VPtr);
   if(CrcOut)*CrcOut = InMemCrc;
   LOGMSG("Source data Crc32: %08X",InMemCrc); 
  }
 return 0;
}
//------------------------------------------------------------------------------------
// md.l 0xADDR 0xCOUNT
// In Two lines: md [.b, .w, .l, .q] address [# of objects]
// Expect max line size is 68 chars, Read max 16 lines at a time (This gives 256 bytes of data (1088 in text))
//
int PullMemFromUBoot(CComPort* Port, HANDLE hDstFile, UINT64 Addr, UINT Size, bool ChkCrc=false)
{
 static const int BytesInLine = 16;   // Output is always 16 bytes per line
 static const int ReqBlkMax   = 512;  // Bytes per request
 CMiniStr Dump; 
 CMiniStr Result;   
 char Cmd[128];   
 if(PurgeCommBuffers(Port) < 0)return -1;
 UINT UnitSize = 4;     // md.l     // TODO: UDivModP2 (Bit count is 1)
 UINT TotalUnits = NCMN::AlignP2Frwd(Size, UnitSize) / UnitSize; //Size / UnitSize;
 //TotalUnits += (bool)(Size % UnitSize);
// UINT LinesInBlk = (ReqBlkMax / BytesInLine); 
 UINT UnitsInBlk =  (ReqBlkMax / UnitSize); 
// UINT UnitsInLine = (BytesInLine / UnitSize);   //   4 units for md.l  

 UINT32 InMemCrc = -1;  // NOTE: do not check crc32 for regions which may change while being dumped!
 if(ChkCrc)  // NOTE: May cause UBOOT to crash if not all memory in the range is available
  {
   if(CalcCrcOnUBoot(Port, Addr, Size, &InMemCrc) < 0){LOGMSG("Crc32 is not supported!"); ChkCrc=false; if(PurgeCommBuffers(Port) < 0)return -1;}
  }
 for(int TryCtr=MaxTries;TotalUnits;)      
  {   
   Dump.Clear();
   Result.Clear();
   UINT UCnt = (TotalUnits > UnitsInBlk)?(UnitsInBlk):(TotalUnits);
   wsprintfA(Cmd, "md.l 0x%08x 0x%08x",Addr,UCnt);     // x64 addr?
   if(RunCommandOnUBoot(Port, Cmd, &Dump) < 0)return -3;
   UINT ExpectSize = UCnt * UnitSize;   
   int RLen = ParseUBootDump(Dump, Result); 
   if(RLen != ExpectSize){if(--TryCtr >= 0){LOGMSG("Incomplete block - repeating!"); continue;}}    
   DWORD WRes = 0;
   WriteFile(hDstFile, Result.c_data(), Result.Length(), &WRes, NULL);
   Addr += RLen;
   if(TryCtr <= 0){LOGMSG("No more tries, finishing at %08X, left %08X!",Addr,TotalUnits*UnitSize); break;}   
   TotalUnits -= UCnt;   
   TryCtr = MaxTries;  
  }
 if(ChkCrc)
  {
   // Then what?
  }
 return Result.Length();
}
//------------------------------------------------------------------------------------
// NOTE: load{x,y,z} commands are not implemented
//
int PushMemToUBoot(CComPort* Port, HANDLE hSrcFile, UINT64 Addr, UINT Size)
{
 CMiniStr Result;   
 char Cmd[128];  
 BYTE Buf[1024]; 
 if(PurgeCommBuffers(Port) < 0)return -1;
 if(RunCommandOnUBoot(Port, "md", &Result) < 0)return -2;  
 UINT DSize = 4;
 char DChar = 'l';
 if(Result.Pos(".q") > 0){DSize = 8;DChar = 'q';}   // Arm64      // In Two lines: md [.b, .w, .l, .q] address [# of objects]
 UINT FullSize = NCMN::AlignP2Frwd(Size, DSize);
 wsprintfA(Cmd, "mm.%c 0x%08x",DChar,Addr);
 UINT UnitsInBuf = 0;
 if(RunCommandOnUBoot(Port, Cmd, &Result) < 0)return -3;
 for(UINT TotalUnits = FullSize / DSize, UnitOffs=0;TotalUnits > 0;TotalUnits--,UnitsInBuf--,Addr+=DSize,UnitOffs+=DSize)
  {
   if(Result.Pos(':',CMiniStr::ComparatorE) <= 0)return -4;
   if(Result.Pos('?',CMiniStr::ComparatorE) <= 0)return -4;
   if(!UnitsInBuf)
    {
     DWORD RRes = 0;
     if(!ReadFile(hSrcFile, &Buf, sizeof(Buf), &RRes, NULL))return -5;
     if(!RRes)break;  // No more data
     UnitsInBuf = NCMN::AlignP2Frwd(RRes, DSize) / DSize;
     UnitOffs = 0;
    }
   ReverseBytes(&Buf[UnitOffs], DSize);
   ByteArrayToHexStr(&Buf[UnitOffs], Cmd, DSize, false);
   Cmd[DSize*2] = 0;
   if(RunCommandOnUBoot(Port, Cmd, &Result) < 0)return -6;
  }
 RunCommandOnUBoot(Port, " ", &Result);  // Any wrong HEX number breaks the input mode
 return 0;
}
//------------------------------------------------------------------------------------
// If hExeFile is not NULL and Send is false then this file is used
// If ElfEPName is NULL then starting at ELF entry point
int ExecOnUBoot(CComPort* Port, UINT64 BaseAddr, char* Args=nullptr, HANDLE hExeFile=0, char* ElfEPName=nullptr)
{
 CMiniStr Result;   
 char Cmd[1024]; 
 if(!Args)Args = "";  
 if(PurgeCommBuffers(Port) < 0)return -1;
 OUTMSG("Starting at %08X: %s",BaseAddr,Args); 
 wsprintfA(Cmd, "go 0x%08x %s",BaseAddr,Args);
 if(RunCommandOnUBoot(Port, Cmd, nullptr) < 0)return -2;   // Response is not needed, pass it to the main loop
 return 0;
}
//------------------------------------------------------------------------------------
 // NOTE: Every 0A ('\n') sent is turned into 0D 0A  // 0D is '\r'
UINT RemoveLineBreaks(unsigned char* Data, UINT Size)
{
 UINT SrcOffs = 0;
 UINT DstOffs = 0;
 while(SrcOffs < Size)
  {
   if((Data[SrcOffs] == 0x0D)&&(Data[SrcOffs+1] == 0x0A))SrcOffs++;   // Skip extra 0D
   Data[DstOffs++] = Data[SrcOffs++];
  }
 return DstOffs;
}
//====================================================================================
void _stdcall SysMain(DWORD UnkArg)
{
 SetErrorMode(SEM_FAILCRITICALERRORS|SEM_NOGPFAULTERRORBOX|SEM_NOOPENFILEERRORBOX);	 // Crash silently an error happens
 hInstance = GetModuleHandleA(NULL);
 GetModuleFileNameW(hInstance,ExePath,sizeof(ExePath)*2); 
 lstrcpyW(StartUpDir, ExePath); 
 lstrcpyW(LogFilePath, ExePath);
 GetFileExt(LogFilePath)[0] = 0;
 if(!AttachConsole(ATTACH_PARENT_PROCESS))AllocConsole();
 hConIn  = GetStdHandle(STD_INPUT_HANDLE);
 hConOut = GetStdHandle(STD_OUTPUT_HANDLE);
 DWORD ConMode = 0;
 GetConsoleMode(hConIn, &ConMode);
 ConMode &= ~ENABLE_ECHO_INPUT;    // Do not echo chars to our console, only transfer them to uboot, it will echo them back
 ConMode &= ~ENABLE_LINE_INPUT;    // Receive chars one by one to transfer them one by one  
 SetConsoleMode(hConIn, ConMode);

 GetConsoleMode(hConOut, &ConMode);
// SetConsoleMode(hConOut, ConMode|ENABLE_VIRTUAL_TERMINAL_PROCESSING);  // Do not work as expected!   https://superuser.com/questions/413073/windows-console-with-ansi-colors-handling
 GetConsoleMode(hConOut, &ConMode);
 AnsiCSupp = ConMode & ENABLE_VIRTUAL_TERMINAL_PROCESSING;
// SetConsoleMode(hConOut,0x0004);      // ENABLE_VIRTUAL_TERMINAL_PROCESSING  // Breaks the terminal output for some reason
 TrimFilePath(StartUpDir);
 lstrcpyW(ConfigPath, LogFilePath);
 lstrcatW(LogFilePath, L"log");
 lstrcatW(ConfigPath, L"jsn");
 LogMode = lmCons;//|lmFile;


// LOGMSG("Loading configuration...");
 PWSTR CmdLine = GetCommandLineW();
 ULONG CmdLen = lstrlenW(CmdLine);
 if(CmdLine[CmdLen-1] == '\"')CmdLen--;
 LOGMSG("CmdLine: %ls", CmdLine);

 int ParCnt = -1;
 wchar_t Cmd[64];
 wchar_t Arg[MAX_PATH];
 for(;*CmdLine;ParCnt++)
  {
 //  DBGMSG("Parsing Arg: %ls", CmdLine);
   CmdLine = GetCmdLineParam(CmdLine, Cmd);   // Get a command
   if(NSTR::IsStrEqualIC("-stay", Cmd))
    {
     if((*CmdLine <= '9')&&(*CmdLine >= '0'))
      {
       long NumSize = 0;
       CmdLine = GetCmdLineParam(CmdLine, Arg);  // Get port number
       StayDelay = DecStrToNum<UINT>(Arg, &NumSize); 
       if(!NumSize){LOGMSG("Wrong value for stay delay!"); ExitProcess(-1);} 
      }
     MFlags |= ecStay;  
     continue;
    } 
   if(NSTR::IsStrEqualIC("-pull", Cmd))
    {
     MFlags |= ecPull;  
     continue;
    }
   if(NSTR::IsStrEqualIC("-push", Cmd))
    {
     MFlags |= ecPush;  
     continue;
    }
   if(NSTR::IsStrEqualIC("-exec", Cmd))
    {
     if(*CmdLine == '\"')  // Have arguments for UBOOT`s go command
      {
       CmdLine = GetCmdLineParam(CmdLine, Arg);  // Get the argument string
       NSTR::StrCopy(GoArgs, Arg, sizeof(GoArgs)-1);
      }
     MFlags |= ecExec;  
     continue;
    }
   if(NSTR::IsStrEqualIC("-port", Cmd))
    {
     long NumSize = 0;
     CmdLine = GetCmdLineParam(CmdLine, Arg);  // Get port number
     PortNum = DecStrToNum<UINT>(Arg, &NumSize); 
     if(!NumSize){LOGMSG("Wrong value for port number!"); ExitProcess(-1);}  
     CmdLine = GetCmdLineParam(CmdLine, Arg);  // Get port speed
     PortSpd = DecStrToNum<UINT>(Arg, &NumSize); 
     if(!NumSize){LOGMSG("Wrong value for port speed!"); ExitProcess(-1);}  
     MFlags |= ecPort;
     continue;
    }  
   if(NSTR::IsStrEqualIC("-a", Cmd))
    {
     CmdLine = GetCmdLineParam(CmdLine, Arg);  // Get address param
     RAddr   = HexStrToNum<UINT64>(Arg);
     MFlags |= ecAddr;  
     continue;
    }
   if(NSTR::IsStrEqualIC("-s", Cmd))
    {
     CmdLine = GetCmdLineParam(CmdLine, Arg);  // Get size param
     RSize   = HexStrToNum<UINT32>(Arg);
     MFlags |= ecSize;  
     continue;
    }
   if(NSTR::IsStrEqualIC("-o", Cmd))
    {
     CmdLine = GetCmdLineParam(CmdLine, Arg);  // Get file offset param
     ROffs   = HexStrToNum<UINT32>(Arg);
     MFlags |= ecOffs;  
     continue;
    }
   if(NSTR::IsStrEqualIC("-f", Cmd))
    {
     CmdLine = GetCmdLineParam(CmdLine, Arg);  // Get file param
     MFlags |= ecFile;
     if(!AssignFilePath(FilePath, StartUpDir, Arg)){LOGMSG("No Path in '%ls'", &Cmd); ExitProcess(-1);}   
     continue;
    } 
  }

// Show help if no arguments specified
 if(ParCnt < 1)  
  {
   OUTMSG("-port n: COM port number to communicate with UBOOT");
   OUTMSG("-stay: Stay open and listen to messages (i.e. after exec) [opt: delay]");
   OUTMSG("-pull: Read memory from UBOOT system into a file [Priority: 1]");
   OUTMSG("-push: Write memory from a file into UBOOT system [Priority: 2]");
   OUTMSG("-exec: Execute code(can be combined with 'push' to execute after upload) [opt: \"args\"] [Priority: 3]");
   OUTMSG("-f: A file path to use with (pull, push, exec)");
   OUTMSG("-a: An address parameter to use (pull, push, exec)");
   OUTMSG("-s: A size parameter to use (pull, push)");
   OUTMSG("-o: An offset parameter to use (push)");
   OUTMSG("");
   OUTMSG("Example: -port 3 -stay -pull -a 02100000 -s 00001000 -f C:\\temp\\dump.bin");
   OUTMSG("");  
   ExitProcess(1);
  }

// Validate arguments
 if(!(MFlags & ecPort)){OUTMSG("No COM port specified!"); ExitProcess(-1);}
 if(MFlags & (ecPull|ecPush))
  {
   if(!(MFlags & ecAddr)){OUTMSG("No ADDRESS specified!"); ExitProcess(-1);}
   if(!(MFlags & ecSize) && (MFlags & ecPull)){OUTMSG("No SIZE specified!"); ExitProcess(-1);}
   if(!(MFlags & ecFile)){OUTMSG("No FILE specified!"); ExitProcess(-1);}
  }
 if((MFlags & ecExec) && !(MFlags & ecAddr)){OUTMSG("No ADDRESS specified!"); ExitProcess(-1);}

 CComPort port;
 if(port.Open(PortNum, PortSpd, 8, 0, 0, 5, 1, 10) < 0){LOGMSG("Failed to open COM %u!",PortNum); ExitProcess(-1);}    // 115200 for UBOOT
 port.Purge(true, true);
 CacheCtrlOnUBoot(&port, false);    // This is required for code upload and execution
                       
// Execute commands
if(MFlags & ecPull)
 {
  HANDLE hDstFile = CreateFileW(FilePath,GENERIC_WRITE,FILE_SHARE_READ|FILE_SHARE_WRITE,NULL,CREATE_ALWAYS,FILE_ATTRIBUTE_NORMAL|FILE_FLAG_SEQUENTIAL_SCAN,NULL);
  if(INVALID_HANDLE_VALUE == hDstFile){LOGMSG("Failed to create dst file: %ls",&FilePath); ExitProcess(-1);}
  LOGMSG("Dst file: %ls",&FilePath);  
  if(ROffs){ SetFilePointer(hDstFile,ROffs,NULL,FILE_BEGIN); SetEndOfFile(hDstFile); }  // For whatever reason
  int res = PullMemFromUBoot(&port, hDstFile, RAddr, RSize);
  CloseHandle(hDstFile);
  OUTMSG("Pull completed with status %i",res);
 }

if(MFlags & ecPush)
 {
  HANDLE hSrcFile = CreateFileW(FilePath,GENERIC_READ,FILE_SHARE_READ|FILE_SHARE_WRITE,NULL,OPEN_EXISTING,FILE_ATTRIBUTE_NORMAL|FILE_FLAG_SEQUENTIAL_SCAN,NULL);
  if(INVALID_HANDLE_VALUE == hSrcFile){LOGMSG("Failed to create src file: %ls",&FilePath); ExitProcess(-1);}
  LOGMSG("Src file: %ls",&FilePath);
  UINT SrcSize = GetFileSize(hSrcFile, NULL);
  if(!RSize)RSize = SrcSize;
  if(ROffs)
   {
    if(ROffs >= SrcSize){CloseHandle(hSrcFile); LOGMSG("Offset %08X is beyond EOF!",ROffs); ExitProcess(-1);}
    SetFilePointer(hSrcFile,ROffs,NULL,FILE_BEGIN);
   }
  if((ROffs+RSize) > SrcSize)
   {
    RSize = SrcSize - ROffs;
    OUTMSG("End of data is beyond EOF, trimming size to %08X",RSize);
   }
  int res = PushMemToUBoot(&port, hSrcFile, RAddr, RSize);
  CloseHandle(hSrcFile);
  OUTMSG("Push completed with status %i",res);
 }

if(MFlags & ecExec)  // TODO: Use the specified file as a reference to call different exported symbols from ELF. For now only raw binaries are supported (-oFormat=binary)
 {
  int res = ExecOnUBoot(&port, RAddr, GoArgs);
  OUTMSG("Exec completed with status %i",res);
 }

if(MFlags & ecStay)
 {   
  if(StayDelay > 1000000)StayDelay = 1000000;
  if(StayDelay < 0){ OUTMSG("Listening to incoming messages indefinitely..."); }
   else {OUTMSG("Listening to incoming messages for %u seconds",StayDelay); StayDelay *= 1000; }   // Into milliseconds
  char RspBuf[256];
  UINT res = 0;
  UINT TimeLeft = StayDelay;
  DWORD RTime = GetTickCount();
  bool FileRecMode = false;
  DWORD  FileCrc  = -1;
  DWORD  FileSize = 0;
  DWORD  LastSize = 0;
  CArr<UINT8> rarr;
  wchar_t FilePath[MAX_PATH];
  for(bool DoListen=true;DoListen;)      
   { 
    INPUT_RECORD rec[32];
    DWORD Res = 0;
    if(PeekConsoleInput(hConIn, &rec[0], 32, &Res) && Res)
     {
      bool ekctr = false;
      for(UINT ctr=0;ctr < Res;ctr++){if(rec[ctr].EventType == KEY_EVENT){ekctr=true;break;}}
      if(ekctr)
       {       
        if(ReadFile(hConIn,&RspBuf,sizeof(RspBuf),&Res,NULL) && Res)
         {
          UINT result;
          port.Write((PBYTE)&RspBuf, Res, &result);  // Send input to UBOOT
         }
       }
     }
    if(StayDelay > 0)
     {
      DWORD VTime = GetTickCount();
      StayDelay -= (VTime - RTime);    
      RTime = VTime;
      if(StayDelay <= 0){OUTMSG("Time is out!"); break;}
     }
    for(int TryCtr=MaxTries;port.Read((PBYTE)&RspBuf, MaxRead, &res) < 0;TryCtr--){LOGMSG("Failed to read COM!"); if(TryCtr <= 0)DoListen=false;}
    if(!res)continue;       //{Sleep(100); continue;}   // Nothing received   // PeekConsoleInput delays enough
    UINT ROffs = 0;
    if(!FileRecMode && (res > 6))
     {
      int offs = NSTR::StrOffsetSC(RspBuf, "<{[: ");
      if(offs >= 0)
       {
        ConLogFromUBoot((char*)&RspBuf, offs);   // Log everything before
        FileRecMode = true;
        char* Arr[5] = {};
        int eoffs = NSTR::CharOffsetSC(RspBuf, 0x0A, offs+5)+1;
        int vctr  = NSTR::SplitBySep((char*)&RspBuf[offs], eoffs-offs, Arr, 5, 0x20);
        FileSize  = HexStrToNum<UINT32>(Arr[1]);      // NOTE: No checks!
        FileCrc   = HexStrToNum<UINT32>(Arr[2]);
        NSTR::StrCopy(FilePath, StartUpDir);
        NSTR::StrCnat(FilePath, Arr[3]); 
        rarr.Clear();        
        ROffs = eoffs;
        OUTMSG("Receiving a file: Size=%08X, Crc32=%08X, Name: %s",FileSize,FileCrc,Arr[3]);
       }
     }
    if(FileRecMode)  
     {
      int eoffs = NSTR::StrOffsetSC(&RspBuf[ROffs], ":]}>");
      if(eoffs >= 0)
       {
        rarr.Append(&RspBuf[ROffs], eoffs);
         //  rarr.ToFile("C:\\Compressed1.bin");      
        FileRecMode = false;
        UINT RealSize = RemoveLineBreaks(rarr.Data(), rarr.Size());
         //  rarr.Resize(RealSize);
         //  rarr.ToFile("C:\\Compressed2.bin")
        CStrRLE rle;
        CArr<UINT8> DeArr;
        DeArr.Resize(FileSize+0x10000);
        rle.SetDataForDeCompr(rarr.Data(), RealSize);
        UINT DecSize = rle.DeCompressBlk(DeArr.Data(), DeArr.Size());
         //  DeArr.Resize(DecSize);
         //  DeArr.ToFile("C:\\Decompressed1.bin");
        OUTMSG("File receive complete: %08X/%08X bytes; Size is %s; CRC is %s", rarr.Size(),RealSize, (DecSize==FileSize?"OK":"BAD"), (rle.GetCrc()==FileCrc?"OK":"BAD"));  //OUTMSG("File receive complete: %s", "CRC !!!");
        DeArr.Resize(DecSize);
        if(DeArr.ToFile(FilePath) == DecSize){OUTMSG("Saved: %ls",&FilePath);}
          else {OUTMSG("Failed to save: %ls",&FilePath);}
        rarr.Clear();
        eoffs += 4;
        if(res > eoffs)ConLogFromUBoot((char*)&RspBuf[eoffs], res-eoffs); 
       }
        else
         {
          rarr.Append(&RspBuf[ROffs], res-ROffs);
          UINT32 CurrSize = rarr.Size() & ~0xFFFF;  // Report every 64k
          if(CurrSize > LastSize)
           {
            LastSize = CurrSize;
            OUTMSG("Received %08X bytes",rarr.Size());
           }
         }
     }
      else ConLogFromUBoot((char*)&RspBuf[ROffs], res-ROffs);  //  LOGTXT((char*)&RspBuf, res);
    if(StayDelay == 0)break;
   }
 }


/*
 {   // Inputs are echoed
  CComPort port;
 // BYTE Buf[1224];
  if(port.Open(3, 115200) < 0){LOGMSG("Failed to open COM!"); ExitProcess(0);}
  port.Purge(true, true);
 // BYTE Cmd[300]; 

  lstrcpyW(DmpPath, StartUpDir);
  lstrcatW(DmpPath, L"Test.txt");
  HANDLE hSrcFile = CreateFileW((PWSTR)&DmpPath,GENERIC_READ,FILE_SHARE_READ|FILE_SHARE_WRITE,NULL,OPEN_EXISTING,FILE_ATTRIBUTE_NORMAL|FILE_FLAG_SEQUENTIAL_SCAN,NULL);
  if(INVALID_HANDLE_VALUE == hSrcFile){LOGMSG("Failed to create src file: %ls",&DmpPath); ExitProcess(0);}
  UINT SrcSize = GetFileSize(hSrcFile, NULL);
  int rr = PushMemToUBoot(&port, hSrcFile, 0, 0x02000000, SrcSize);
  CloseHandle(hSrcFile);
  ExitProcess(0);

  UINT Addr = 0x0fea0000;  //0x01704000;   0EF1B000
  UINT AEnd = 0x0ffa0000; //Addr +  1660112;  //0x000b7c00; 
  lstrcpyW(DmpPath, StartUpDir);
  lstrcatW(DmpPath, L"UBootDmp2.bin");
  HANDLE hDstFile = CreateFileW((PWSTR)&DmpPath,GENERIC_WRITE,FILE_SHARE_READ|FILE_SHARE_WRITE,NULL,CREATE_ALWAYS,FILE_ATTRIBUTE_NORMAL|FILE_FLAG_SEQUENTIAL_SCAN,NULL);
  if(INVALID_HANDLE_VALUE == hDstFile){LOGMSG("Failed to create dst file: %ls",&DmpPath); ExitProcess(0);}
  LOGMSG("Dst file: %ls",&DmpPath);
  PullMemFromUBoot(&port, hDstFile, Addr, AEnd-Addr, true);
  CloseHandle(hDstFile);
 }
*/
 OUTMSG("Done");
 ExitProcess(0);  
}
//====================================================================================

//------------------------------------------------------------------------------------

//------------------------------------------------------------------------------------

//====================================================================================
