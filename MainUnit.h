
#pragma once


#include "Common.hpp"
#include "ComPort.hpp"
#include "StrRLE.hpp"
//------------------------------------------------------------------------------------------------------------
// Define as flags to track requirements
enum ECmd {ecNone=0,
           ecPull = 0x0001,
           ecPush = 0x0002,
           ecExec = 0x0004,
           ecPort = 0x0008,
           ecStay = 0x0010,
           ecAddr = 0x0020,
           ecSize = 0x0040,
           ecOffs = 0x0080,
           ecFile = 0x0100,

};
//------------------------------------------------------------------------------------------------------------
