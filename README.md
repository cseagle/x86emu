Clone into the plugins subdirectory of your IDA SDK subdirectory.
Unpack it there so that you have something along the lines of: 

<SDK_DIR>\plugins\x86emu

---------------------------------------------------------------------------

BUILDING THE QT VERSION OF THE PLUGIN

Ida ships with a limited number of link libraries for Qt.  These may be found
in <SDK>/lib/Qt.w32 or <SDK>/lib/x86_win_qt on Windows.  On linux you may link
against the .so files that ship with your Ida install.  On OS X you may link
against the .dylib files that ship with your Ida install.

In order to build the Qt version of the plugin for Ida versions 6.0 and later
you will also need the Qt source code.

Ida 6.0 uses Qt version 4.6.3 whose source is available here 
http://download.qt.io/archive/qt/4.6/qt-everywhere-opensource-src-4.6.3.tar.gz
or here
http://download.qt.io/archive/qt/4.6/qt-win-opensource-4.6.3-vs2008.exe

Ida 6.1 through 6.8 uses Qt version 4.7.2 whose source is available here 
http://download.qt.io/archive/qt/4.7/qt-everywhere-opensource-src-4.7.2.tar.gz
or here
http://download.qt.io/archive/qt/4.7/qt-win-opensource-4.7.2-vs2008.exe

Ida 6.9 and later Qt version 5.4.1 whose source is available here 
http://download.qt.io/archive/qt/5.4/5.4.1/qt-opensource-linux-x86-5.4.1.run
or here
http://download.qt.io/archive/qt/5.4/5.4.1/qt-opensource-mac-x64-clang-5.4.1.dmg
or here
http://download.qt.io/archive/qt/5.4/5.4.1/qt-opensource-windows-x86-winrt-5.4.1.exe

Before building the plugin, your Qt source must be properly configured.  See the
Qt documentation for your platform regarding configuring Qt. The Qt libraries
shipped with Ida are configured to wrap all of Qt in a QT namespace so a sample
configuration might look like:

configure -qtnamespace QT -no-openssl -no-dbus -shared -no-phonon-backend \
 -no-phonon -no-audio-backend -no-multimedia -no-rtti -release -opensource \
 -no-script -no-scripttools -no-webkit -nomake examples -nomake demos  \
 -platform win32-msvc2010
 
Change the -platform to linux-g++, macx-g++, or macx-clang as appropriate

Note that the Qt libraries shipped with the Windows version of Ida were built
with Visual Studio, so the Windows version of the plugin will need to be 
built using Visual Studio.

Once Qt is configured, the Qt libraries need to be built.  On Windows, with 
a properly configured Visual Studo command line environment, the nmake utility 
may be used to compile Qt.  On linux gmake is used, and on OS X make is used.

Once Qt has been confugred and built, the plugin can be built.  From the
plugin's directory, the first step is to create the required makefiles
using Qt's qmake utility (which should be in your path):

> qmake -o Makefile.msvc x86emu.pro -platform win32-msvc2010

Of course you can name the output makefile anything you like and you should
set the platform option appropriately.

To complete the build on Windows, use Visual Studio's nmake utility, again
assuming a properly configure command line build environment:

> nmake -f Makefile.msvc

You should find the compiled plugin at <SDK>/bin/plugins/x86emu_qt.plw

Build scripts for Windows, linux, and OS X ship with x86emu.  Within the
plugin directory, the command
> ./build.win32
should perform the necessary steps to build the plugin (assuming Qt and Visual
Studio environment variables are properly set)

---------------------------------------------------------------------------

BUILDING WITH VISUAL C++ (VISUAL STUDIO 2010)

These instructions are applicable only to the idag (native Windows) version
of the plugin for IDA versions 5.7 and older.

The VC++ solution file for Visual Studio 2010 and above and is named: x86emu.sln

Open the solution file with Visual Studio and you should be able to build 
x86emu.plw which will end up in <SDK>bin\plugins\x86emu.plw

---------------------------------------------------------------------------

INSTALLATION

Copy the plugin binary (x86emu.plw or x86emu_qt.plw) into your IDA\plugins
directory in order to actually use the plugin. By default the plugin activates
with the Alt-F8 key sequence. If you need to change this, you should edit
plugins.cfg file in that same directory to add the following line at the end:

        x86Emu          x86emu          Alt-F7          0

This configures IDA to open the plugin when you press Alt-F7.  Change the
key sequence to anything you wish.

---------------------------------------------------------------------------

USAGE

Here is a quick rundown of the buttons:

Step - Execute a single instruction at eip
Jump - Set eip to the current cursor location
Run  - Runs until a breakpoint is encountered
Skip - Skip the instruction at eip, advancing eip to the next 
       instruction 
Run to cursor - Execute instructions from eip until eip == the cursor location
       Could be dangerous. If you never actually reach the cursor 
       location, there is no good way to regain control 

Push - Opens an input window for you to push data onto the 
       plugin's stack. Enter data as space separated values.  each 
       value is treated as a 4 byte quantity.  Values are pushed 
       right to left, so you would enter them in the same order they 
       appear in a C argument list for example.

Set Data - Opens a dialog where you can specify an address and data values to
       write at that address.  Data values can be entered in a variety of 
       formats depending on the radio button that you select

Segments - Opens the segment register dialog box. You can set 16 bit values for
       any segment register and 32 bit values for the segment base.  This is a
       crude workaround for the current lack of a GDT. 16 bit addressing is not
       currently implemented.  All address values are added to the appropriate
       segment base address (either implied or explicit)
       
A menu bar has been added to offer menu style access to some functions.  The 
menu is the only way to access function hooking operations and to specify
your own memory configuration for the stack and the heap.

Additional functionality available via menus includes:

File/Dump - Allows you to enter a range of addresses and choose a file to dump
       the raw binary data at those addresses to.

View/Enumerate Heap: Prints to the message window a list of all allocated heap
       blocks and their associated sizes.

Emulate/Set Breakpoint: Set a breakpoint at the specified address
Emulate/Remove Breakpoint: Remove a breakoint at a specified address
Emulate/Switch thread: switch to a new thread of execution.

Emulate/Windows/Auto Hook: Turns auto-hooking on/off.  Auto hooking allows
       the emulator to automatically hook calls to known library functions
       when GetProcAddress is used to lookup the address of those functions.
Emulate/Windows/Set import address save point: Remembers the cursor locations
       as an instruction that is used to save GetProcAddress results.  When 
       the instruction at that location is executed, the emulator will 
       automatically name the destination memory location using the name
       that was last passed to GetProcAddress.  Useful for rebuilding import
       tables automatically.
Emulate/Windows/Export lookup: Prompts for an address, then does a reverse
       lookup through loaded dlls to determine if that address is the address
       of an exported function.  Reports the associated function name if 
       found.
       
Functions/Hook a Function: Specifiy a function intercept address and 
       associated function mapping.  Allows emulated execution of a very small
       subset of library functions.  Whenever a call is made to the specified
       address, the function is emulated, a useable result is placed in eax
       and the stack is cleaned up (if necessary).
Functions/Patch and Hook: Similar to hooking a function with the added effect
       that it writes the current cursor address into the current cursor
       location.  This is useful when you are hooking import table entries, it
       simply makes the import table entry refer back to itself and sets up a 
       hook for calls to that import table location.

You can double click on any of the register windows to bring up an input dialog
to modify register values directly at any time.  The input routines for all of
the input dialogs recognize a 0x prefix to mean a hex value and parses it
appropriately.

Limitations:

A warning up front that the x86 emulator code (cpu.cpp) was thrown together 
very hastily and certainly contains many bugs.  I debugged enough of it to run
the instructions that I was interested in running for a particular binary I was 
reversing.  Over the years more and more instructions have been added with
preliminary support for FPU and MMX operations now included.

Exception handling:

A very limited set of exceptions are recognized.  The emulator maintains an IDT
and looks up exception handlers for recognized exceptions.  If a handler is 
installed, the emulator pushes appropriate CPU state info and transfers control
to the installed handler.  When reversing Windows binaries, the emulator will 
build an exception context and transfer control to an installed SEH handler for
Int 1, Int 3, Divide by Zero.

NEW FEATURES:

Please refer to ChangeLog for more recent changes

07/12/05 -
   The emulator now saves its state with the IDA database and reloads state if
   a saved state is located at idb load time.  The distribution now also 
   includes a makefile for building with g++ on cygwin.
   
08/17/04 -
   Changed function hooking behavior.  Hooks are now based on destination
   (i.e. hooked function) address rather than call location.  Now, hooking
   a function once properly hooks it for all calls to that function.  The best
   way to hook a function is to assign unique values for each function address
   in the program's import table, then use the Emulate/Hook menu to bring up
   the hook function dialog and pair the unique address to the desired function
   In Windows programs if you hook GetProcAddress, then GetProcAddress will
   report the name of each function being looked up and assign each an ID that
   can be used to hook the function.  The emulated GetProcAddress function also
   automatically hooks any function for which an emulation exists and directs
   all functions for which no emulation exists to an "unemulated" stub.


07/04/04 -
   SEH code is now working. Exceptions generated by the program being emulated
   will trigger Windows SEH for PE binaries.  Of course this only works if the
   program took the time to setup an exception handler via fs:[0].  Currently
   the emulator will handle INT3, single stepping with the TRAP flag set, use
   of Debug registers 0-3/7 and division by zero.

04/03/04 - 
   The emulator now incorporates a memory manager to separate program, heap, 
   and stack spaces.  There have been some changed to the UI.  There is now 
   a menu bar that incorporates many of the existing functions as well as some
   new one.  You can configure the stack and heap layout via Emulator/Settings.
   The emulator also provides emulated calls to a few memory allocation 
   functions.  See the Functions menu.  To execute an emulated function, step 
   the emulator through all of the parameter setup for the desired function
   stopping at the instruction that performs the call, then select the function
   to be emulated from the Functions menu.  The emulator will take the proper
   parameters from the stack and execute the function cleaning up the stack as
   required and placing any result into eax.  The emulator will step forward to
   the instruction following the call.  Pointers returned from the emulated
   memory allocation functions are valid pointers into the emulator heap.
   Memory access via these pointers will make use of the emulated heap memory.

   Heap usage: Make sure you configure the heap via Emulate/Settings before
               attempting to use any heap functions

Some tips:

If you want to grab some scratch space for your own use, you have two options:
1) You can push data onto the stack to grab some space for buffers. 
2) Utilize the Functions/Allocate heap block or Functions/Allocate mmap block.
   and keep track of the value returned as the pointer to your newly allocated
   space.

You will need to manage your own pointers into this space, but you can push
them as parameters to functions or provide them as function return values.  For
example, if you have grabbed some stack space prior to stepping through any 
code, then when you encounter a call to malloc, you can skip the call itself
and set eax to point into your stack buffer before you continue stepping.  
Poor man's malloc!

Windows SEH - The emulator allocates a teb segment and a peb segment in the
IDA database and populates several fields in these segments with reasonable
values that a program would expect to encounter at runtime.

Feedback:

Your feedback is greatly appreciated. You can reach me at:
cseagle at gmail d0t c0m
