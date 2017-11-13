'''
Created on 11 mai 2017

@author: hugo.porcher
'''
from ctypes import *
from defines import *
import sys

kernel32 = windll.kernel32
ntdll = windll.ntdll

class debugger():
    def __init__(self):
        self.h_process = None
        self.pid = None
        self.debugger_active = False
        self.h_thread = None
        self.context = None
        self.exception = None
        self.exception_address = None
        self.breakpoints = {}
        self.first_breakpoint = True
        self.hardware_breakpoints = {}
        self.guarded_pages = []
        self.memory_breakpoints = {}
        
        # Here let's determine and store 
        # the default page size for the system
        # determine the system page size.
        system_info = SYSTEM_INFO()
        kernel32.GetSystemInfo(byref(system_info))
        self.page_size = system_info.dwPageSize
        
    # Load a process, open it and set the flag debugger_active to true if it worked
    def load(self, path):
        creation_flags = DEBUG_PROCESS
        
        startupinfo = STARTUPINFO()
        procinfo = PROCESS_INFORMATION()
        
        startupinfo.dwFlags = 0x1
        startupinfo.wShowWindow = 0x0
        
        startupinfo.cb = sizeof(startupinfo)
        if kernel32.CreateProcessA(path, None, None, None, None, creation_flags, None, None, byref(startupinfo), byref(procinfo)):
            print "[*] Process successfully launched!"
            print "[*] PID: %d" % procinfo.dwProcessId
            self.pid = procinfo.dwProcessId
            self.h_process = self.open_process(procinfo.dwProcessId)
            self.debugger_active = True
        else:
            print "[*] Error: 0x%08x." % kernel32.GetLastError()
    
    # Function to open the process
    def open_process(self,pid):
        h_process = kernel32.OpenProcess(PROCESS_ALL_ACCESS, False, pid) 
        return h_process
    
    # Attach a process to the debugger and set the flag debugger_active to true if it worked
    def attach(self, pid):    
        self.h_process = self.open_process(pid)
        if self.h_process == 0:
            print "[*] Error: 0x%08x." % kernel32.GetLastError()
            
        if kernel32.DebugActiveProcess(pid):
            self.debugger_active = True
            self.pid = int(pid)             
        else:
            print "[*] Unable to attach to the process."
            print "[*] Error: 0x%08x." % kernel32.GetLastError()
    
    # Loop of the debugger while the flag debugger_active is set to true
    def run(self):        
        while self.debugger_active == True:
            self.get_debug_event() 
    
    # Function to get a debug event
    def get_debug_event(self):
        debug_event = DEBUG_EVENT()
        continue_status = DBG_CONTINUE
        
        if kernel32.WaitForDebugEvent(byref(debug_event), INFINITE):
            self.h_thread = self.open_thread(debug_event.dwThreadId)
            self.context = self.get_thread_context(h_thread=self.h_thread)
            self.debug_event = debug_event
            #print "Event Code: %d Thread ID: %d" % (debug_event.dwDebugEventCode,debug_event.dwThreadId)
            
            if debug_event.dwDebugEventCode == EXCEPTION_DEBUG_EVENT:
                self.exception = debug_event.u.Exception.ExceptionRecord.ExceptionCode
                self.exception_address = debug_event.u.Exception.ExceptionRecord.ExceptionAddress
                
                if self.exception == EXCEPTION_ACCESS_VIOLATION:
                    print "Access violation detected."
                elif self.exception == EXCEPTION_BREAKPOINT:
                    continue_status = self.exception_handler_breakpoint()
                elif self.exception == EXCEPTION_GUARD_PAGE:
                    print "Guard page access detected."
                elif self.exception == EXCEPTION_SINGLE_STEP:
                    self.exception_handler_single_step()

                self.prompt()
                
            kernel32.ContinueDebugEvent(debug_event.dwProcessId, debug_event.dwThreadId, continue_status)
    
    # Detach the process of the debugger         
    def detach(self):
        if kernel32.DebugActiveProcessStop(self.pid):
            print "[*] Finished debugging. Exiting..."
            return True
        else:
            print "There was an error"
            return False
     
    # Open one of the thread of the process we want to debug in order to get its CPU context (stack + registers)   
    def open_thread (self, thread_id):
        h_thread = kernel32.OpenThread(THREAD_ALL_ACCESS, None, thread_id)
        
        if h_thread is not None:
            return h_thread
        else:
            print "[*] Could not obtain a valid thread handle."
            return False
    
    # Enumerate all the threads of the debuggee and return a list of its threads   
    def enumerate_threads(self):
        thread_entry = THREADENTRY32()
        thread_list = []
        snapshot = kernel32.CreateToolhelp32Snapshot(TH32CS_SNAPTHREAD, self.pid)
        
        if snapshot is not None:
            thread_entry.dwSize = sizeof(thread_entry)
            success = kernel32.Thread32First(snapshot, byref(thread_entry))
            
            while success:
                if thread_entry.th32OwnerProcessID == self.pid:
                    thread_list.append(thread_entry.th32ThreadID)
                success = kernel32.Thread32Next(snapshot, byref(thread_entry))
            
            kernel32.CloseHandle(snapshot)
            return thread_list
        else:
            return False
    
    # Get a particular thread context
    def get_thread_context (self, thread_id=None,h_thread=None):    
        context = CONTEXT()
        context.ContextFlags = CONTEXT_FULL | CONTEXT_DEBUG_REGISTERS
        
        # Obtain a handle to the thread
        if h_thread is None:
            self.h_thread = self.open_thread(thread_id)
                        
        if kernel32.GetThreadContext(self.h_thread, byref(context)):
            return context 
        else:
            return False    
    
    # Read process memory to be able to save the byte replaced by the INT3 when a breakpoint is set 
    def read_process_memory(self,address,length):    
        data = ""
        read_buf = create_string_buffer(length)
        count = c_ulong(0)
        
        kernel32.ReadProcessMemory(self.h_process, address, read_buf, 5, byref(count))
        data = read_buf.raw
        
        return data
    
    # Write process memory to be able to write the INT3 where the breakpoint is set
    def write_process_memory(self,address,data):
        count  = c_ulong(0)
        length = len(data)
        
        c_data = c_char_p(data[count.value:])
        print c_data
        if not kernel32.WriteProcessMemory(self.h_process, address, c_data, length, byref(count)):
            return False
        else:
            return True
    
    def bp_set(self,address):
        print "[*] Setting breakpoint at: 0x%08x" % address
        if not self.breakpoints.has_key(address):
            # store the original byte
            old_protect = c_ulong(0)
            kernel32.VirtualProtectEx(self.h_process, address, 1, PAGE_EXECUTE_READWRITE, byref(old_protect))          
            original_byte = self.read_process_memory(address, 1)
            if original_byte != False:
                # write the INT3 opcode (0xCC)
                if self.write_process_memory(address, "\xCC"):
                    # register the breakpoint in our internal list
                    self.breakpoints[address] = (original_byte)
                    return True
            else:
                return False

    def show_registers(self):
        print "[*] Dumping registers for thread ID: 0x%08x" % self.h_thread
        print "[**] EIP: 0x%08x" % self.context.Eip
        print "[**] ESP: 0x%08x" % self.context.Esp
        print "[**] EBP: 0x%08x" % self.context.Ebp
        print "[**] EAX: 0x%08x" % self.context.Eax
        print "[**] EBX: 0x%08x" % self.context.Ebx
        print "[**] ECX: 0x%08x" % self.context.Ecx
        print "[**] EDX: 0x%08x" % self.context.Edx
        print "[**] EDI: 0x%08x" % self.context.Edi
        print "[**] ESI: 0x%08x" % self.context.Esi
        print "[**] EFLAGS: " + bin(self.context.EFlags)
        
    def exception_handler_breakpoint(self):
        print "[*] Exception address: 0x%08x" % self.exception_address
        # check if the breakpoint is one that we set
        if not self.breakpoints.has_key(self.exception_address):
            # if it is the first Windows driven breakpoint
            # then let's just continue on
            if self.first_breakpoint == True:
                self.first_breakpoint = False
                print "[*] Hit the first breakpoint."
                return DBG_CONTINUE
        else:
            print "[*] Hit user defined breakpoint."
            # this is where we handle the breakpoints we set 
            # first put the original byte back
            self.write_process_memory(self.exception_address, self.breakpoints[self.exception_address])

            # obtain a fresh context record, reset EIP back to the 
            # original byte and then set the thread's context record
            # with the new EIP value
            self.context = self.get_thread_context(h_thread=self.h_thread)
            self.context.Eip -= 1
            
            kernel32.SetThreadContext(self.h_thread,byref(self.context))
            
            continue_status = DBG_CONTINUE

        return continue_status 
    
    # Get the memory address of a specific function
    def func_resolve(self,dll,function):
        handle  = kernel32.GetModuleHandleA(dll)
        address = kernel32.GetProcAddress(handle, function)
        
        kernel32.CloseHandle(handle)

        return address
    
    def bp_set_hw(self, address, length, condition):
        
        # Check for a valid length value
        if length not in (1, 2, 4):
            return False
        else:
            length -= 1
            
        # Check for a valid condition
        if condition not in (HW_ACCESS, HW_EXECUTE, HW_WRITE):
            return False
        
        # Check for available slots
        if not self.hardware_breakpoints.has_key(0):
            available = 0
        elif not self.hardware_breakpoints.has_key(1):
            available = 1
        elif not self.hardware_breakpoints.has_key(2):
            available = 2
        elif not self.hardware_breakpoints.has_key(3):
            available = 3
        else:
            return False

        # We want to set the debug register in every thread
        for thread_id in self.enumerate_threads():
            context = self.get_thread_context(thread_id=thread_id)

            # Enable the appropriate flag in the DR7
            # register to set the breakpoint
            context.Dr7 |= 1 << (available * 2)

            # Save the address of the breakpoint in the
            # free register that we found
            if   available == 0: context.Dr0 = address
            elif available == 1: context.Dr1 = address
            elif available == 2: context.Dr2 = address
            elif available == 3: context.Dr3 = address

            # Set the breakpoint condition
            context.Dr7 |= condition << ((available * 4) + 16)

            # Set the length
            context.Dr7 |= length << ((available * 4) + 18)

            # Set this threads context with the debug registers
            # set
            h_thread = self.open_thread(thread_id)
            kernel32.SetThreadContext(h_thread,byref(context))

        # update the internal hardware breakpoint array at the used slot index.
        self.hardware_breakpoints[available] = (address,length,condition)

        return True
    
    def exception_handler_single_step(self):
        print "[*] Exception address: 0x%08x" % self.exception_address
        # Comment from PyDbg:
        # determine if this single step event occurred in reaction to a hardware breakpoint and grab the hit breakpoint.
        # according to the Intel documentation, we should be able to check for the BS flag in Dr6. but it appears that windows
        # isn't properly propagating that flag down to us.
        slot = None
        if self.context.Dr6 & 0x1 and self.hardware_breakpoints.has_key(0):
            slot = 0
        elif self.context.Dr6 & 0x2 and self.hardware_breakpoints.has_key(1):
            slot = 1
        elif self.context.Dr6 & 0x4 and self.hardware_breakpoints.has_key(2):
            slot = 2
        elif self.context.Dr6 & 0x8 and self.hardware_breakpoints.has_key(3):
            slot = 3
        else:
            # This wasn't an INT1 generated by a hw breakpoint
            continue_status = DBG_CONTINUE

        # Now let's remove the breakpoint from the list
        if slot:
            if self.bp_del_hw(slot):
                continue_status = DBG_CONTINUE
                print "[*] Hardware breakpoint removed."
                
        return continue_status
    
    def bp_del_hw(self,slot):
        
        # Disable the breakpoint for all active threads
        for thread_id in self.enumerate_threads():

            context = self.get_thread_context(thread_id=thread_id)
            
            # Reset the flags to remove the breakpoint
            context.Dr7 &= ~(1 << (slot * 2))

            # Zero out the address
            if   slot == 0: 
                context.Dr0 = 0x00000000
            elif slot == 1: 
                context.Dr1 = 0x00000000
            elif slot == 2: 
                context.Dr2 = 0x00000000
            elif slot == 3: 
                context.Dr3 = 0x00000000

            # Remove the condition flag
            context.Dr7 &= ~(3 << ((slot * 4) + 16))

            # Remove the length flag
            context.Dr7 &= ~(3 << ((slot * 4) + 18))

            # Reset the thread's context with the breakpoint removed
            h_thread = self.open_thread(thread_id)
            kernel32.SetThreadContext(h_thread,byref(context))
            
        # remove the breakpoint from the internal list.
        del self.hardware_breakpoints[slot]

        return True
    
    def bp_set_mem(self, address, size):
        
        mbi = MEMORY_BASIC_INFORMATION()
        
        # Attempt to discover the base address of the memory page
        if kernel32.VirtualQueryEx(self.h_process, address, byref(mbi), sizeof(mbi)) < sizeof(mbi):
            return False

    
        current_page = mbi.BaseAddress
    
        # We will set the permissions on all pages that are
        # affected by our memory breakpoint.
        while current_page <= address + size:
        
            # Add the page to the list, this will
            # differentiate our guarded pages from those
            # that were set by the OS or the debuggee process
            self.guarded_pages.append(current_page)
            
            old_protection = c_ulong(0)
            if not kernel32.VirtualProtectEx(self.h_process, current_page, size, mbi.Protect | PAGE_GUARD, byref(old_protection)):
                return False
         
            # Increase our range by the size of the
            # default system memory page size
            current_page += self.page_size
    
        # Add the memory breakpoint to our global list
        self.memory_breakpoints[address] = (address, size, mbi)
    
        return True
    
    def anti_dbg(self):
        # Step 1 & 2: Set the flag BeingDebugged in the PEB structure to 0
        pbi = PROCESS_BASIC_INFORMATION()
        len_out = 0
        return_val = ntdll.NtQueryInformationProcess(self.h_process, 0, byref(pbi), sizeof(pbi), None)
        if (return_val != 0):
            print "[*] Failed to query information process, error code 0x%08x" % return_val
        #print "Output: %d" % len_out
        #print "PEB base address: 0x%08x" % int(pbi.PebBaseAddress)
        if (self.write_process_memory(pbi.PebBaseAddress+0x2, "\x00")):
            print "[*] PEB anti-debug flag set to 0."
        else:
            print "[*] Unable to set the PEB anti-debug flag to 0."

    def single_step(self):
        context = self.context
        context.EFlags += 256
        kernel32.SetThreadContext(self.h_thread,byref(context))
        return True

    def modify_general_register(self, register, data):
        context = self.context
        if register == "eax":
            context.Eax = data
        elif register == "ebx":
            context.Ebx = data
        elif register == "ecx":
            context.Ecx = data
        elif register == "edx":
            context.Edx = data
        elif register == "esp":
            context.Esp = data
        elif register == "ebp":
            context.Ebp = data
        elif register == "esi":
            context.Esi = data
        elif register == "edi":
            context.Esi = data
        else:
            return False
        kernel32.SetThreadContext(self.h_thread,byref(context))
        return True

    def prompt(self):
        while True:
            cmd = raw_input(hex(self.context.Eip) + ">")
            scmd = cmd.split()
            if scmd:
                if scmd[0] == "bs":
                    self.bp_set(int(scmd[1],0))
                elif scmd[0] == "r":
                    data = self.read_process_memory(int(scmd[1],0),int(scmd[2],0))
                    print "Data: %s" % " ".join(x.encode('hex') for x in data)
                elif scmd[0] == "w":
                    self.write_process_memory(int(scmd[1],0),str(scmd[2].decode('hex')))
                elif scmd[0] == "m":
                    self.modify_general_register(scmd[1],int(scmd[1],0))
                elif scmd[0] == "sc":
                    self.show_registers()
                elif scmd[0] == "s":
                    self.single_step()
                    break
                elif scmd[0] == "c":
                    break
                elif scmd[0] == "e":
                    sys.exit()
                elif scmd[0] == "h":
                    print "Commands availables:"
                    print "- Sofware breakpoint: bp [address]"
                    print "- Read memory at: r [address] [size]"
                    print "- Write memory at: w [address] [data]"
                    print "- Modify register: m [register] [data]"
                    print "- Show the context: sc"
                    print "- Single step exectution: s"
                    print "- Continue to execute: c"
                    print "- Exit the debugger: e"
                    print "- Print the help menu: h"
            
            
        
        
