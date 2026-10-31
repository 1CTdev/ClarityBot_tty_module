//! Test application that calls tty_module exported functions directly

use std::thread;
use std::time::Duration;

// Link against the tty_module library
use tty_module::{launch, stdin, stdout, signal_terminal};

fn main() {
    println!("=== TTY Module Library Test ===\n");
    
    unsafe {
        test_tty_lib();
    }
}

unsafe fn test_tty_lib() {
    let label: u32 = 1; // Session ID
    let mut flags: u16 = 0;
    
    // Terminal size: 80x24
    let size_data: [u8; 4] = [80, 0, 24, 0]; // cols=80, rows=24 as little-endian u16s
    
    println!("[TEST] Calling launch() with label={}", label);
    
    let mut out: usize = 0;
    let mut out_size: usize = 0;
    
    let result = launch(
        &mut flags,
        label,
        size_data.as_ptr() as *const usize,
        size_data.len(),
        &mut out,
        &mut out_size,
    );
    
    if result != 0 {
        println!("[TEST] launch() FAILED with result: {}", result);
        return;
    }
    
    println!("[TEST] launch() SUCCESS! Session {} created", label);
    
    // Wait a moment for cmd.exe to start and produce output
    println!("\n[TEST] Waiting 500ms for terminal to initialize...");
    thread::sleep(Duration::from_millis(500));
    
    // Poll stdout a few times to get initial output
    println!("\n[TEST] Polling stdout()...");
    for i in 0..10 {
        let mut out: usize = 0;
        let mut out_size: usize = 0;
        
        let result = stdout(
            &mut flags,
            label,
            std::ptr::null(),
            0,
            &mut out,
            &mut out_size,
        );
        
        println!("[TEST] stdout() poll {}: result={}, out_size={}", i + 1, result, out_size);
        
        if result == 0 && out_size > 0 {
            let data = std::slice::from_raw_parts(out as *const u8, out_size);
            println!("[TEST] Received {} bytes:", out_size);
            println!("--- OUTPUT START ---");
            print!("{}", String::from_utf8_lossy(data));
            println!("--- OUTPUT END ---");
            
            // Free the buffer (it was allocated by VirtualAlloc)
            windows_sys::Win32::System::Memory::VirtualFree(
                out as *mut _,
                0,
                windows_sys::Win32::System::Memory::MEM_RELEASE,
            );
        }
        
        if out_size > 0 {
            break; // Got output, continue with test
        }
        
        thread::sleep(Duration::from_millis(100));
    }
    
    // Send a command via stdin
    println!("\n[TEST] Sending 'dir' command via stdin()...");
    let cmd = b"dir\r\n";
    
    let result = stdin(
        &mut flags,
        label,
        cmd.as_ptr() as *const usize,
        cmd.len(),
        &mut out,
        &mut out_size,
    );
    
    println!("[TEST] stdin() result: {}", result);
    
    if result != 0 {
        println!("[TEST] stdin() FAILED!");
    } else {
        println!("[TEST] stdin() SUCCESS! Sent {} bytes", cmd.len());
    }
    
    // Wait for command to execute
    println!("\n[TEST] Waiting 500ms for command output...");
    thread::sleep(Duration::from_millis(500));
    
    // Poll stdout for the response
    println!("\n[TEST] Polling stdout() for response...");
    for i in 0..10 {
        let mut out: usize = 0;
        let mut out_size: usize = 0;
        
        let result = stdout(
            &mut flags,
            label,
            std::ptr::null(),
            0,
            &mut out,
            &mut out_size,
        );
        
        println!("[TEST] stdout() poll {}: result={}, out_size={}", i + 1, result, out_size);
        
        if result == 0 && out_size > 0 {
            let data = std::slice::from_raw_parts(out as *const u8, out_size);
            println!("[TEST] Received {} bytes:", out_size);
            println!("--- OUTPUT START ---");
            print!("{}", String::from_utf8_lossy(data));
            println!("--- OUTPUT END ---");
            
            // Free the buffer
            windows_sys::Win32::System::Memory::VirtualFree(
                out as *mut _,
                0,
                windows_sys::Win32::System::Memory::MEM_RELEASE,
            );
        }
        
        thread::sleep(Duration::from_millis(100));
    }
    
    // Send exit command
    println!("\n[TEST] Sending 'exit' command...");
    let exit_cmd = b"exit\r\n";
    
    stdin(
        &mut flags,
        label,
        exit_cmd.as_ptr() as *const usize,
        exit_cmd.len(),
        &mut out,
        &mut out_size,
    );
    
    thread::sleep(Duration::from_millis(500));
    
    // Terminate the session via signal
    println!("\n[TEST] Sending terminate signal...");
    let terminate_signal: [u8; 1] = [0]; // Signal type 0 = terminate
    
    let result = signal_terminal(
        &mut flags,
        label,
        terminate_signal.as_ptr() as *const usize,
        terminate_signal.len(),
        &mut out,
        &mut out_size,
    );
    
    println!("[TEST] signal(terminate) result: {}", result);
    
    println!("\n[TEST] Done!");
}