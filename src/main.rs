use crossterm::{
    event::{self, Event, KeyCode},
    execute,
    terminal::{EnterAlternateScreen, LeaveAlternateScreen, disable_raw_mode, enable_raw_mode},
};
use nix::{
    sys::{
        ptrace,
        wait::{WaitStatus, waitpid},
    },
    unistd::Pid,
};
use ratatui::{prelude::*, widgets::*};
use std::{error::Error, io, sync::mpsc, thread, time::Duration};

#[derive(Debug, Clone)]
enum SyscallState {
    UserSpace,      // Running in User Mode
    EnteringKernel, // Just executed 'syscall'
    InService,      // Kernel is processing
    ExitingKernel,  // Just before returning to User
}

struct AppState {
    syscall_name: String,
    rax: u64,
    rdi: u64,
    state: SyscallState,
    history: Vec<String>,
}
