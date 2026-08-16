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

fn main() -> Result<(), Box<dyn Error>> {
    //1. Setup Channel for communication between tracer thread and UI thread
    let (rx, tx) = mpsc::channel();

    //2. Fork and start the tracer
    match unsafe { fork() }? {
        ForkResult::Parent { child } => {
            thread::spawn(move || run_tracer(child, tx));
        }
        ForkResult::Child => {
            run_target_process();
            return Ok(());
        }
    }

    //3. Setting up the UI
    enable_raw_mode()?;
    let mut stdout = io::stdout();
    execute!(stdout, EnterAlternateScreen)?;
    let mut terminal = Terminal::new(CrosstermBackend::new(stdout))?;

    let mut app_state = AppState {
        syscall_name: "NONE".to_string(),
        rax: 0,
        rdi: 0,
        state: SyscallState::UserSpace,
        history: Vec::new(),
    };

    // Main UI Loop
    loop {}

    Ok(())
}

fn run_tracer(child: Pid, tx: mpsc::Sender<AppState>) {
    waitpid(child, None).unwrap(); // Wait for the child process to exit
    let mut in_syscall = false;
    let mut history = Vec::new();

    loop {
        // Wait for the next syscall event
        ptrace::syscall(child, None).unwrap();

        match waitpid(child, None).unwrap() {
            WaitStatus::PtraceSyscall(_) => {
                let regs = ptrace::getregs(child).unwrap();
                if !in_syscall {
                    in_syscall = true;
                    let name = format!("Syscall: {}", regs.rax);
                    history.push(format!("Entered: {}", name));
                    let _ = tx.send(AppState {
                        syscall_name: name,
                        rax: regs.rax,
                        rdi: regs.rdi,
                        state: SyscallState::EnteringKernel,
                        history: history.clone(),
                    });
                    // slow down UI to make it easier to read
                    thread::sleep(Duration::from_millis(400));
                } else {
                    // Exit Point
                    in_syscall = false;
                    history.push(format!("Result: {}", regs.rax));
                    let _ = tx.send(AppState {
                        syscall_name: "RETURNING".into(),
                        rax: regs.rax,
                        rdi: regs.rdi,
                        state: SyscallState::ExitingKernel,
                        history: history.clone(),
                    });
                    thread::sleep(Duration::from_millis(400));
                }
            }
            WaitStatus::Exited(_, _) => break,
            _ => {}
        }
    }
}
