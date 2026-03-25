use crate::println;
use alloc::collections::vec_deque::VecDeque;
use alloc::vec::Vec;
use core::arch::global_asm;
use spin::Mutex;

global_asm!(include_str!("switch.s"), options(att_syntax));

unsafe extern "C" {
    fn context_switch(old_rsp: *mut usize, new_rsp: usize);
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum TaskState {
    Ready,
    Running,
    Blocked,
}

pub struct Task {
    pub id: usize,
    pub thread_id: usize,
    pub rsp: usize,
    pub state: TaskState,
    pub stack: Vec<u8>,
}

impl Task {
    pub fn new(id: usize, thread_id: usize, entry: extern "C" fn() -> !) -> Self {
        let mut task = Self {
            id,
            thread_id,
            rsp: 0,
            state: TaskState::Ready,
            stack: alloc::vec![0; 4096 * 4],
        };

        let stack_top = task.stack.as_ptr() as usize + task.stack.len();
        let rsp = stack_top;
        
        println!("TASK: stack_base={:p}, stack_top={:p}, entry={:#x}", task.stack.as_ptr(), stack_top as *const u8, entry as usize);

        // Push initial state onto stack as if it was saved by context_switch
        // registers: r15, r14, r13, r12, rbp, rbx, rip
        let _registers = [
            0,              // r15
            0,              // r14
            0,              // r13
            0,              // r12
            0,              // rbp
            0,              // rbx
            entry as usize, // rip
        ];

        unsafe {
            let stack_ptr = (rsp - 7 * core::mem::size_of::<usize>()) as *mut usize;
            for i in 0..6 {
                stack_ptr.add(i).write(0);
            }
            stack_ptr.add(6).write(entry as usize);
            task.rsp = stack_ptr as usize;
        }

        task
    }
}

pub struct Scheduler {
    pub tasks: VecDeque<Task>,
    pub current_task: Option<Task>,
}

impl Scheduler {
    pub const fn new() -> Self {
        Self {
            tasks: VecDeque::new(),
            current_task: None,
        }
    }

    pub fn add_task(&mut self, task: Task) {
        self.tasks.push_back(task);
    }

    pub fn schedule(&mut self) {
        if self.tasks.is_empty() {
            return;
        }

        // Get the next task
        let mut next_task = self.tasks.pop_front().unwrap();
        next_task.state = TaskState::Running;
        let next_rsp = next_task.rsp;

        // Save old task and get its RSP pointer
        static mut DUMMY_RSP: usize = 0;
        let old_rsp_ptr: *mut usize = if let Some(mut prev) = self.current_task.take() {
            prev.state = TaskState::Ready;
            self.tasks.push_back(prev);
            // The task is now at the back of the queue. We need a pointer to its rsp.
            &mut self.tasks.back_mut().unwrap().rsp
        } else {
            // First run
            unsafe { &raw mut DUMMY_RSP }
        };
        
        // Make next_task the current one
        self.current_task = Some(next_task);

        unsafe {
            // Debug: print the stack we're about to switch to
            let ptr = next_rsp as *const usize;
            println!("SWITCH: next_rsp={:#x}, rip={:#x}, rbx={:#x}", 
                next_rsp, 
                ptr.add(6).read(),
                ptr.add(5).read()
            );

            x86_64::instructions::interrupts::without_interrupts(|| {
                context_switch(old_rsp_ptr, next_rsp);
            });
        }
    }
}

pub static SCHEDULER: Mutex<Scheduler> = Mutex::new(Scheduler::new());
