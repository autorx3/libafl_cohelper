//! The symccstage is for using symcc/symqemu to spawn a child and collect information
use alloc::{
    borrow::{Cow, ToOwned},
    string::ToString,
};

use core::{fmt::Debug, marker::PhantomData};
use std::{env, os::unix::process::ExitStatusExt};
use libafl_bolts::Named;
use std::process::{Child, Command, Stdio};
use std::vec::Vec;
use std::{
    path::PathBuf,
    time::Instant,
    fs,
};
use std::string::String;

use std::sync::{LazyLock,Mutex};
use std::hash::Hasher;
use std::collections::HashSet;
use std::collections::hash_map::DefaultHasher;

//use crate::inputs::BytesInput;
#[allow(unused_imports)]
use crate::{
    Error, HasNamedMetadata,Evaluator,HasMetadata,
    corpus::{HasCurrentCorpusId,HasTestcase},
    executors::{Executor, HasObservers},
    inputs::{Input,HasMutatorBytes},
    mark_feature_time,
    observers::ObserversTuple,
    stages::{Restartable, RetryCountRestartHelper, Stage},
    start_timer,
    state::{HasCorpus, HasCurrentTestcase, HasSymCompleted,HasExecutions,
        HasSymimQueue,MaybeHasClientPerfMonitor},
};

const TIMEOUT:u32 = 90;
const MAX_CONCURRENT_TASKS: usize = 1;
/// for random delay
//static mut DELAY_COUNTER: usize = 0;

/// for symcc output dir
static mut SYMCC_OUTID :usize = 0;

/// check senn inputs
static SEEN_INPUTS: LazyLock<Mutex<HashSet<u64>>> = LazyLock::new(|| {
    Mutex::new(HashSet::new())
});

#[derive(Debug)]
struct SymCCTask {
    output_path: PathBuf,
    is_completed: bool,
    start_time: Instant,
    exec_time:u32,
    child:Option<Child>,
}

/// symccstage
#[derive(Debug)]
pub struct SymCCStage<E, EM, I, S, Z> {
    name:Cow<'static,str>,
    target_program: Vec<String>,
    pending_tasks: Vec<SymCCTask>,
    phantom:PhantomData<(E, EM, I, S, Z)>,
}

impl<E, EM, I, S, Z> Named for SymCCStage<E, EM, I, S, Z>{
    fn name(&self) -> &Cow<'static, str>{
        &self.name
    }
}

impl<E, EM, I, S, Z> Stage<E, EM, S, Z> for SymCCStage<E, EM, I, S, Z>
where
    Z: Evaluator<E, EM, I, S>,
    I: Input + HasMutatorBytes,
    S: HasExecutions
        + HasCorpus<I>
        + HasMetadata
        + HasNamedMetadata
        + HasTestcase<I>
        + HasSymCompleted
        + HasSymimQueue
        + HasCurrentTestcase<I>
        + MaybeHasClientPerfMonitor
        + HasCurrentCorpusId,
{
    #[inline]
    fn perform(
        &mut self,
        fuzzer: &mut Z,
        executor: &mut E,
        state: &mut S,
        manager: &mut EM,
    ) -> Result<(), Error> {

        let is_completed = *state.is_symcompleted();
        if !is_completed{
            self.process_results(fuzzer, executor, state, manager)?;
            return Ok(());
        }
        //
        {
            start_timer!(state);
            mark_feature_time!(state,PerfFeature::GetInputFromCorpus);
        }

        // here to get input from symim_queue 
        // always has an input
        let input = if !state.symim_queue().is_empty() {
            let id = state.symim_pop().unwrap();
            match state.testcase_mut(id)?.input_owned() {
                Some(i) => {
                    println!("symim_queue pop testcase!");
                    i
                }, 
                None => {
                    println!("Error: Cannot find the id corresponding testcase & input (id: {})", id);
                    state.current_input_cloned()? 

                }
            }
        } else {
            println!("symim_queue is empty so get the current_input_cloned()!");
            state.current_input_cloned()? 
        };

        //hashmap input 
        let hash = {
            let mut hasher = DefaultHasher::new();
            input.hash(&mut hasher);
            hasher.finish()
        };
        let should_spawn = {
            let mut set = SEEN_INPUTS.lock().unwrap();
            if set.contains(&hash) {
                println!("the input:{} has been executed by symcc",hash);
                false 
            } else {
                println!("the input:{} will be executed by symcc",hash);
                set.insert(hash);
                println!("Inserted, set size now: {}", set.len());
                true   
            }
        };

        if should_spawn{
            self.spawn_symcc(state,&input)?;
        }
        self.process_results(fuzzer, executor, state, manager)?;

        Ok(())
    }
}


impl<E, EM, I, S, Z> Restartable<S> for SymCCStage<E, EM, I, S, Z>
where
    S: HasNamedMetadata + HasCurrentCorpusId,
{
    fn should_restart(&mut self, state: &mut S) -> Result<bool, Error> {
        RetryCountRestartHelper::no_retry(state, &self.name)
    }

    fn clear_progress(&mut self, state: &mut S) -> Result<(), Error> {
        RetryCountRestartHelper::clear_progress(state, &self.name)
    }
}

#[allow(dead_code)]
/// The counter for giving this stage unique id
static mut SYMCC_STAGE_ID: usize = 0;
#[allow(dead_code)]
/// The name for tracing stage
pub static SYMCC_STAGE_NAME: &str = "symccstage";

#[allow(dead_code)]
impl<E, EM, I, S, Z> SymCCStage<E, EM, I, S, Z>
where
    Z: Evaluator<E, EM, I, S>,
    I: Input + HasMutatorBytes,
    S: HasExecutions
        + HasCorpus<I>
        + HasMetadata
        + HasNamedMetadata
        + HasSymCompleted
        + HasSymimQueue
        + HasCurrentTestcase<I>
        + MaybeHasClientPerfMonitor
        + HasCurrentCorpusId,
{   
    /// new a symccstage
    pub fn new(target_program: String) -> Result<Self, Error> {

        let stage_id = unsafe {
            let ret = SYMCC_STAGE_ID;
            SYMCC_STAGE_ID += 1;
            ret
        };

        let words: Vec<String> = target_program
            .split_whitespace() 
            .map(|s| s.to_string())  
            .collect();

        Ok(Self {
            name: Cow::Owned(SYMCC_STAGE_NAME.to_owned() + ":" + stage_id.to_string().as_ref()),
            target_program:words,
            pending_tasks: Vec::with_capacity(32), 
            phantom:PhantomData,
        })
    }

    fn spawn_symcc(&mut self, state: &mut S,input: &I) -> Result<(), Error> {
        if self.pending_tasks.len() >= MAX_CONCURRENT_TASKS{
            return Ok(());
        }
        let current_dir: PathBuf = env::current_dir()?;

        let id = unsafe{SYMCC_OUTID};
        let lastdir = current_dir.join(format!("out/symcc_output_{}", id ));
        unsafe{
            SYMCC_OUTID +=1;
        }

        fs::create_dir_all(&lastdir)?;
        let input_path = lastdir.join("cur_input");
        input.to_file(&input_path)?;

        let output_dir = lastdir.join("output");
        fs::create_dir_all(&output_dir)?;

        let mut task = SymCCTask {
            output_path: output_dir.clone(),
            is_completed: false,
            start_time: Instant::now(),
            exec_time:0,
            child:None,
        };

        let mut analysis_command = Command::new("timeout");
        analysis_command
            .args(&["-k", "5", &TIMEOUT.to_string()])
            .args(&self.target_program)
            .arg(&input_path)
            .env("SYMCC_ENABLE_LINEARIZATION", "1")
            .env("SYMCC_INPUT_FILE", &input_path)
            .env("SYMCC_OUTPUT_DIR", &output_dir)
            .stdout(Stdio::piped())
            .stderr(Stdio::piped());


        println!("Running SymCC as follows: {:?}", &analysis_command);

        let output = analysis_command.output()?; 

        println!("Status: {:?}", output.status.signal());
        println!("Stdout: {}", String::from_utf8_lossy(&output.stdout));
        println!("Stderr: {}", String::from_utf8_lossy(&output.stderr));

        let sym_child = match analysis_command.spawn() {
            Ok(child) => {
                *state.is_symcompleted_mut() = false;
                println!("Child process started with id: {:?}", child.id());
                child 
            }
            Err(e) => {
                eprintln!("Failed to start child process: {}", e);
                return Err(e.into());
            }
        };

        task.child = Some(sym_child);
        // todo when child is None
        self.pending_tasks.push(task);

        Ok(())
    }

    fn process_results(
        &mut self,
        fuzzer: &mut Z,
        executor: &mut E,
        state: &mut S,
        manager: &mut EM,
    ) -> Result<(), Error> {
        for task in &mut self.pending_tasks {
            if let Some(child) = &mut task.child {
                match child.try_wait() {
                    Ok(Some(_status)) => {//finished
                        println!("symcc/symqemu exec finished!");

                        if let Some(mut child) = task.child.take() {
                            let _ = child.kill();
                            let _ = child.wait();
                        }
        
                        task.exec_time = task.start_time.elapsed().as_secs() as u32;
                        println!("Task completed in {} sec", task.exec_time);
        
                        let entries = match fs::read_dir(&task.output_path) {
                            Ok(read_dir) => read_dir, 
                            Err(err) => {
                                eprintln!("cannot read the output_dir {}: {}", task.output_path.display(), err);
                                return Err(err.into()); 
                            }
                        };

                        let mut cnt = 0;

                        for entry in entries {
                            let path = entry?.path();

                            if path.to_string_lossy().contains("constraint") {
                                continue;
                            }
                            
                            if path.is_file() {
                                let solved_input = I::from_file(&path)?;

                                cnt +=1;
                                println!("completed output_dir testcase :{}", cnt);

                                //let bytes = solved_input.mutator_bytes_mut();
                                //let end = 20.min(bytes.len());
                                //println!("First {} bytes: {:?}", end, &bytes[..end]);
            
                                fuzzer.evaluate_filtered(state, executor, manager, &solved_input)?;
                            }
                        }
                        task.is_completed = true;
                        *state.is_symcompleted_mut() = true;
                    }
                    Ok(None) => {
                        if task.start_time.elapsed().as_secs() > TIMEOUT.into() {
                            println!("!!!TIMEOUT after {} seconds", TIMEOUT);
                            if let Some(mut child) = task.child.take() {
                                let _ = child.kill();
                                let _ = child.wait();
                            }
                            task.is_completed = true;
                            *state.is_symcompleted_mut() = true;
                        }
                        println!("symcc child is still running!");
                    }
                    Err(e) => {//error
                        println!("Failed to check process status: {}", e);
                        if let Some(mut child) = task.child.take() {
                            let _ = child.kill();
                            let _ = child.wait();
                        }
                        task.is_completed = true;
                        *state.is_symcompleted_mut() = true;
                    }
                }
            }
        }
        self.pending_tasks.retain(|t| !t.is_completed);
        Ok(())
    }

}

