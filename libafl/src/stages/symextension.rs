//! The symccstage is for using symcc/symqemu to spawn a child and collect information
use alloc::{
    borrow::{Cow, ToOwned},
    string::ToString,
};
use core::{fmt::Debug, marker::PhantomData};

use libafl_bolts::Named;

#[allow(unused_imports)]
use std::{env, os::unix::process::ExitStatusExt};
#[allow(unused_imports)]
use std::process::{Child, Command, Stdio};
use std::vec::Vec;
use std::{
    path::PathBuf,
    fs,
};
use std::fs::read_to_string;
use std::string::String;
#[allow(unused_imports)]
use z3::{
    Config, Context, Solver, Symbol,Params,
    ast::{Ast, BV, Bool, Dynamic},
};

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
    state::{HasCorpus, HasCurrentTestcase,HasExecutions,
        MaybeHasClientPerfMonitor},
};


/// for symcc output dir
static mut SYMCC_EXTENSION_ID :usize = 0;

/// symccstage
#[derive(Clone,Debug)]
pub struct SymExtensionStage<E, EM, I,S, Z> {
    name:Cow<'static,str>,
    phantom:PhantomData<(E, EM, I,S, Z)>,
}

impl<E, EM, I,S, Z> Named for SymExtensionStage<E, EM, I,S, Z>{
    fn name(&self) -> &Cow<'static, str>{
        &self.name
    }
}

impl<E, EM, I,S, Z> Stage<E, EM, S, Z> for SymExtensionStage<E, EM, I,S, Z>
where
    Z: Evaluator<E, EM, I, S>,
    I: Input + HasMutatorBytes + Clone,
    S: HasExecutions
        + HasCorpus<I>
        + HasMetadata
        + HasNamedMetadata
        + HasTestcase<I>
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
        self.symextend(fuzzer, executor, state, manager)?;
        Ok(())
    }
}

impl<E, EM, I,S, Z> Restartable<S> for SymExtensionStage<E, EM, I,S, Z>
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
static mut SYMEXTENSION_STAGE_ID: usize = 0;
#[allow(dead_code)]
/// The name for tracing stage
pub static SYMEXTENSION_STAGE_NAME: &str = "symextensionstage";

#[allow(dead_code)]
impl<E, EM, I, S, Z> SymExtensionStage<E, EM, I,S, Z>
where
    Z: Evaluator<E, EM, I, S>,
    I: Input + HasMutatorBytes + Clone,
    S: HasExecutions
        + HasCorpus<I>
        + HasMetadata
        + HasNamedMetadata
        + HasTestcase<I>
        + HasCurrentTestcase<I>
        + MaybeHasClientPerfMonitor
        + HasCurrentCorpusId,
{   
    /// new a symccstage
    pub fn new() -> Result<Self, Error> {

        let stage_id = unsafe {
            let ret = SYMEXTENSION_STAGE_ID;
            SYMEXTENSION_STAGE_ID += 1;
            ret
        };

        Ok(Self {
            name: Cow::Owned(SYMEXTENSION_STAGE_NAME.to_owned() + ":" + stage_id.to_string().as_ref()),
            phantom:PhantomData,
        })
    }
    fn symextend(
        &mut self,
        fuzzer: &mut Z,
        executor: &mut E,
        state: &mut S,
        manager: &mut EM,
    ) -> Result<(), Error> {
        let symextension_id = unsafe{SYMCC_EXTENSION_ID};

        let current_dir: PathBuf = env::current_dir()?;
        let temp_outdir = current_dir.join(format!("out/symcc_output_{}", symextension_id));

        if temp_outdir.exists() && temp_outdir.is_dir(){
            unsafe {
                SYMCC_EXTENSION_ID+=1;
            }
            // set solver &rand num generator
            let mut cfg = Config::new();
            cfg.set_timeout_msec(10_000);
            let ctx = Context::new(&cfg);
            let solver = Solver::new(&ctx);


            // set input & output_dir
            let input_path = temp_outdir.join("cur_input");
            let outdir = temp_outdir.join("output");

            let input_extended = I::from_file(&input_path)?;

            // get the constraints and collect path string
            let constraint_files: Vec<String> = fs::read_dir(outdir)?
                .filter_map(|entry| {
                    let entry = entry.ok()?;
                    let path = entry.path();
                    if path.is_file() && path.file_name().unwrap_or_default().to_str().unwrap_or("").contains("constraints") {
                        Some(path.display().to_string())
                    } else {
                        None
                    }
                })
                .collect();
            // loop for a single constraint file
            for file in constraint_files {
                solver.push();
                match read_to_string(&file) {
                    Ok(constraints) => {
                        solver.from_string(constraints);
                        println!("load the constraints from string txt");

                        // five loops for a single constraints
                        for _ in 0..5{

                            if solver.check() == z3::SatResult::Sat{
                                // start concolic.rs logic
                                let model = solver.get_model().unwrap();
                                let model_string = model.to_string();

                                let mut replacements = Vec::new();
                                let mut current_assignments = Vec::new();

                                for l in model_string.lines() {
                                    if let [offset_str, value_str] =
                                        l.split(" -> ").collect::<Vec<_>>().as_slice()
                                    {
                                        let offset = offset_str
                                            .trim_start_matches("k!")
                                            .parse::<usize>()
                                            .unwrap();
                                        let value =
                                            u8::from_str_radix(value_str.trim_start_matches("#x"), 16)
                                                .unwrap();
                                        replacements.push((offset, value));
                                        current_assignments.push((offset, value));
                                    } else {
                                        panic!();
                                    }
                                }
                                // copy the input & mutate
                                let mut input_copy = input_extended.clone();
                                for (index, new_byte) in replacements {
                                    /*
                                    if index>= input_copy.len() {continue;}
                                    */
                                    input_copy.mutator_bytes_mut()[index/10] = new_byte;
                                    print!("[{} {}]",index,new_byte);
                                }
                                println!("  the replacements is here");

                                //add random not equal constraint
                                let mut diff_constraints = Vec::new();
                                for (offset, value) in current_assignments {
                                    let var_name = format!("k!{}", offset);
                                    let var = BV::new_const(&ctx, var_name, 8);
                                    let var_value = BV::from_u64(&ctx, value as u64, 8);
                                    diff_constraints.push(var._eq(&var_value).not());
                                }
                                let constraints_ref: Vec<&Bool> = diff_constraints.iter().collect();
                                solver.assert(&Bool::or(&ctx, &constraints_ref));

                                // execute fuzzer
                                fuzzer.evaluate_filtered(state, executor, manager, &input_copy)?;
                            }
                        }
                    },
                    Err(e) => {
                        println!("Failed to read file {}: {}", file, e);
                    }
                }
                solver.pop(1);
            }
        }
        Ok(())
    }
}

