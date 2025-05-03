use core::cell::RefCell;
use std::os::unix::io::{AsRawFd, FromRawFd};
use std::{
    env,
    fs::{self, File, OpenOptions},
    io::{self, Write},
    path::PathBuf,
    process,
};
use clap::{Arg, Command as Commandargs};
use libafl::{
    corpus::{Corpus, InMemoryOnDiskCorpus, OnDiskCorpus},
    events::SimpleRestartingEventManager,
    executors::{ExitKind, ShadowExecutor},
    feedback_or,
    feedbacks::{CrashFeedback, MaxMapFeedback, TimeFeedback},
    fuzzer::{Fuzzer, StdFuzzer},
    inputs::{BytesInput, HasTargetBytes, Input},
    monitors::SimpleMonitor,
    mutators::{
        havoc_mutations, /*token_mutations::I2SRandReplace, tokens_mutations, StdMOptMutator,*/
        HavocScheduledMutator, /*Tokens,*/
    },
    observers::{CanTrack, HitcountsMapObserver, TimeObserver, VariableMapObserver,
    },
    schedulers::{
        powersched::PowerSchedule, IndexesLenTimeMinimizerScheduler, PowerQueueScheduler,
    },
    stages::{
        calibrate::CalibrationStage, power::StdPowerMutationalStage, ShadowTracingStage,
        StdMutationalStage,
        sympatch::SymPatchStage,symcc::SymCCStage,symextension::SymExtensionStage,
    },
    state::{HasCorpus, StdState},
    Error,
};
use libafl_bolts::{
    current_time,
    current_nanos,
    ownedref::OwnedMutSlice,
    rands::StdRand,
    shmem::{ShMemProvider, StdShMemProvider},
    tuples::{tuple_list, Handled},
    AsSlice,
};
use libafl_qemu::{
    elf::EasyElf,
    filter_qemu_args,
    modules::{
        cmplog::{CmpLogModule, CmpLogObserver},
        edges::StdEdgeCoverageModule,
    },
    Emulator, GuestReg, MmapPerms, QemuExecutor, QemuExitError, QemuExitReason, QemuShutdownCause,
    Regs,
};
use libafl_targets::{edges_map_mut_ptr, EDGES_MAP_ALLOCATED_SIZE, MAX_EDGES_FOUND};

#[cfg(unix)]
use nix::unistd::dup;

pub const MAX_INPUT_SIZE: usize = 1048576; // 1MB
//static mut SYMQEMU_BINARY: Option<PathBuf> = None;

//const MAGIC_FILENAME : &'static str = "SLASTI_MORMANTI";

pub fn main(){
    let res = match Commandargs::new(env!("CARGO_PKG_NAME"))
        .version(env!("CARGO_PKG_VERSION"))
        // .author("AFLplusplus team")
        // .about("LibAFL-based fuzzer with QEMU for Fuzzbench")
        .arg(
            Arg::new("out")
                .help("The directory to place finds in ('corpus')")
                .long("libafl-out")
                .required(true),
        )
        .arg(
            Arg::new("in")
                .help("The directory to read initial inputs from ('seeds')")
                .long("libafl-in")
                .required(true),
        )
        .arg(
            Arg::new("logfile")
                .long("libafl-logfile")
                .help("Duplicates all output to this file")
                .default_value("libafl.log"),
        )
        .try_get_matches_from(filter_qemu_args())
    {
        Ok(res) => res,
        Err(err) => {
            println!(
                "Syntax: {}, --libafl-in <input> --libafl-out <output>\n{:?}",
                env::current_exe()
                    .unwrap_or_else(|_| "fuzzer".into())
                    .to_string_lossy(),
                err,
            );
            return;
        }
    };

    println!(
        "Workdir: {:?}",
        env::current_dir().unwrap().to_string_lossy().to_string()
    );

    // For fuzzbench, crashes and finds are inside the same `corpus` directory, in the "queue" and "crashes" subdir.
    let mut out_dir = PathBuf::from(res.get_one::<String>("out").unwrap().to_string());
    if fs::create_dir(&out_dir).is_err() {
        println!("Out dir at {:?} already exists.", &out_dir);
        if !out_dir.is_dir() {
            println!("Out dir at {:?} is not a valid directory!", &out_dir);
            return;
        }
    }
    
    let mut crashes = out_dir.clone();
    crashes.push("crashes");
    out_dir.push("queue");

    let in_dir = PathBuf::from(res.get_one::<String>("in").unwrap().to_string());
    if !in_dir.is_dir() {
        println!("In dir at {:?} is not a valid directory!", &in_dir);
        return;
    }

    //let tokens = res.get_one::<String>("tokens").map(PathBuf::from);

    let logfile = PathBuf::from(res.get_one::<String>("logfile").unwrap().to_string());
        
    fuzz(out_dir, crashes, in_dir, logfile)
        .expect("An error occurred while fuzzing");
}

fn fuzz(
    corpus_dir:PathBuf,
    objective_dir:PathBuf,
    seed_dir:PathBuf,
    //broker_port:u16,
    logfile:PathBuf,
) -> Result<(),Error> {
    env_logger::init();
    env::remove_var("LD_LIBRARY_PATH");

    let args: Vec<String> = env::args().collect();

    let mut edges_observer = unsafe {
        HitcountsMapObserver::new(VariableMapObserver::from_mut_slice(
            "edges",
            OwnedMutSlice::from_raw_parts_mut(edges_map_mut_ptr(), EDGES_MAP_ALLOCATED_SIZE),
            &raw mut MAX_EDGES_FOUND,
        ))
        .track_indices()
    };

    let modules = tuple_list!(
        StdEdgeCoverageModule::builder()
            .map_observer(edges_observer.as_mut())
            .build()
            .unwrap(),
        CmpLogModule::default(),
    );

    let emulator = Emulator::empty()
        .qemu_parameters(args)
        .modules(modules)
        .build()?;
    
    let qemu = emulator.qemu();

    let mut elf_buffer = Vec::new();
    let elf = EasyElf::from_file(qemu.binary_path(),&mut elf_buffer).unwrap();

    let test_one_input_ptr = elf
        .resolve_symbol("LLVMFuzzerTestOneInput",qemu.load_addr())// LLVMFuzzerTestOneInput
        .expect("Symbol not found");

    qemu.set_breakpoint(test_one_input_ptr); 
    println!("Break at {:#x}", &test_one_input_ptr);
    println!("Break at 3 point here");

    unsafe {
        println!("About to run QEMU...");
        let result = qemu.run();
        println!("QEMU exit reason: {:?}", result);

        match result {
            Ok(QemuExitReason::Breakpoint(_)) => {
                println!("expected breakpoint");
            }
            _ => {
                println!("Unexpected exit reason, triggering panic.");
                panic!("Unexpected QEMU exit.");
            }
        }
    }   

    let stack_ptr: u64 = qemu.read_reg(Regs::Sp).unwrap();

    let mut ret_addr = [0; 8];
    qemu.read_mem(stack_ptr, &mut ret_addr)
        .expect("Error while reading QEMU memory.");

    let ret_addr = u64::from_le_bytes(ret_addr);

    println!("Stack pointer = {stack_ptr:#x}");
    println!("Return address = {ret_addr:#x}");

    qemu.remove_breakpoint(test_one_input_ptr); 
    qemu.set_breakpoint(ret_addr); 

    let input_addr = qemu
    .map_private(0,MAX_INPUT_SIZE,MmapPerms::ReadWrite)
    .unwrap();

    let log = RefCell::new(
        OpenOptions::new()
            .append(true)
            .create(true)
            .open(&logfile)?,
    );

    #[cfg(unix)]
    let mut stdout_cpy = unsafe {
        let new_fd = dup(io::stdout().as_raw_fd())?;
        File::from_raw_fd(new_fd)
    };

    //#[cfg(unix)]
    //let file_null = File::open("/dev/null")?;

    let monitor = SimpleMonitor::new(|s| {
        #[cfg(unix)]
        writeln!(&mut stdout_cpy, "{s}").unwrap();
        #[cfg(windows)]
        println!("{s}");
        writeln!(log.borrow_mut(), "{:?} {}", current_time(), s).unwrap();
    });

    let mut shmem_provider = StdShMemProvider::new()?;
    let (state, mut mgr) = match SimpleRestartingEventManager::launch(monitor, &mut shmem_provider)
    {
        // The restarting state will spawn the same process again as child, then restarted it each time it crashes.
        Ok(res) => res,
        Err(err) => match err {
            Error::ShuttingDown => {
                return Ok(());
            }
            _ => {
                panic!("Failed to setup the restarter: {err}");
            }
        },
    };


    // Create an observation channel to keep track of the execution time
    let time_observer = TimeObserver::new("time");
    // Create an observation channel using cmplog map
    let cmplog_observer = CmpLogObserver::new("cmplog", true);

    let map_feedback = MaxMapFeedback::new(&edges_observer);

    let calibration = CalibrationStage::new(&map_feedback);

    let mut feedback = feedback_or!(
        map_feedback,
        TimeFeedback::new(&time_observer)
    );

    let mut objective = CrashFeedback::new();

    let mut state = state.unwrap_or_else(|| {
        StdState::new(
            StdRand::with_seed(current_nanos()),
            InMemoryOnDiskCorpus::new(corpus_dir).unwrap(),
            OnDiskCorpus::new(objective_dir).unwrap(),
            &mut feedback,
            &mut objective,
        )
        .unwrap()
    });

    // Setup a Havoc mutator
    let mutator = HavocScheduledMutator::new(havoc_mutations());

    let power: StdPowerMutationalStage<_, _, BytesInput, _, _, _> =
        StdPowerMutationalStage::new(mutator);    

    let scheduler = IndexesLenTimeMinimizerScheduler::new(
        &edges_observer,
        PowerQueueScheduler::new(&mut state,&edges_observer,PowerSchedule::fast()),
    );

    let mut fuzzer = StdFuzzer::new(scheduler,feedback,objective);

    let mut harness = |_emulator: &mut Emulator<_, _, _, _, _, _, _>, _state: &mut _, input: &BytesInput|{
        let target = input.target_bytes();
        let mut buf = target.as_slice();
        //add s qemu
        let mut len = buf.len();
        if len > MAX_INPUT_SIZE{
            buf = &buf[0..MAX_INPUT_SIZE];
            len = MAX_INPUT_SIZE;
        }
        let len = len as GuestReg;

        unsafe{
            qemu.write_mem_unchecked(input_addr,buf);

            qemu.write_reg(Regs::Rdi, input_addr).unwrap();
            qemu.write_reg(Regs::Rsi, len).unwrap();
            qemu.write_reg(Regs::Rip, test_one_input_ptr).unwrap();
            qemu.write_reg(Regs::Rsp, stack_ptr).unwrap();
            
            match qemu.run(){
                Ok(QemuExitReason::Breakpoint(_)) =>{}
                Ok(QemuExitReason::End(QemuShutdownCause::HostSignal(signal))) =>{
                    signal.handle();
                }
                Err(QemuExitError::UnexpectedExit) => return ExitKind::Crash,
                _ => panic!("Unexpected QEMU exit.")
            }
        }
 
        ExitKind::Ok
    };

    let executor = QemuExecutor::new( //QemuForkExecutor
        emulator,
        &mut harness,
        tuple_list!(edges_observer,time_observer),
        &mut fuzzer,
        &mut state,
        &mut mgr,
        core::time::Duration::from_millis(5000),  ////timeout
    )?;

    let mut executor = ShadowExecutor::new(executor,tuple_list!(cmplog_observer));

    if state.must_load_initial_inputs() {
        state
            .load_initial_inputs(&mut fuzzer,&mut executor,&mut mgr,&[seed_dir.clone()])
            .unwrap_or_else(|_| {
                panic!("Failed to load initial corpus at {:?}",&seed_dir);
                //process::exit(0);
            });
        println!("We imported {} inputs from disk.",state.corpus().count());
    }

    // let tracing = ShadowTracingStage::new();
    // let i2s = StdMutationalStage::new(HavocScheduledMutator::new(tuple_list!(I2SRandReplace::new())));
    // let mutator = HavocScheduledMutator::new(havoc_mutations());
    // let mutational = StdMutationalStage::new(mutator);

    // #[cfg(unix)]
    // {
    //     let null_fd = file_null.as_raw_fd();
    //     dup2(null_fd, io::stdout().as_raw_fd())?;
    //     dup2(null_fd, io::stderr().as_raw_fd())?;
    // }
    
    log.replace(
        OpenOptions::new()
            .append(true)
            .create(true)
            .open(&logfile)?,
    );

    let sympatch = SymPatchStage::new();
    let symcc = SymCCStage::new("/hf/symqemu/symqemu_tosmt2_build/qemu-x86_64 /xy/LibAFL/fuzzers/structure_aware/hybrid_helper/fuzzer/symharness".to_string())?;
    let symexten = SymExtensionStage::new()?;

    let mut stages = tuple_list!(calibration,power,sympatch,symcc,symexten);

    fuzzer.fuzz_loop(&mut stages,&mut executor,&mut state, &mut mgr)?;
    Ok(())
}
