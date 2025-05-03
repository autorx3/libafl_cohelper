//! The concolic seed schedules. This stage should be invoked before the concolic tracing stage.

use alloc::{
    borrow::{Cow, ToOwned},
    string::ToString,
};
use core::{fmt::Debug, marker::PhantomData};

use libafl_bolts::Named;
use rand::random;

#[cfg(feature = "introspection")]
use crate::monitors::stats::PerfFeature;
#[allow(unused_imports)]
use crate::{
    Error, HasMetadata, HasNamedMetadata,
    corpus::{HasCurrentCorpusId, HasTestcase,SchedulerTestcaseMetadata}, 
    inputs::Input, mark_feature_time, 
    schedulers::SchedulerMetadata,
    stages::{Restartable, RetryCountRestartHelper, Stage}, start_timer, 
    state::{HasCorpus, HasCurrentTestcase, HasExecutions, //HasExecutedBitmap, 
         HasPathTracker, HasSymimQueue, MaybeHasClientPerfMonitor}
};

/// a stage that allocates the seed to concolic tracing
#[derive(Clone,Debug)]
pub struct SymPatchStage<I,S> {
    name:Cow<'static, str>,
    phantom:PhantomData<(I,S)>,
}

impl<I,S> SymPatchStage<I,S>
where 
    I:Input,
    S: HasExecutions
        + HasCorpus<I>
        + HasCurrentTestcase<I>
        + HasNamedMetadata
        + HasMetadata
        + HasCurrentCorpusId
        + HasTestcase<I>
        + HasPathTracker
        + HasSymimQueue
        //+ HasExecutedBitmap
        + MaybeHasClientPerfMonitor,
{
    /// SYMPATCH for concolic
    pub fn sympatch(&mut self, state: &mut S) -> Result<(), Error>{
        // Get the next index from the scheduler
        start_timer!(state);
        let id= state.current_corpus_id()?.unwrap();
        mark_feature_time!(state, PerfFeature::GetInputFromCorpus);

        let path_id = {
            let mut testcase = state.testcase_mut(id)?;
            let tcmeta = testcase.metadata_mut::<SchedulerTestcaseMetadata>()?;
            tcmeta.n_fuzz_entry()
        };

        let stuck_path = *state.path_tracker().stuck_paths();

        if path_id == stuck_path{
            //
            let probability: f64 = random();
            let prob_threshold = 0.8-(state.symim_queue().len() as f64)*0.1;
            if probability < prob_threshold{
                state.symim_push(id);
            }
            return Ok(());
        }

        let path_hits_now = {
            let path_hits = state.path_tracker_mut().path_hits_mut();
            path_hits[path_id] += 1;
            path_hits[path_id]
        };

        let stuck_threshold = *state.path_tracker().stuck_threshold();

        let should_push = {
            if path_hits_now >= stuck_threshold{
                *state.path_tracker_mut().stuck_paths_mut() = path_id;
                true
            }else{
                false
            }
        };

        if should_push{
            state.symim_push(id);
            state.path_tracker_mut().cycle_reset();
        }

        Ok(())
    }
}

impl<E, EM, I, S, Z> Stage<E, EM, S, Z> for SymPatchStage<I,S>
where
    S: HasExecutions
        + HasCorpus<I>
        + HasCurrentTestcase<I>
        + HasNamedMetadata
        + HasMetadata
        + HasCurrentCorpusId
        + HasTestcase<I>
        + HasPathTracker
        + HasSymimQueue
        //+ HasExecutedBitmap
        + MaybeHasClientPerfMonitor,
    I: Input,
{
    #[inline]
    fn perform(
        &mut self,
        _fuzzer: &mut Z,
        _executor: &mut E,
        state: &mut S,
        _manager: &mut EM,
    ) -> Result<(), Error> {
        self.sympatch(state)
    }
}


impl<I, S> Restartable<S> for SymPatchStage<I,S>
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


impl<I, S> Named for SymPatchStage<I,S> {
    fn name(&self) -> &Cow<'static, str> {
        &self.name
    }
}

#[allow(dead_code)]
/// The counter for giving this stage unique id
static mut SYMPATCH_STAGE_ID: usize = 0;
/// The name for SYMPATCH stage
pub static SYMPATCH_STAGE_NAME: &str = "sympatch";

impl<I, S> SymPatchStage<I,S> {
    /// Creates a new default stage
    #[allow(dead_code)]
    pub fn new() -> Self {
        // unsafe but impossible that you create two threads both instantiating this instance
        let stage_id = unsafe {
            let ret = SYMPATCH_STAGE_ID;
            SYMPATCH_STAGE_ID += 1;
            ret
        };

        Self {
            name: Cow::Owned(SYMPATCH_STAGE_NAME.to_owned() + ":" + stage_id.to_string().as_ref()),
            phantom: PhantomData,
        }
    }
}