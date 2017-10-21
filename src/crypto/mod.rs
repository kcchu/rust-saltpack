mod hash;
mod sign;

pub use self::hash::*;
pub use self::sign::*;

use sodiumoxide;
use std::sync::{Once, ONCE_INIT};

static SODIUM_INIT: Once = ONCE_INIT;

pub fn sodium_init_once() {
    SODIUM_INIT.call_once(|| {
        sodiumoxide::init();
    });
}
