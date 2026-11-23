//! Staff unlock. Phoenix checks staff as `(user.flags | flag_override) & 1`
//! against its store state, inlined in about 30 places. Every gateway handler
//! gets that state as its first argument, so the gateway detour sets
//! `flag_override` there while the reducer holds it, and every copy of the
//! check reads it.

use std::{
   ffi::c_void,
   ptr,
   sync::{
      OnceLock,
      atomic::{
         AtomicBool,
         Ordering,
      },
   },
};

use phoenix_hook::{
   Image,
   Pattern,
};

/// The standalone `is_staff(handle, force)`, 0x1cfca90 on 356207. Matching it
/// pins the field offsets below, which sit in its loads at +0x58 and +0x5c.
const IS_STAFF: Pattern = Pattern::ida(
   "FF 03 01 D1 FD 7B 02 A9 F3 1B 00 F9 FD 83 00 91 A1 00 00 37 08 00 40 F9 08 21 43 F9 08 45 49 \
    39 68 00 00 36 33 00 80 52 1A 00 00 14 ?? ?? ?? ?? ?? ?? ?? ?? E8 03 00 91 ?? ?? ?? ?? E8 03 \
    40 F9 08 21 40 91 09 75 42 F9 3F 09 00 F1 61 00 00 54 F3 03 1F 2A 0D 00 00 14 0A 81 45 B9 0B \
    89 45 B9 0C F1 44 B9 5F 01 00 71 6A 11 9F 1A",
);

/// `flag_override: Option<u32>` in the store state. The check loads the tag
/// as a word and tests it for zero.
const OVERRIDE_TAG: usize = 0x8580;
const OVERRIDE_VALUE: usize = 0x8588;
const STAFF: u32 = 1;

static UNLOCKED: AtomicBool = AtomicBool::new(true);
static LAYOUT_KNOWN: OnceLock<bool> = OnceLock::new();

#[must_use]
pub fn enabled() -> bool {
   UNLOCKED.load(Ordering::Acquire)
}

pub fn set_enabled(on: bool) {
   UNLOCKED.store(on, Ordering::Release);
}

/// Checks the state layout off the main thread, since the scan reads most of
/// the host library.
pub fn start(on: bool, image: &'static Image<'static>) {
   set_enabled(on);
   std::thread::spawn(|| {
      let found = image.scan(IS_STAFF).len();
      if found != 1 {
         log::warn!("staff: {found} matches for is_staff, the staff flag stays off");
      }
      LAYOUT_KNOWN.get_or_init(|| found == 1);
   });
}

/// Sets or clears the staff bit in `flag_override`, before each gateway event
/// so it survives Phoenix rebuilding the state.
///
/// # Safety
///
/// `state` is the store state a gateway handler was called with, and the
/// caller runs inside that handler.
pub unsafe fn apply(state: *mut c_void) {
   if LAYOUT_KNOWN.get() != Some(&true) {
      return;
   }
   // SAFETY: the matched is_staff reads both fields from this state as u32s.
   unsafe {
      let tag = state.byte_add(OVERRIDE_TAG).cast::<u32>();
      let value = state.byte_add(OVERRIDE_VALUE).cast::<u32>();
      let had = ptr::read(tag) != 0;
      let current = if had { ptr::read(value) } else { 0 };
      let wanted = if enabled() {
         current | STAFF
      } else {
         current & !STAFF
      };
      if wanted == current {
         return;
      }
      ptr::write(value, wanted);
      ptr::write(tag, u32::from(wanted != 0 || had));
   }
}
