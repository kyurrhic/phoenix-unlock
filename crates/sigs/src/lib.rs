//! Hook points as YARA-style rules, plus a table of known builds keyed by build
//! ID.
//!
//! A [`Sig`] lists [`Anchor`]s. Every anchor is evaluated, each one that
//! resolves must land on exactly one address, and all of them must agree. A
//! build-specific byte pattern and a portable table lookup can sit in one rule,
//! so a stale pattern is caught instead of hooked.
//!
//! The event set is never compiled in. [`GatewayRegistry`] walks the target's
//! registry at load time, so a new Discord build brings its own events. Porting
//! the build table is `cargo run -p sigscan -- liblibdiscord_wasm_host.so`,
//! which dumps the registry and checks every rule. Unknown builds still load
//! through [`Sig::gateway`].

use std::{
   borrow::Cow,
   ffi::c_void,
   fmt,
   marker::PhantomData,
};

pub use phoenix_hook::{
   BuildId,
   Image,
   Pattern,
   Segment,
};

mod builds;
#[cfg(feature = "file")]
pub mod file;
mod registry;

pub use builds::BUILDS;
pub use registry::{
   EventId,
   GatewayEntry,
   GatewayRegistry,
};

/// Libraries that carry the gateway registry, Phoenix's and the stand-in's.
pub const LIBRARIES: &[&str] = &["liblibdiscord_wasm_host.so", "libstand_in.so"];

/// Name of the plugin bundle the patcher stores next to the loader in the APK's
/// native library directory, a JSON object of plugin name to source.
pub const PLUGIN_BUNDLE: &str = "libplm.plugins.so";

/// Offset of the handler pointer in a gateway registry entry `{name ptr, name
/// len, handler}`.
pub const GATEWAY_HANDLER_FIELD: usize = 2 * size_of::<usize>();

/// One way to find a hook point.
#[derive(Clone, Debug)]
pub enum Anchor<'a> {
   /// Code matching `pattern`, shifted by `offset`.
   Code { pattern: Pattern, offset: isize },
   /// A `{name ptr, name len, ...}` table entry whose name is `key`. The result
   /// is the code pointer `field` bytes into the entry.
   Table { key: Cow<'a, str>, field: usize },
}

impl fmt::Display for Anchor<'_> {
   fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
      match self {
         Self::Code { pattern, offset: 0 } => write!(formatter, "code {pattern}"),
         Self::Code { pattern, offset } => write!(formatter, "code {pattern} {offset:+}"),
         Self::Table { key, field } => write!(formatter, "table {key:?} +{field}"),
      }
   }
}

/// Calling convention of a hook point, which picks the detour the runtime
/// installs.
pub trait Abi {
   type Fn: Copy;
}

#[repr(C)]
#[derive(Clone, Copy)]
pub struct RawStr {
   pub ptr: *const u8,
   pub len: usize,
}

/// Phoenix's gateway event, `name` and `data` are borrowed UTF-8 with `data`
/// holding the raw dispatch JSON. `rest` is opaque and copied through
/// unchanged.
#[repr(C)]
#[derive(Clone, Copy)]
pub struct GatewayEvent {
   pub name: RawStr,
   pub data: RawStr,
   pub rest: [u64; 4],
}

/// A pointer-sized-word Rust `Result` (32 bytes on 64-bit, 16 bytes on 32-bit),
/// returned through x8 on arm64 and a hidden pointer on x86_64 / arm.
#[repr(C)]
#[derive(Clone, Copy)]
pub struct HandlerResult(pub [usize; 4]);

impl HandlerResult {
   pub const OK: Self = Self([usize::MAX, 0, 0, 0]);

   #[must_use]
   pub const fn is_ok(&self) -> bool {
      self.0[0] == usize::MAX
   }
}

/// A gateway registry handler, `handler(store, event, ctx)`.
pub struct GatewayHandler;

impl Abi for GatewayHandler {
   type Fn = unsafe extern "C" fn(*mut c_void, *const GatewayEvent, *mut c_void) -> HandlerResult;
}

#[derive(Debug)]
pub struct Sig<'a, A: Abi> {
   pub name:    Cow<'a, str>,
   pub anchors: Cow<'a, [Anchor<'a>]>,
   abi:         PhantomData<fn() -> A>,
}

impl<A: Abi> Clone for Sig<'_, A> {
   fn clone(&self) -> Self {
      Self {
         name:    self.name.clone(),
         anchors: self.anchors.clone(),
         abi:     PhantomData,
      }
   }
}

impl<'a, A: Abi> Sig<'a, A> {
   #[must_use]
   pub const fn new(name: &'a str, anchors: &'a [Anchor<'a>]) -> Self {
      Self {
         name:    Cow::Borrowed(name),
         anchors: Cow::Borrowed(anchors),
         abi:     PhantomData,
      }
   }
}

impl Sig<'static, GatewayHandler> {
   /// The portable rule for a gateway event, a registry lookup by the name
   /// the target keys it under.
   #[must_use]
   pub fn gateway(event: &str) -> Self {
      Self {
         name:    Cow::Owned(event.to_owned()),
         anchors: Cow::Owned(vec![Anchor::Table {
            key:   Cow::Owned(event.to_owned()),
            field: GATEWAY_HANDLER_FIELD,
         }]),
         abi:     PhantomData,
      }
   }
}

/// Where a rule resolved, which anchor found it first, and how many anchors
/// agreed.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Located {
   pub addr:     usize,
   pub anchor:   usize,
   pub agreeing: usize,
}

#[derive(Debug, flub::Error)]
pub enum Error {
   #[error("{sig}: no anchor matched")]
   NotFound { sig: String },
   #[error("{sig}: `{anchor}` matched {} places ({})", .hits.len(), hex_list(.hits))]
   Ambiguous {
      sig:    String,
      anchor: String,
      hits:   Vec<usize>,
   },
   #[error("{sig}: `{anchor}` found {found:#x}, an earlier anchor found {expected:#x}")]
   Conflict {
      sig:      String,
      anchor:   String,
      expected: usize,
      found:    usize,
   },
}

fn hex_list(addrs: &[usize]) -> String {
   addrs
      .iter()
      .take(8)
      .map(|addr| format!("{addr:#x}"))
      .collect::<Vec<_>>()
      .join(", ")
}

impl<A: Abi> Sig<'_, A> {
   pub fn resolve(&self, image: &Image<'_>) -> Result<Located, Error> {
      let mut located = Option::<Located>::None;

      for (index, anchor) in self.anchors.iter().enumerate() {
         let mut hits = evaluate(anchor, image);
         hits.sort_unstable();
         hits.dedup();
         let found = match hits[..] {
            [] => continue,
            [found] => found,
            _ => {
               return Err(Error::Ambiguous {
                  sig: self.name.to_string(),
                  anchor: anchor.to_string(),
                  hits,
               });
            },
         };
         match &mut located {
            None => {
               located = Some(Located {
                  addr:     found,
                  anchor:   index,
                  agreeing: 1,
               });
            },
            Some(first) if first.addr != found => {
               return Err(Error::Conflict {
                  sig: self.name.to_string(),
                  anchor: anchor.to_string(),
                  expected: first.addr,
                  found,
               });
            },
            Some(first) => first.agreeing += 1,
         }
      }

      located.ok_or_else(|| {
         Error::NotFound {
            sig: self.name.to_string(),
         }
      })
   }
}

fn evaluate(anchor: &Anchor<'_>, image: &Image<'_>) -> Vec<usize> {
   match anchor {
      Anchor::Code { pattern, offset } => {
         image
            .scan(*pattern)
            .into_iter()
            .filter_map(|addr| addr.checked_add_signed(*offset))
            .collect()
      },
      Anchor::Table { key, field } => {
         table_entries(image, key, *field)
            .into_iter()
            .map(|(_, code)| code)
            .collect()
      },
   }
}

/// `(slot, code)` for every `{name ptr, name len, ...}` entry named `key` whose
/// pointer `field` bytes in starts a function.
fn table_entries(image: &Image<'_>, key: &str, field: usize) -> Vec<(usize, usize)> {
   // Stops at the first copy of `key` a table points at. Literals sit in
   // `.rodata` at the front of the image, so the scan never reaches `.text`
   // (most of the library) at startup. Every table pointing at that copy still
   // counts, so callers still see ambiguity.
   image
      .find_bytes_iter(key.as_bytes())
      .map(|string| {
         image
            .pointers_to(string)
            .into_iter()
            .filter(|slot| image.read_usize(slot + size_of::<usize>()) == Some(key.len()))
            .filter_map(|slot| Some((slot, image.read_usize(slot + field)?)))
            .filter(|(_, code)| image.is_function(*code))
            .collect::<Vec<_>>()
      })
      .find(|entries| !entries.is_empty())
      .unwrap_or_default()
}

/// A gateway handler rule in a [`Build`], named by the event's registry key.
pub struct Gateway {
   pub sig: Sig<'static, GatewayHandler>,
}

/// A build phoenix has rules for.
pub struct Build {
   pub id:      BuildId,
   pub label:   &'static str,
   pub library: &'static str,
   pub gateway: &'static [Gateway],
}

impl Build {
   #[must_use]
   pub fn find(id: BuildId) -> Option<&'static Self> {
      BUILDS.iter().find(|build| build.id == id)
   }

   /// The table rule for `event`, or the portable registry lookup when the
   /// table has none.
   #[must_use]
   pub fn gateway_sig(build: Option<&Self>, event: &str) -> Sig<'static, GatewayHandler> {
      build
         .and_then(|build| build.gateway.iter().find(|rule| rule.sig.name == event))
         .map_or_else(|| Sig::gateway(event), |rule| rule.sig.clone())
   }
}
