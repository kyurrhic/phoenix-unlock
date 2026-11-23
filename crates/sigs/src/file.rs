//! ELF files viewed the way the dynamic linker maps them, for offline tools.

use std::{
   borrow::Cow,
   num::TryFromIntError,
};

use object::{
   Endianness,
   elf::{
      self,
      FileHeader32,
      FileHeader64,
   },
   read::elf::{
      FileHeader,
      ProgramHeader,
      SectionHeader,
   },
};

use crate::{
   BuildId,
   Image,
   Segment,
};

const PT_ARM_EXIDX: elf::ProgramType = elf::ProgramType(0x7000_0001);
const SHT_ANDROID_REL: elf::SectionType = elf::SectionType(0x6000_0001);

#[derive(Debug, flub::Error)]
pub enum FileError {
   #[error("{path}: {source}")]
   Parse {
      path:   String,
      #[source]
      source: object::Error,
   },
   #[error("{path}: unsupported e_machine {machine}")]
   Machine { path: String, machine: u16 },
   #[error("{path}: segment or section outside the file")]
   Truncated { path: String },
   #[error("{path}: relocation at {offset:#x} outside every segment")]
   Relocation { path: String, offset: usize },
   #[error("{path}: {message}")]
   Packed {
      path:    String,
      message: &'static str,
   },
   #[error("{path}: address does not fit in usize")]
   Address {
      path:   String,
      #[source]
      source: TryFromIntError,
   },
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Machine {
   Arm,
   Aarch64,
   X86_64,
}

impl Machine {
   #[must_use]
   pub const fn pointer_size(self) -> usize {
      match self {
         Self::Arm => 4,
         Self::Aarch64 | Self::X86_64 => 8,
      }
   }
}

/// A `PT_LOAD` segment's place in the file.
#[derive(Clone, Copy, Debug)]
struct FileLoad {
   vaddr:  usize,
   offset: usize,
   size:   usize,
}

pub struct ElfFile<'a> {
   /// Segments at their link addresses with `R_*_RELATIVE` relocations applied,
   /// from `.rela.dyn` plain or Android APS2-packed. RELR and REL keep the
   /// addend in place, which with a zero load base is already the final value.
   pub image:     Image<'a>,
   pub machine:   Machine,
   pub arm_exidx: Option<(usize, usize)>,
   loads:         Vec<FileLoad>,
}

impl<'a> ElfFile<'a> {
   pub fn parse(path: &str, data: &'a [u8]) -> Result<Self, FileError> {
      if data.get(4) == Some(&elf::ELFCLASS32.0) {
         Self::parse_header::<FileHeader32<Endianness>>(path, data)
      } else {
         Self::parse_header::<FileHeader64<Endianness>>(path, data)
      }
   }

   fn parse_header<H: FileHeader<Endian = Endianness>>(
      path: &str,
      data: &'a [u8],
   ) -> Result<Self, FileError> {
      let parse = |source| {
         FileError::Parse {
            path: path.to_owned(),
            source,
         }
      };
      let truncated = || {
         FileError::Truncated {
            path: path.to_owned(),
         }
      };
      let address = |source| {
         FileError::Address {
            path: path.to_owned(),
            source,
         }
      };

      let header = H::parse(data).map_err(parse)?;
      let endian = header.endian().map_err(parse)?;
      let (machine, relative) = match header.e_machine(endian) {
         elf::EM_ARM => (Machine::Arm, elf::R_ARM_RELATIVE.0),
         elf::EM_X86_64 => (Machine::X86_64, elf::R_X86_64_RELATIVE.0),
         elf::EM_AARCH64 => (Machine::Aarch64, elf::R_AARCH64_RELATIVE.0),
         other => {
            return Err(FileError::Machine {
               path:    path.to_owned(),
               machine: other.0,
            });
         },
      };

      let mut image = Image {
         path:         path.to_owned(),
         build_id:     None,
         segments:     Vec::new(),
         eh_frame_hdr: None,
      };
      let mut arm_exidx = None;
      let mut loads = Vec::new();
      for segment in header.program_headers(endian, data).map_err(parse)? {
         let bytes = segment.data(endian, data).map_err(|()| truncated())?;
         let vaddr = usize::try_from(segment.p_vaddr(endian).into()).map_err(address)?;
         let flags = segment.p_flags(endian);

         match segment.p_type(endian) {
            elf::PT_LOAD => {
               let mut owned = bytes.to_vec();
               owned.resize(
                  usize::try_from(segment.p_memsz(endian).into()).map_err(address)?,
                  0,
               );
               image.segments.push(Segment {
                  addr:       vaddr,
                  bytes:      Cow::Owned(owned),
                  executable: flags.0 & elf::PF_X.0 != 0,
                  writable:   flags.0 & elf::PF_W.0 != 0,
               });
               loads.push(FileLoad {
                  vaddr,
                  offset: usize::try_from(segment.p_offset(endian).into()).map_err(address)?,
                  size: bytes.len(),
               });
            },
            elf::PT_NOTE if image.build_id.is_none() => image.build_id = BuildId::from_notes(bytes),
            elf::PT_GNU_EH_FRAME => image.eh_frame_hdr = Some(vaddr),
            PT_ARM_EXIDX if arm_exidx.is_none() => {
               arm_exidx = Some((
                  vaddr,
                  usize::try_from(segment.p_memsz(endian).into()).map_err(address)?,
               ));
            },
            _ => {},
         }
      }

      let ptr_size = machine.pointer_size();
      for section in header.sections(endian, data).map_err(parse)?.iter() {
         let contents = || section.data(endian, data).map_err(parse);

         let relocs = match section.sh_type(endian) {
            elf::SHT_RELA if ptr_size == 4 => plain_rela32(contents()?, relative),
            elf::SHT_RELA => plain_rela64(contents()?, relative),
            elf::SHT_ANDROID_RELA | SHT_ANDROID_REL => {
               aps2(contents()?, relative).map_err(|message| {
                  FileError::Packed {
                     path: path.to_owned(),
                     message,
                  }
               })?
            },
            _ => continue,
         };

         for (offset, addend) in relocs {
            let segment = image
               .segments
               .iter_mut()
               .find(|segment| segment.contains(offset))
               .ok_or_else(|| {
                  FileError::Relocation {
                     path: path.to_owned(),
                     offset,
                  }
               })?;
            let at = offset - segment.addr;
            if ptr_size == 4 {
               segment.bytes.to_mut()[at..at + 4]
                  .copy_from_slice(&(addend as u32).to_le_bytes());
            } else {
               segment.bytes.to_mut()[at..at + 8].copy_from_slice(&addend.to_le_bytes());
            }
         }
      }

      Ok(Self {
         image,
         machine,
         arm_exidx,
         loads,
      })
   }

   /// Where the byte at link address `vaddr` sits in the file, when it has file
   /// backing.
   #[must_use]
   pub fn file_offset(&self, vaddr: usize) -> Option<usize> {
      self
         .loads
         .iter()
         .find(|load| (load.vaddr..load.vaddr + load.size).contains(&vaddr))
         .map(|load| vaddr - load.vaddr + load.offset)
   }
}

fn plain_rela32(bytes: &[u8], relative: u32) -> Vec<(usize, u64)> {
   bytes
      .as_chunks::<12>()
      .0
      .iter()
      .filter_map(|entry| {
         let word = |at: usize| u32::from_le_bytes(entry[at..at + 4].try_into().unwrap());
         let offset = usize::try_from(word(0)).ok()?;
         (word(4) & 0xFF == relative).then_some((offset, u64::from(word(8))))
      })
      .collect()
}

fn plain_rela64(bytes: &[u8], relative: u32) -> Vec<(usize, u64)> {
   bytes
      .as_chunks::<24>()
      .0
      .iter()
      .filter_map(|entry| {
         let word = |at: usize| u64::from_le_bytes(entry[at..at + 8].try_into().unwrap());
         let offset = usize::try_from(word(0)).ok()?;
         (word(8) & 0xFFFF_FFFF == u64::from(relative)).then_some((offset, word(16)))
      })
      .collect()
}

/// Android's packed relocation format: `APS2` then SLEB128 groups of offset
/// deltas, info and addend deltas, each optionally shared across the group.
fn aps2(bytes: &[u8], relative: u32) -> Result<Vec<(usize, u64)>, &'static str> {
   const BY_INFO: i64 = 1;
   const BY_OFFSET_DELTA: i64 = 2;
   const BY_ADDEND: i64 = 4;
   const HAS_ADDEND: i64 = 8;

   let mut stream = bytes
      .strip_prefix(b"APS2")
      .ok_or("packed relocations without APS2")?;

   let mut next = || -> Result<i64, &'static str> {
      let (mut value, mut shift) = (0i64, 0);
      loop {
         let (&byte, rest) = stream.split_first().ok_or("truncated APS2 stream")?;
         stream = rest;
         value |= i64::from(byte & 0x7F) << shift;
         shift += 7;
         if byte & 0x80 == 0 {
            if byte & 0x40 != 0 && shift < 64 {
               value |= -1 << shift;
            }
            return Ok(value);
         }
      }
   };

   let count = next()?;
   let (mut offset, mut addend, mut done) = (next()?, 0i64, 0);
   let mut out = Vec::new();

   while done < count {
      let group_size = next()?;
      let flags = next()?;
      let offset_delta = if flags & BY_OFFSET_DELTA != 0 {
         next()?
      } else {
         0
      };

      let mut info = if flags & BY_INFO != 0 { next()? } else { 0 };
      if flags & HAS_ADDEND != 0 && flags & BY_ADDEND != 0 {
         addend += next()?;
      }

      for _ in 0..group_size {
         offset += if flags & BY_OFFSET_DELTA != 0 {
            offset_delta
         } else {
            next()?
         };

         if flags & BY_INFO == 0 {
            info = next()?;
         }
         if flags & HAS_ADDEND != 0 && flags & BY_ADDEND == 0 {
            addend += next()?;
         }
         if info & 0xFFFF_FFFF == i64::from(relative) {
            let value = if flags & HAS_ADDEND != 0 { addend } else { 0 };
            out.push((
               usize::try_from(offset).map_err(|_| "negative relocation offset")?,
               value.cast_unsigned(),
            ));
         }

         done += 1;
      }
   }
   Ok(out)
}
