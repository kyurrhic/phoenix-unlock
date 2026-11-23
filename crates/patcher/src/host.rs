//! Patches to `liblibdiscord_wasm_host.so`, located from anchors so a new build
//! only needs a re-run while the code keeps its shape.

use std::ops::Range;

use misstep::{
   OptionExt,
   ensure,
   report,
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
      SectionHeader,
   },
};
use phoenix_sigs::file::{
   ElfFile,
   Machine,
};

pub const LIBRARY: &str = "liblibdiscord_wasm_host.so";
/// The loader's name inside the APK. It replaces `liblog.so` in the host's
/// `DT_NEEDED` list, so it must be the same length to fit in `.dynstr`. The
/// loader itself needs `liblog.so`, which keeps the host's log imports bound.
pub const INJECTED: &str = "libplm.so";
const REPLACED: &str = "liblog.so";
const _: () = assert!(INJECTED.len() == REPLACED.len());

/// The client-access evaluator is the only function that references the
/// experiment table whose first entry is `{"2026-11-phoenix-app-access", 26}`.
const EXPERIMENT: &str = "2026-11-phoenix-app-access";

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum Isa {
   Thumb,
   Arm,
   Aarch64,
   X86_64,
}

pub struct Patched {
   pub machine: Machine,
   pub access:  usize,
}

pub fn patch(path: &str, data: &mut [u8]) -> misstep::Result<Patched> {
   let (machine, needed, access, access_at, isa) = {
      let file = ElfFile::parse(path, data)?;
      let needed = needed_name(data)?;
      let (access, isa) = access_evaluator(data, &file)?;
      let access_at = file
         .image
         .is_code(access)
         .then(|| file.file_offset(access))
         .flatten()
         .context("access evaluator has no file backing")?;
      (file.machine, needed, access, access_at, isa)
   };

   data[needed..needed + INJECTED.len()].copy_from_slice(INJECTED.as_bytes());
   // Returns Some(true), an Option<bool> in the low byte of the return
   // register.
   let return_true: &[u8] = match isa {
      Isa::Aarch64 => &[0x20, 0x00, 0x80, 0x52, 0xC0, 0x03, 0x5F, 0xD6],
      Isa::X86_64 => &[0xB0, 0x01, 0xC3],
      Isa::Thumb => &[0x01, 0x20, 0x70, 0x47],
      Isa::Arm => &[0x01, 0x00, 0xA0, 0xE3, 0x1E, 0xFF, 0x2F, 0xE1],
   };
   data[access_at..access_at + return_true.len()].copy_from_slice(return_true);
   Ok(Patched { machine, access })
}

/// File offset of the `liblog.so` string a `DT_NEEDED` entry names.
fn needed_name(data: &[u8]) -> misstep::Result<usize> {
   if data.get(4) == Some(&elf::ELFCLASS32.0) {
      needed_name_with::<FileHeader32<Endianness>>(data, 8)
   } else {
      needed_name_with::<FileHeader64<Endianness>>(data, 16)
   }
}

fn needed_name_with<H: FileHeader<Endian = Endianness>>(
   data: &[u8],
   entry_size: usize,
) -> misstep::Result<usize> {
   const DT_NEEDED: u64 = 1;

   let header = H::parse(data)?;
   let endian = header.endian()?;
   let sections = header.sections(endian, data)?;
   let range = |name: &[u8]| -> misstep::Result<Range<usize>> {
      let (_, section) = sections
         .section_by_name(endian, name)
         .ok_or_else(|| report!("no {} section", String::from_utf8_lossy(name)))?;
      let start = usize::try_from(section.sh_offset(endian).into())?;
      Ok(start..start + usize::try_from(section.sh_size(endian).into())?)
   };
   let dynamic = data
      .get(range(b".dynamic")?)
      .context(".dynamic outside the file")?;
   let strings = range(b".dynstr")?;

   let hits = dynamic
      .chunks_exact(entry_size)
      .map(|entry| {
         if entry_size == 8 {
            (
               u64::from(u32::from_le_bytes(entry[..4].try_into().unwrap())),
               u64::from(u32::from_le_bytes(entry[4..8].try_into().unwrap())),
            )
         } else {
            (
               u64::from_le_bytes(entry[..8].try_into().unwrap()),
               u64::from_le_bytes(entry[8..16].try_into().unwrap()),
            )
         }
      })
      .filter(|&(tag, _)| tag == DT_NEEDED)
      .filter_map(|(_, value)| strings.start.checked_add(usize::try_from(value).ok()?))
      .filter(|&at| {
         at < strings.end && data.get(at..at + REPLACED.len() + 1) == Some(b"liblog.so\0")
      })
      .collect::<Vec<usize>>();

   match hits[..] {
      [at] => Ok(at),
      _ => {
         Err(report!(
            "expected one DT_NEEDED {REPLACED}, found {}",
            hits.len()
         ))
      },
   }
}

fn access_evaluator(data: &[u8], file: &ElfFile<'_>) -> misstep::Result<(usize, Isa)> {
   let image = &file.image;
   let text = text_range(data)?;
   let ptr_size = file.machine.pointer_size();
   let slots = image
      .find_bytes(EXPERIMENT.as_bytes())
      .into_iter()
      .flat_map(|string| pointers_to(image, ptr_size, string))
      .filter(|&slot| read_ptr(image, ptr_size, slot + ptr_size) == Some(EXPERIMENT.len()))
      .collect::<Vec<usize>>();

   let code = image
      .read(text.start, text.len())
      .context(".text outside every segment")?;

   let mut functions = references(file.machine, text.start, code, image)
      .into_iter()
      .filter(|(_, target, _)| slots.contains(target))
      .filter_map(|(at, _, isa)| function_containing(file, at).map(|fn_addr| (fn_addr, isa)))
      .collect::<Vec<(usize, Isa)>>();
   functions.sort_unstable_by_key(|&(addr, _)| addr);
   functions.dedup_by_key(|(addr, _)| *addr);
   ensure!(
      functions.len() == 1,
      "access evaluator: expected one function referencing {EXPERIMENT}, found {functions:x?}"
   );
   Ok(functions[0])
}

fn pointers_to(image: &phoenix_sigs::Image<'_>, ptr_size: usize, target: usize) -> Vec<usize> {
   if ptr_size == 8 {
      return image.pointers_to(target);
   }
   let Ok(target32) = u32::try_from(target) else {
      return Vec::new();
   };
   let needle = target32.to_le_bytes();
   let mut out = Vec::new();
   for segment in &image.segments {
      if segment.executable {
         continue;
      }
      let start = segment.addr.next_multiple_of(4) - segment.addr;
      for offset in (start..segment.bytes.len().saturating_sub(3)).step_by(4) {
         if segment.bytes[offset..offset + 4] == needle {
            out.push(segment.addr + offset);
         }
      }
   }
   out
}

fn read_ptr(image: &phoenix_sigs::Image<'_>, ptr_size: usize, addr: usize) -> Option<usize> {
   if ptr_size == 8 {
      image.read_usize(addr)
   } else {
      let bytes = image.read(addr, 4)?;
      Some(u32::from_le_bytes(bytes.try_into().ok()?) as usize)
   }
}

fn function_containing(file: &ElfFile<'_>, addr: usize) -> Option<usize> {
   if let Some(found) = file.image.function_containing(addr) {
      return Some(found);
   }
   let (exidx, size) = file.arm_exidx?;
   let count = size / 8;
   let start = |index: usize| -> Option<usize> {
      let entry = exidx + index * 8;
      let bytes = file.image.read(entry, 4)?;
      let raw = i32::from_le_bytes(bytes.try_into().ok()?);
      let prel31 = (raw << 1) >> 1;
      entry.checked_add_signed(prel31 as isize)
   };
   let (mut low, mut high) = (0, count);
   while low < high {
      let mid = low + (high - low) / 2;
      if start(mid)? <= addr {
         low = mid + 1;
      } else {
         high = mid;
      }
   }
   start(low.checked_sub(1)?)
}

fn text_range(data: &[u8]) -> misstep::Result<Range<usize>> {
   if data.get(4) == Some(&elf::ELFCLASS32.0) {
      text_range_with::<FileHeader32<Endianness>>(data)
   } else {
      text_range_with::<FileHeader64<Endianness>>(data)
   }
}

fn text_range_with<H: FileHeader<Endian = Endianness>>(
   data: &[u8],
) -> misstep::Result<Range<usize>> {
   let header = H::parse(data)?;
   let endian = header.endian()?;
   let (_, text) = header
      .sections(endian, data)?
      .section_by_name(endian, b".text")
      .context("no .text section")?;
   let start = usize::try_from(text.sh_addr(endian).into())?;
   Ok(start..start + usize::try_from(text.sh_size(endian).into())?)
}

/// `(instruction, target, isa)` for every PC-relative address the code forms.
fn references(
   machine: Machine,
   base: usize,
   code: &[u8],
   image: &phoenix_sigs::Image<'_>,
) -> Vec<(usize, usize, Isa)> {
   match machine {
      Machine::Aarch64 => {
         let words = code
            .as_chunks::<4>()
            .0
            .iter()
            .map(|word| u32::from_le_bytes(*word))
            .collect::<Vec<u32>>();

         (0..words.len())
            .flat_map(|index| {
               let word = words[index];
               let pc = base + 4 * index;
               let is_adrp = word & 0x9F00_0000 == 0x9000_0000;
               let page = is_adrp
                  .then(|| {
                     let imm = i64::from((word >> 29) & 3 | ((word >> 5) & 0x7_FFFF) << 2);
                     let imm = if imm & (1 << 20) != 0 {
                        imm - (1 << 21)
                     } else {
                        imm
                     };
                     isize::try_from(imm << 12).ok()
                  })
                  .flatten()
                  .map(|offset| (pc & !0xFFF).wrapping_add_signed(offset));
               let register = word & 0x1F;

               let partners = words
                  .get(index + 1..(index + 5).min(words.len()))
                  .unwrap_or_default();
               partners
                  .iter()
                  .filter_map(move |&next| {
                     let page = page?;
                     let same = (next >> 5) & 0x1F == register;
                     let imm12 = ((next >> 10) & 0xFFF) as usize;
                     match next & 0xFFC0_0000 {
                        0x9100_0000 if same => Some((pc, page + imm12, Isa::Aarch64)),
                        0xF940_0000 if same => Some((pc, page + imm12 * 8, Isa::Aarch64)),
                        _ => None,
                     }
                  })
                  .collect::<Vec<_>>()
            })
            .collect()
      },

      Machine::X86_64 => {
         (0..code.len().saturating_sub(7))
            .filter_map(|at| {
               let &[rex, opcode, modrm, ..] = &code[at..] else {
                  return None;
               };
               let rip_relative = matches!(rex, 0x48 | 0x4C)
                  && matches!(opcode, 0x8B | 0x8D)
                  && modrm & 0xC7 == 0x05;
               if !rip_relative {
                  return None;
               }
               let disp = i32::from_le_bytes(code[at + 3..at + 7].try_into().ok()?);
               Some((
                  base + at,
                  (base + at + 7).wrapping_add_signed(disp as isize),
                  Isa::X86_64,
               ))
            })
            .collect()
      },

      Machine::Arm => arm_references(base, code, image),
   }
}

fn thumb_mov_imm16(hw1: u16, hw2: u16) -> Option<(u8, u16)> {
   if hw2 & 0x8000 != 0 {
      return None;
   }
   let rd = ((hw2 >> 8) & 0xF) as u8;
   let imm = ((hw1 & 0xF) << 12) | (((hw1 >> 10) & 1) << 11) | (((hw2 >> 12) & 7) << 8) | (hw2 & 0xFF);
   Some((rd, imm))
}

fn is_thumb32(hw: u16) -> bool {
   matches!(hw >> 11, 0x1D..=0x1F)
}

fn arm_references(
   base: usize,
   code: &[u8],
   image: &phoenix_sigs::Image<'_>,
) -> Vec<(usize, usize, Isa)> {
   let mut out = Vec::new();
   let hws: Vec<u16> = code
      .as_chunks::<2>()
      .0
      .iter()
      .map(|pair| u16::from_le_bytes(*pair))
      .collect();

   // Thumb-2: MOVW + MOVT + ADD Rd, PC, or LDR Rd, [PC, #imm] + ADD Rd, PC.
   let mut i = 0;
   while i < hws.len() {
      let hw1 = hws[i];
      if is_thumb32(hw1) && i + 1 < hws.len() {
         let hw2 = hws[i + 1];
         if hw1 & 0xFBF0 == 0xF240
            && let Some((rd, lo)) = thumb_mov_imm16(hw1, hw2)
         {
            let pc_start = base + i * 2;
            let mut j = i + 2;
            let mut hi = None;
            let limit = (i + 12).min(hws.len());
            while j < limit {
               let nhw1 = hws[j];
               if is_thumb32(nhw1) && j + 1 < hws.len() {
                  let nhw2 = hws[j + 1];
                  if nhw1 & 0xFBF0 == 0xF2C0
                     && let Some((trd, thi)) = thumb_mov_imm16(nhw1, nhw2)
                     && trd == rd
                  {
                     hi = Some(thi);
                  }
                  j += 2;
               } else {
                  if nhw1 & 0xFF78 == 0x4478 {
                     let add_rd = ((nhw1 & 7) | ((nhw1 & 0x80) >> 4)) as u8;
                     if add_rd == rd
                        && let Some(thi) = hi
                     {
                        let imm32 = (u32::from(thi) << 16) | u32::from(lo);
                        let add_pc = base + j * 2;
                        let target = (add_pc as u32).wrapping_add(4).wrapping_add(imm32) as usize;
                        out.push((pc_start, target, Isa::Thumb));
                        break;
                     }
                  }
                  j += 1;
               }
            }
         }
         i += 2;
         continue;
      }

      // 16-bit Thumb LDR Rd, [PC, #imm8*4] + ADD Rd, PC
      if hw1 & 0xF800 == 0x4800 {
         let rd = ((hw1 >> 8) & 7) as u8;
         let pc_start = base + i * 2;
         let pool_addr = ((pc_start + 4) & !3) + usize::from(hw1 & 0xFF) * 4;
         if let Some(pool_bytes) = image.read(pool_addr, 4)
            && let Ok(arr) = pool_bytes.try_into()
         {
            let offset = u32::from_le_bytes(arr);
            let mut j = i + 1;
            let limit = (i + 8).min(hws.len());
            while j < limit {
               let nhw = hws[j];
               if is_thumb32(nhw) {
                  j += 2;
                  continue;
               }
               if nhw & 0xFF78 == 0x4478 {
                  let add_rd = ((nhw & 7) | ((nhw & 0x80) >> 4)) as u8;
                  if add_rd == rd {
                     let add_pc = base + j * 2;
                     let target = (add_pc as u32).wrapping_add(4).wrapping_add(offset) as usize;
                     out.push((pc_start, target, Isa::Thumb));
                     break;
                  }
               }
               j += 1;
            }
         }
      }
      i += 1;
   }

   // ARM mode: MOVW + MOVT + ADD Rd, PC, Rd
   let words: Vec<u32> = code
      .as_chunks::<4>()
      .0
      .iter()
      .map(|w| u32::from_le_bytes(*w))
      .collect();
   for idx in 0..words.len() {
      let w = words[idx];
      if w & 0x0FF0_0000 != 0x0300_0000 {
         continue;
      }
      let rd = (w >> 12) & 0xF;
      let lo = ((w >> 4) & 0xF000) | (w & 0xFFF);
      let mut hi = None;
      for k in idx + 1..(idx + 6).min(words.len()) {
         let nw = words[k];
         if nw & 0x0FF0_0000 == 0x0340_0000 && ((nw >> 12) & 0xF) == rd {
            hi = Some(((nw >> 4) & 0xF000) | (nw & 0xFFF));
         } else if let Some(thi) = hi {
            let add_pc_rd = (nw & 0x0FFF_0FFF) == (0x008F_0000 | (rd << 12) | rd);
            let add_rd_pc = (nw & 0x0FFF_0FFF) == (0x0080_000F | (rd << 16) | (rd << 12));
            if add_pc_rd || add_rd_pc {
               let imm32 = (thi << 16) | lo;
               let add_pc = base + k * 4;
               let target = (add_pc as u32).wrapping_add(8).wrapping_add(imm32) as usize;
               out.push((base + idx * 4, target, Isa::Arm));
               break;
            }
         }
      }
   }

   out
}

#[cfg(test)]
mod tests {
   use super::*;

   #[test]
   fn patches_synthetic_arm32_thumb2_elf() {
      // Minimal ELF32 little-endian EM_ARM binary with:
      // - PT_LOAD RX+RW at vaddr 0x0..0x2000
      // - PT_ARM_EXIDX covering function at 0x1000
      // - .text at 0x1000..0x1020 containing Thumb-2 MOVW+MOVT+ADD r0, pc -> slot at 0x1100
      // - .rodata/.data at 0x1100 with slot { ptr: 0x1110, len: 26 } and "2026-11-phoenix-app-access" at 0x1110
      // - .dynstr at 0x1200 with "liblog.so\0", .dynamic at 0x1220 with DT_NEEDED -> "liblog.so\0"
      let mut elf = vec![0u8; 0x2000];
      // ELF32 header
      elf[0..4].copy_from_slice(&[0x7F, b'E', b'L', b'F']);
      elf[4] = 1; // ELFCLASS32
      elf[5] = 1; // ELFDATA2LSB
      elf[6] = 1; // EV_CURRENT
      elf[16..18].copy_from_slice(&3u16.to_le_bytes()); // ET_DYN
      elf[18..20].copy_from_slice(&40u16.to_le_bytes()); // EM_ARM
      elf[20..24].copy_from_slice(&1u32.to_le_bytes()); // EV_CURRENT
      elf[28..32].copy_from_slice(&52u32.to_le_bytes()); // e_phoff
      elf[32..36].copy_from_slice(&0x1800u32.to_le_bytes()); // e_shoff
      elf[40..42].copy_from_slice(&52u16.to_le_bytes()); // e_ehsize
      elf[42..44].copy_from_slice(&32u16.to_le_bytes()); // e_phentsize
      elf[44..46].copy_from_slice(&3u16.to_le_bytes()); // e_phnum
      elf[46..48].copy_from_slice(&40u16.to_le_bytes()); // e_shentsize
      elf[48..50].copy_from_slice(&5u16.to_le_bytes()); // e_shnum
      elf[50..52].copy_from_slice(&4u16.to_le_bytes()); // e_shstrndx

      let mut write_phdr = |idx: usize, ptype: u32, off: u32, va: u32, sz: u32, flags: u32| {
         let b = 52 + idx * 32;
         elf[b..b + 4].copy_from_slice(&ptype.to_le_bytes());
         elf[b + 4..b + 8].copy_from_slice(&off.to_le_bytes());
         elf[b + 8..b + 12].copy_from_slice(&va.to_le_bytes());
         elf[b + 12..b + 16].copy_from_slice(&va.to_le_bytes());
         elf[b + 16..b + 20].copy_from_slice(&sz.to_le_bytes());
         elf[b + 20..b + 24].copy_from_slice(&sz.to_le_bytes());
         elf[b + 24..b + 28].copy_from_slice(&flags.to_le_bytes());
         elf[b + 28..b + 32].copy_from_slice(&0x1000u32.to_le_bytes());
      };
      write_phdr(0, 1, 0x1000, 0x1000, 0x100, 5); // RX
      write_phdr(1, 1, 0x1100, 0x1100, 0x400, 6); // RW
      write_phdr(2, 0x7000_0001, 0x1300, 0x1300, 8, 4); // PT_ARM_EXIDX

      // .ARM.exidx entry at 0x1300 pointing to function at 0x1000 (prel31 = -0x300)
      let prel31 = (-0x300i32 as u32) & 0x7FFF_FFFF;
      elf[0x1300..0x1304].copy_from_slice(&prel31.to_le_bytes());
      elf[0x1304..0x1308].copy_from_slice(&1u32.to_le_bytes());

      // Experiment string at 0x1110, slot at 0x1100
      elf[0x1110..0x1110 + EXPERIMENT.len()].copy_from_slice(EXPERIMENT.as_bytes());
      elf[0x1100..0x1104].copy_from_slice(&0x1110u32.to_le_bytes());
      elf[0x1104..0x1108].copy_from_slice(&(EXPERIMENT.len() as u32).to_le_bytes());

      // Thumb-2 code at 0x1000:
      // 0x1000: MOVW r0, #imm16
      // 0x1004: MOVT r0, #0
      // 0x1008: ADD r0, pc  (PC = 0x1008 + 4 = 0x100c, so imm = 0x1100 - 0x100c = 0x00f4)
      let imm = 0x00f4u16;
      let movw_hw1 = 0xF240u16 | ((imm >> 12) & 0xF) | (((imm >> 11) & 1) << 10);
      let movw_hw2 = (((imm >> 8) & 7) << 12) | (imm & 0xFF); // rd = 0
      let movt_hw1 = 0xF2C0u16;
      let movt_hw2 = 0x0000u16; // rd = 0
      let add_pc = 0x4478u16; // add r0, pc
      elf[0x1000..0x1002].copy_from_slice(&movw_hw1.to_le_bytes());
      elf[0x1002..0x1004].copy_from_slice(&movw_hw2.to_le_bytes());
      elf[0x1004..0x1006].copy_from_slice(&movt_hw1.to_le_bytes());
      elf[0x1006..0x1008].copy_from_slice(&movt_hw2.to_le_bytes());
      elf[0x1008..0x100a].copy_from_slice(&add_pc.to_le_bytes());

      // .dynstr at 0x1200, .dynamic at 0x1220
      elf[0x1200..0x1200 + 10].copy_from_slice(b"liblog.so\0");
      elf[0x1220..0x1224].copy_from_slice(&1u32.to_le_bytes()); // DT_NEEDED
      elf[0x1224..0x1228].copy_from_slice(&0u32.to_le_bytes()); // offset 0 in .dynstr

      // .shstrtab at 0x1400
      let shstr = b"\0.text\0.dynamic\0.dynstr\0.shstrtab\0";
      elf[0x1400..0x1400 + shstr.len()].copy_from_slice(shstr);

      let mut write_shdr = |idx: usize, name: u32, stype: u32, addr: u32, off: u32, sz: u32| {
         let b = 0x1800 + idx * 40;
         elf[b..b + 4].copy_from_slice(&name.to_le_bytes());
         elf[b + 4..b + 8].copy_from_slice(&stype.to_le_bytes());
         elf[b + 12..b + 16].copy_from_slice(&addr.to_le_bytes());
         elf[b + 16..b + 20].copy_from_slice(&off.to_le_bytes());
         elf[b + 20..b + 24].copy_from_slice(&sz.to_le_bytes());
      };
      write_shdr(0, 0, 0, 0, 0, 0);
      write_shdr(1, 1, 1, 0x1000, 0x1000, 0x20); // .text
      write_shdr(2, 7, 6, 0x1220, 0x1220, 16); // .dynamic
      write_shdr(3, 16, 3, 0x1200, 0x1200, 16); // .dynstr
      write_shdr(4, 24, 3, 0x1400, 0x1400, shstr.len() as u32); // .shstrtab

      let patched = patch("test-arm32.so", &mut elf).unwrap();
      assert_eq!(patched.machine, Machine::Arm);
      assert_eq!(patched.access, 0x1000);
      assert_eq!(&elf[0x1200..0x120a], b"libplm.so\0");
      assert_eq!(&elf[0x1000..0x1004], &[0x01, 0x20, 0x70, 0x47]);
   }
}
