use crate::file_ext::*;
use anyhow::*;
use serde::*;
use std::convert::TryFrom;
use std::io::{Read, Seek};

#[derive(Serialize)]
pub struct MsgAttributeHeader {
    pub j: i32,
    pub name: String,
}

#[derive(Serialize)]
pub struct MsgEntry {
    pub name: String,
    pub attributes: Vec<String>,
    pub content: Vec<String>,
}

#[derive(Serialize)]
pub struct Msg {
    pub attribute_headers: Vec<MsgAttributeHeader>,
    pub entries: Vec<MsgEntry>,
}

impl Msg {
    pub fn new<F: Read + Seek>(mut file: F) -> Result<Msg> {
        if file.read_u32()? != 17 {
            bail!("Wrong version for MSG")
        }
        if &file.read_magic()? != b"GMSG" {
            bail!("Wrong magic for MSG")
        }
        if file.read_u64()? != 0x10 {
            bail!("Expected 0x10")
        }
        let count_a = file.read_u32()?;
        let attribute_count = file.read_u32()?;
        let language_count = file.read_u32()?;
        file.seek_align_up(8)?;

        let data_offset = file.read_u64()?;
        let p_offset = file.read_u64()?;
        let q_offset = file.read_u64()?;
        let attribute_js_offset = file.read_u64()?;
        let attribute_names_offset = file.read_u64()?;

        let entries = (0..count_a)
            .map(|_| file.read_u64())
            .collect::<Result<Vec<_>>>()?;

        file.seek_noop(p_offset)?;
        let p = file.read_u64()?;
        if p != 0 {
            bail!("Expected 0")
        }

        file.seek_noop(q_offset)?;
        let languages = (0..language_count)
            .map(|_| file.read_u32())
            .collect::<Result<Vec<_>>>()?;

        for (i, language) in languages.into_iter().enumerate() {
            if i != usize::try_from(language)? {
                bail!("Unexpected language index")
            }
        }

        file.seek_noop(attribute_js_offset)?;
        let attribute_js = (0..attribute_count)
            .map(|_| file.read_i32())
            .collect::<Result<Vec<_>>>()?;

        file.seek_assert_align_up(attribute_names_offset, 8)?;
        let attribute_names = (0..attribute_count)
            .map(|_| file.read_u64())
            .collect::<Result<Vec<_>>>()?;

        let entries = entries
            .into_iter()
            .map(|entry| {
                file.seek_noop(entry)?;
                let mut guid = [0; 24];
                file.read_exact(&mut guid)?;

                let name = file.read_u64()?;
                let attributes = file.read_u64()?;
                let content = (0..language_count)
                    .map(|_| file.read_u64())
                    .collect::<Result<Vec<_>>>()?;

                Ok((name, attributes, content))
            })
            .collect::<Result<Vec<_>>>()?
            .into_iter()
            .map(|(name, attributes, content)| {
                file.seek_noop(attributes)?;
                let n = (0..attribute_count)
                    .map(|_| file.read_u64())
                    .collect::<Result<Vec<_>>>()?;
                Ok((name, n, content))
            })
            .collect::<Result<Vec<_>>>()?;

        file.seek_noop(data_offset)?;
        let mut data = vec![];
        file.read_to_end(&mut data)?;

        let key = [
            0xCF, 0xCE, 0xFB, 0xF8, 0xEC, 0x0A, 0x33, 0x66, 0x93, 0xA9, 0x1D, 0x93, 0x50, 0x39,
            0x5F, 0x09,
        ];

        let mut prev = 0;
        for (i, byte) in data.iter_mut().enumerate() {
            let cur = *byte;
            *byte ^= prev ^ key[i & 0xF];
            prev = cur;
        }

        let entries = entries
            .into_iter()
            .map(|(name, attributes, content)| {
                let name = (&data[usize::try_from(name - data_offset)?..]).read_u16str()?;
                let attributes = attributes
                    .into_iter()
                    .map(|n| (&data[usize::try_from(n - data_offset)?..]).read_u16str())
                    .collect::<Result<Vec<_>>>()?;
                let content = content
                    .into_iter()
                    .map(|o| (&data[usize::try_from(o - data_offset)?..]).read_u16str())
                    .collect::<Result<Vec<_>>>()?;
                Ok(MsgEntry {
                    name,
                    attributes,
                    content,
                })
            })
            .collect::<Result<Vec<_>>>()?;

        let attribute_headers = attribute_js
            .into_iter()
            .zip(attribute_names)
            .map(|(j, name)| {
                let name = (&data[usize::try_from(name - data_offset)?..]).read_u16str()?;
                Ok(MsgAttributeHeader { j, name })
            })
            .collect::<Result<Vec<_>>>()?;

        Ok(Msg {
            attribute_headers,
            entries,
        })
    }
}
