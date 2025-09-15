use crate::error::Result;
use byteorder::{BigEndian, LittleEndian, ReadBytesExt, WriteBytesExt};
use log::{debug, warn};
use std::io::{Read, Seek, SeekFrom, Write};

pub struct EndianReader<R> {
    reader: R,
    is_little_endian: bool,
}

#[allow(dead_code)]
impl<R: Read> EndianReader<R> {
    pub fn new(reader: R, is_little_endian: bool) -> Self {
        Self {
            reader,
            is_little_endian,
        }
    }

    pub fn set_endian(&mut self, is_little_endian: bool) {
        self.is_little_endian = is_little_endian;
    }

    pub fn read_u8(&mut self) -> Result<u8> {
        Ok(self.reader.read_u8()?)
    }

    pub fn read_u16(&mut self) -> Result<u16> {
        if self.is_little_endian {
            Ok(self.reader.read_u16::<LittleEndian>()?)
        } else {
            Ok(self.reader.read_u16::<BigEndian>()?)
        }
    }

    pub fn read_u32(&mut self) -> Result<u32> {
        if self.is_little_endian {
            Ok(self.reader.read_u32::<LittleEndian>()?)
        } else {
            Ok(self.reader.read_u32::<BigEndian>()?)
        }
    }

    pub fn read_u64(&mut self) -> Result<u64> {
        if self.is_little_endian {
            Ok(self.reader.read_u64::<LittleEndian>()?)
        } else {
            Ok(self.reader.read_u64::<BigEndian>()?)
        }
    }

    pub fn read_i8(&mut self) -> Result<i8> {
        Ok(self.reader.read_i8()?)
    }

    pub fn read_i16(&mut self) -> Result<i16> {
        if self.is_little_endian {
            Ok(self.reader.read_i16::<LittleEndian>()?)
        } else {
            Ok(self.reader.read_i16::<BigEndian>()?)
        }
    }

    pub fn read_i32(&mut self) -> Result<i32> {
        if self.is_little_endian {
            Ok(self.reader.read_i32::<LittleEndian>()?)
        } else {
            Ok(self.reader.read_i32::<BigEndian>()?)
        }
    }

    pub fn read_i64(&mut self) -> Result<i64> {
        if self.is_little_endian {
            Ok(self.reader.read_i64::<LittleEndian>()?)
        } else {
            Ok(self.reader.read_i64::<BigEndian>()?)
        }
    }

    pub fn read_f32(&mut self) -> Result<f32> {
        if self.is_little_endian {
            Ok(self.reader.read_f32::<LittleEndian>()?)
        } else {
            Ok(self.reader.read_f32::<BigEndian>()?)
        }
    }

    pub fn read_bytes(&mut self, count: usize) -> Result<Vec<u8>> {
        debug!("read_bytes: Attempting to read {} bytes", count);
        let mut buffer = vec![0u8; count];

        match self.reader.read_exact(&mut buffer) {
            Ok(()) => {
                debug!("read_bytes: Successfully read {} bytes", count);
                Ok(buffer)
            }
            Err(e) => {
                warn!("read_bytes: Failed to read {} bytes: {}", count, e);

                // Try to read whatever we can to see how much is actually available
                let mut partial_buffer = Vec::new();
                match self.reader.read_to_end(&mut partial_buffer) {
                    Ok(bytes_read) => {
                        debug!(
                            "read_bytes: Only {} bytes were actually available",
                            bytes_read
                        );
                    }
                    Err(read_err) => {
                        debug!(
                            "read_bytes: Could not even read remaining bytes: {}",
                            read_err
                        );
                    }
                }

                Err(e.into())
            }
        }
    }

    pub fn read_cstring(&mut self, max_length: Option<usize>) -> Result<String> {
        let mut bytes = Vec::new();
        let max = max_length.unwrap_or(255);

        debug!("read_cstring: Starting, max_length: {}", max);

        for i in 0..max {
            match self.read_u8() {
                Ok(byte) => {
                    if byte == 0 {
                        debug!("read_cstring: Found null terminator at offset {}", i);
                        break;
                    }
                    bytes.push(byte);
                }
                Err(e) => {
                    debug!("read_cstring: Hit EOF or error at offset {}: {}", i, e);
                    if bytes.is_empty() {
                        return Err(e);
                    }
                    // If we have some bytes, treat as unterminated string
                    break;
                }
            }
        }

        // Use Shift-JIS encoding like the original C# code
        let (decoded, _, _) = encoding_rs::SHIFT_JIS.decode(&bytes);
        let result = decoded.into_owned();
        debug!("read_cstring: Read string: '{}'", result);
        Ok(result)
    }
}

impl<R: Seek> EndianReader<R> {
    pub fn seek(&mut self, pos: SeekFrom) -> Result<u64> {
        let result = self.reader.seek(pos)?;
        debug!("seek: Moved to position {}", result);
        Ok(result)
    }

    pub fn position(&mut self) -> Result<u64> {
        Ok(self.reader.stream_position()?)
    }
}

#[allow(dead_code)]
pub struct EndianWriter<W> {
    writer: W,
    is_little_endian: bool,
}

#[allow(dead_code)]
impl<W: Write> EndianWriter<W> {
    pub fn new(writer: W, is_little_endian: bool) -> Self {
        Self {
            writer,
            is_little_endian,
        }
    }

    pub fn write_u8(&mut self, value: u8) -> Result<()> {
        Ok(self.writer.write_u8(value)?)
    }

    pub fn write_u16(&mut self, value: u16) -> Result<()> {
        if self.is_little_endian {
            Ok(self.writer.write_u16::<LittleEndian>(value)?)
        } else {
            Ok(self.writer.write_u16::<BigEndian>(value)?)
        }
    }

    pub fn write_u32(&mut self, value: u32) -> Result<()> {
        if self.is_little_endian {
            Ok(self.writer.write_u32::<LittleEndian>(value)?)
        } else {
            Ok(self.writer.write_u32::<BigEndian>(value)?)
        }
    }

    pub fn write_u64(&mut self, value: u64) -> Result<()> {
        if self.is_little_endian {
            Ok(self.writer.write_u64::<LittleEndian>(value)?)
        } else {
            Ok(self.writer.write_u64::<BigEndian>(value)?)
        }
    }

    pub fn write_f32(&mut self, value: f32) -> Result<()> {
        if self.is_little_endian {
            Ok(self.writer.write_f32::<LittleEndian>(value)?)
        } else {
            Ok(self.writer.write_f32::<BigEndian>(value)?)
        }
    }

    pub fn write_bytes(&mut self, data: &[u8]) -> Result<()> {
        Ok(self.writer.write_all(data)?)
    }
}

#[allow(dead_code)]
impl<W: Seek> EndianWriter<W> {
    pub fn seek(&mut self, pos: SeekFrom) -> Result<u64> {
        Ok(self.writer.seek(pos)?)
    }

    pub fn position(&mut self) -> Result<u64> {
        Ok(self.writer.stream_position()?)
    }
}
