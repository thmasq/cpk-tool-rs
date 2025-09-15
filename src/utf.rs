use crate::endian::EndianReader;
use crate::error::{CpkError, Result};
use log::{debug, warn};
use std::io::{Cursor, SeekFrom};

#[derive(Debug, Clone)]
#[allow(dead_code)]
pub enum ColumnFlags {
    StorageNone = 0x00,
    StorageZero = 0x10,
    StorageConstant = 0x30,
    StoragePerRow = 0x50,
}

#[derive(Debug, Clone)]
#[allow(dead_code)]
pub enum ColumnType {
    UInt8 = 0x00,
    Int8 = 0x01,
    UInt16 = 0x02,
    Int16 = 0x03,
    UInt32 = 0x04,
    Int32 = 0x05,
    UInt64 = 0x06,
    Int64 = 0x07,
    Float = 0x08,
    String = 0x0A,
    Data = 0x0B,
}

#[derive(Debug, Clone)]
pub struct Column {
    pub flags: u8,
    pub name: String,
}

#[derive(Debug, Clone)]
#[allow(dead_code)]
pub enum CellValue {
    UInt8(u8),
    Int8(i8),
    UInt16(u16),
    Int16(i16),
    UInt32(u32),
    Int32(i32),
    UInt64(u64),
    Int64(i64),
    Float(f32),
    String(String),
    Data(Vec<u8>),
    None,
}

#[allow(dead_code)]
impl CellValue {
    pub fn as_u8(&self) -> Option<u8> {
        match self {
            CellValue::UInt8(v) => Some(*v),
            _ => None,
        }
    }

    pub fn as_u16(&self) -> Option<u16> {
        match self {
            CellValue::UInt16(v) => Some(*v),
            _ => None,
        }
    }

    pub fn as_u32(&self) -> Option<u32> {
        match self {
            CellValue::UInt32(v) => Some(*v),
            _ => None,
        }
    }

    pub fn as_u64(&self) -> Option<u64> {
        match self {
            CellValue::UInt64(v) => Some(*v),
            _ => None,
        }
    }

    pub fn as_string(&self) -> Option<&str> {
        match self {
            CellValue::String(s) => Some(s),
            _ => None,
        }
    }

    pub fn as_data(&self) -> Option<&[u8]> {
        match self {
            CellValue::Data(d) => Some(d),
            _ => None,
        }
    }
}

#[derive(Debug, Clone)]
pub struct Cell {
    pub value: CellValue,
    pub position: u64,
}

pub type Row = Vec<Cell>;

#[derive(Debug)]
pub struct Utf {
    pub table_size: u32,
    pub rows_offset: u64,
    pub strings_offset: u64,
    pub data_offset: u64,
    pub table_name: u32,
    pub num_columns: u16,
    pub row_length: u16,
    pub num_rows: u32,
    pub columns: Vec<Column>,
    pub rows: Vec<Row>,
}

impl Utf {
    pub fn new() -> Self {
        Self {
            table_size: 0,
            rows_offset: 0,
            strings_offset: 0,
            data_offset: 0,
            table_name: 0,
            num_columns: 0,
            row_length: 0,
            num_rows: 0,
            columns: Vec::new(),
            rows: Vec::new(),
        }
    }

    pub fn read_utf(&mut self, data: &[u8]) -> Result<()> {
        debug!(
            "UTF: Starting to read UTF data, buffer size: {}",
            data.len()
        );
        let mut reader = EndianReader::new(Cursor::new(data), false); // Big endian
        let offset = reader.position()?;
        debug!("UTF: Initial offset: {}", offset);

        // Check signature
        let signature = reader.read_bytes(4)?;
        if &signature != b"@UTF" {
            return Err(CpkError::InvalidUtfSignature);
        }
        debug!("UTF: Valid @UTF signature found");

        self.table_size = reader.read_u32()?;
        self.rows_offset = reader.read_u32()? as u64;
        self.strings_offset = reader.read_u32()? as u64;
        self.data_offset = reader.read_u32()? as u64;

        debug!(
            "UTF: Raw offsets - rows: {}, strings: {}, data: {}",
            self.rows_offset, self.strings_offset, self.data_offset
        );

        // Adjust offsets
        self.rows_offset += offset + 8;
        self.strings_offset += offset + 8;
        self.data_offset += offset + 8;

        debug!(
            "UTF: Adjusted offsets - rows: {}, strings: {}, data: {}",
            self.rows_offset, self.strings_offset, self.data_offset
        );

        self.table_name = reader.read_u32()?;
        self.num_columns = reader.read_u16()?;
        self.row_length = reader.read_u16()?;
        self.num_rows = reader.read_u32()?;

        debug!(
            "UTF: Table info - columns: {}, row_length: {}, rows: {}",
            self.num_columns, self.row_length, self.num_rows
        );

        // Validate offsets against buffer size
        if self.rows_offset > data.len() as u64 {
            return Err(CpkError::InvalidFormat(format!(
                "Rows offset ({}) exceeds buffer size ({})",
                self.rows_offset,
                data.len()
            )));
        }
        if self.strings_offset > data.len() as u64 {
            return Err(CpkError::InvalidFormat(format!(
                "Strings offset ({}) exceeds buffer size ({})",
                self.strings_offset,
                data.len()
            )));
        }
        if self.data_offset > data.len() as u64 {
            return Err(CpkError::InvalidFormat(format!(
                "Data offset ({}) exceeds buffer size ({})",
                self.data_offset,
                data.len()
            )));
        }

        // Read columns
        self.columns.clear();
        for i in 0..self.num_columns {
            debug!("UTF: Reading column {}", i);
            let flags = reader.read_u8()?;
            let flags = if flags == 0 {
                reader.seek(SeekFrom::Current(3))?;
                reader.read_u8()?
            } else {
                flags
            };

            let name_offset = reader.read_u32()?;
            debug!("UTF: Column {} name offset: {}", i, name_offset);

            // Safe string reading with bounds checking
            let name = if self.strings_offset + name_offset as u64 >= data.len() as u64 {
                warn!(
                    "UTF: Column {} name offset {} is beyond buffer, using default name",
                    i, name_offset
                );
                format!("Column{}", i)
            } else {
                match self.read_string_at(&mut reader, name_offset as u64) {
                    Ok(s) if !s.is_empty() => s,
                    _ => {
                        warn!("UTF: Failed to read column {} name, using default", i);
                        format!("Column{}", i)
                    }
                }
            };

            debug!("UTF: Column {} name: '{}'", i, name);
            self.columns.push(Column { flags, name });
        }

        // Read rows
        self.rows.clear();
        for row_idx in 0..self.num_rows {
            debug!("UTF: Reading row {}", row_idx);
            reader.seek(SeekFrom::Start(
                self.rows_offset + (row_idx as u64 * self.row_length as u64),
            ))?;

            let mut row = Vec::new();

            for col_idx in 0..self.num_columns {
                let column = &self.columns[col_idx as usize];
                let storage_flag = column.flags & 0xF0;
                debug!(
                    "UTF: Row {}, Column {} ({}), storage_flag: 0x{:02X}",
                    row_idx, col_idx, column.name, storage_flag
                );

                let cell = match storage_flag {
                    0x00 | 0x10 | 0x30 => {
                        // STORAGE_NONE, STORAGE_ZERO, STORAGE_CONSTANT
                        Cell {
                            value: CellValue::None,
                            position: reader.position()?,
                        }
                    }
                    0x50 => {
                        // STORAGE_PERROW
                        let column_type = column.flags & 0x0F;
                        let position = reader.position()?;
                        debug!(
                            "UTF: Reading PERROW data, type: 0x{:02X}, position: {}",
                            column_type, position
                        );

                        let value = match column_type {
                            0x00 | 0x01 => CellValue::UInt8(reader.read_u8()?),
                            0x02 | 0x03 => CellValue::UInt16(reader.read_u16()?),
                            0x04 | 0x05 => CellValue::UInt32(reader.read_u32()?),
                            0x06 | 0x07 => CellValue::UInt64(reader.read_u64()?),
                            0x08 => CellValue::Float(reader.read_f32()?),
                            0x0A => {
                                let str_offset = reader.read_u32()?;
                                debug!("UTF: String offset: {}", str_offset);
                                let string_value =
                                    self.read_string_at(&mut reader, str_offset as u64)?;
                                debug!("UTF: String value: '{}'", string_value);
                                CellValue::String(string_value)
                            }
                            0x0B => {
                                let data_offset = reader.read_u32()?;
                                let data_size = reader.read_u32()?;
                                debug!("UTF: Data offset: {}, size: {}", data_offset, data_size);
                                let data_value = self.read_data_at(
                                    &mut reader,
                                    data_offset as u64,
                                    data_size as usize,
                                )?;
                                CellValue::Data(data_value)
                            }
                            _ => {
                                return Err(CpkError::Parse(format!(
                                    "Unsupported column type: {}",
                                    column_type
                                )));
                            }
                        };

                        Cell { value, position }
                    }
                    _ => {
                        return Err(CpkError::Parse(format!(
                            "Unknown storage flag: {}",
                            storage_flag
                        )));
                    }
                };

                row.push(cell);
            }

            self.rows.push(row);
        }

        debug!("UTF: Successfully parsed UTF data");
        Ok(())
    }

    fn read_string_at(
        &self,
        reader: &mut EndianReader<Cursor<&[u8]>>,
        offset: u64,
    ) -> Result<String> {
        let current_pos = reader.position()?;
        let target_pos = self.strings_offset + offset;
        debug!(
            "UTF: read_string_at offset {}, target position: {}, current: {}",
            offset, target_pos, current_pos
        );

        reader.seek(SeekFrom::Start(target_pos))?;
        let result = reader.read_cstring(None)?;
        reader.seek(SeekFrom::Start(current_pos))?;
        Ok(result)
    }

    fn read_data_at(
        &self,
        reader: &mut EndianReader<Cursor<&[u8]>>,
        offset: u64,
        size: usize,
    ) -> Result<Vec<u8>> {
        let current_pos = reader.position()?;
        let target_pos = self.data_offset + offset;
        debug!(
            "UTF: read_data_at offset {}, size {}, target position: {}, current: {}",
            offset, size, target_pos, current_pos
        );

        reader.seek(SeekFrom::Start(target_pos))?;
        let result = reader.read_bytes(size)?;
        reader.seek(SeekFrom::Start(current_pos))?;
        Ok(result)
    }

    pub fn get_column_data(&self, row: usize, column_name: &str) -> Option<&CellValue> {
        let col_index = self.columns.iter().position(|c| c.name == column_name)?;
        self.rows.get(row)?.get(col_index).map(|cell| &cell.value)
    }

    pub fn get_column_position(&self, row: usize, column_name: &str) -> Option<u64> {
        let col_index = self.columns.iter().position(|c| c.name == column_name)?;
        self.rows.get(row)?.get(col_index).map(|cell| cell.position)
    }

    pub fn get_column_data_or_default(
        &self,
        row: usize,
        column_name: &str,
        default_type: u8,
    ) -> CellValue {
        match self.get_column_data(row, column_name) {
            Some(CellValue::None) | None => match default_type {
                0 => CellValue::UInt8(0xFF),
                1 => CellValue::UInt16(0xFFFF),
                2 => CellValue::UInt32(0xFFFFFFFF),
                3 => CellValue::UInt64(0xFFFFFFFFFFFFFFFF),
                _ => CellValue::None,
            },
            Some(value) => value.clone(),
        }
    }
}
