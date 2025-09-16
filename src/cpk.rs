use crate::compression::decompress_crilayla;
use crate::endian::EndianReader;
use crate::error::{CpkError, Result};
use crate::utf::{CellValue, Utf};
use log::{debug, info, warn};
use std::collections::HashMap;
use std::fs::{File, create_dir_all};
use std::io::{BufReader, Read, Seek, SeekFrom};
use std::path::Path;

#[derive(Debug, Clone)]
pub struct FileEntry {
    pub dir_name: Option<String>,
    pub file_name: String,
    pub file_size: u64,
    pub file_size_pos: u64,
    pub extract_size: Option<u64>,
    pub extract_size_pos: Option<u64>,
    pub file_offset: u64,
    pub file_offset_pos: u64,
    pub id: Option<u32>,
    pub user_string: Option<String>,
    pub local_dir: Option<String>,
    pub toc_name: String,
    pub file_type: String,
    pub encrypted: bool,
    pub offset: u64,
}

impl FileEntry {
    pub fn new() -> Self {
        Self {
            dir_name: None,
            file_name: String::new(),
            file_size: 0,
            file_size_pos: 0,
            extract_size: None,
            extract_size_pos: None,
            file_offset: 0,
            file_offset_pos: 0,
            id: None,
            user_string: None,
            local_dir: None,
            toc_name: String::new(),
            file_type: String::new(),
            encrypted: false,
            offset: 0,
        }
    }
}

#[derive(Debug)]
#[allow(dead_code)]
pub struct Cpk {
    pub file_table: Vec<FileEntry>,
    pub cpk_data: HashMap<String, CellValue>,

    // Packet data
    cpk_packet: Vec<u8>,
    toc_packet: Option<Vec<u8>>,
    itoc_packet: Option<Vec<u8>>,
    etoc_packet: Option<Vec<u8>>,
    gtoc_packet: Option<Vec<u8>>,

    // Offsets
    toc_offset: u64,
    etoc_offset: u64,
    itoc_offset: u64,
    gtoc_offset: u64,
    content_offset: u64,
}

impl Cpk {
    pub fn new() -> Self {
        Self {
            file_table: Vec::new(),
            cpk_data: HashMap::new(),
            cpk_packet: Vec::new(),
            toc_packet: None,
            itoc_packet: None,
            etoc_packet: None,
            gtoc_packet: None,
            toc_offset: 0xFFFFFFFFFFFFFFFF,
            etoc_offset: 0xFFFFFFFFFFFFFFFF,
            itoc_offset: 0xFFFFFFFFFFFFFFFF,
            gtoc_offset: 0xFFFFFFFFFFFFFFFF,
            content_offset: 0,
        }
    }

    pub fn read_cpk<P: AsRef<Path>>(&mut self, path: P) -> Result<()> {
        let file = File::open(&path)?;
        let file_size = file.metadata()?.len();
        let mut reader = EndianReader::new(BufReader::new(file), false); // Start with big endian

        info!("File size: {} bytes", file_size);

        // Check CPK signature
        let signature = reader.read_bytes(4)?;
        debug!(
            "Signature: {:?}",
            std::str::from_utf8(&signature).unwrap_or("invalid")
        );
        if &signature != b"CPK " {
            return Err(CpkError::InvalidSignature);
        }

        // Read UTF data
        let current_pos = reader.position()?;
        debug!("Position before reading UTF data: {}", current_pos);

        let (utf_data, is_encrypted) = self.read_utf_data(&mut reader, file_size)?;
        self.cpk_packet = utf_data.clone();

        // Add CPK header entry
        let cpk_entry = FileEntry {
            file_name: "CPK_HDR".to_string(),
            file_offset: current_pos + 16, // After signature + header
            file_size: self.cpk_packet.len() as u64,
            encrypted: is_encrypted,
            file_type: "CPK".to_string(),
            toc_name: "CPK".to_string(),
            ..FileEntry::new()
        };
        self.file_table.push(cpk_entry);

        // Parse UTF data
        let mut utf = Utf::new();
        utf.read_utf(&utf_data)?;

        // Store CPK data
        for (i, column) in utf.columns.iter().enumerate() {
            if let Some(row) = utf.rows.first() {
                if let Some(cell) = row.get(i) {
                    self.cpk_data
                        .insert(column.name.clone(), cell.value.clone());
                }
            }
        }

        // Extract offsets
        self.toc_offset = self
            .get_column_data_or_default(&utf, 0, "TocOffset", 3)
            .as_u64()
            .unwrap_or(0xFFFFFFFFFFFFFFFF);
        self.etoc_offset = self
            .get_column_data_or_default(&utf, 0, "EtocOffset", 3)
            .as_u64()
            .unwrap_or(0xFFFFFFFFFFFFFFFF);
        self.itoc_offset = self
            .get_column_data_or_default(&utf, 0, "ItocOffset", 3)
            .as_u64()
            .unwrap_or(0xFFFFFFFFFFFFFFFF);
        self.gtoc_offset = self
            .get_column_data_or_default(&utf, 0, "GtocOffset", 3)
            .as_u64()
            .unwrap_or(0xFFFFFFFFFFFFFFFF);
        self.content_offset = self
            .get_column_data_or_default(&utf, 0, "ContentOffset", 3)
            .as_u64()
            .unwrap_or(0);

        debug!("TOC offset: 0x{:X}", self.toc_offset);
        debug!("ETOC offset: 0x{:X}", self.etoc_offset);
        debug!("ITOC offset: 0x{:X}", self.itoc_offset);
        debug!("GTOC offset: 0x{:X}", self.gtoc_offset);
        debug!("Content offset: 0x{:X}", self.content_offset);

        // Add content offset entry
        if self.content_offset != 0 {
            let content_entry = FileEntry {
                file_name: "CONTENT_OFFSET".to_string(),
                file_offset: self.content_offset,
                file_type: "CONTENT".to_string(),
                toc_name: "CPK".to_string(),
                ..FileEntry::new()
            };
            self.file_table.push(content_entry);
        }

        let files = self
            .get_column_data_or_default(&utf, 0, "Files", 2)
            .as_u32()
            .unwrap_or(0);
        let align = self
            .get_column_data_or_default(&utf, 0, "Align", 1)
            .as_u16()
            .unwrap_or(0x800);

        debug!("Files: {}", files);
        debug!("Align: 0x{:X}", align);

        // Read TOC if present
        if self.toc_offset != 0xFFFFFFFFFFFFFFFF {
            let toc_entry = FileEntry {
                file_name: "TOC_HDR".to_string(),
                file_offset: self.toc_offset,
                file_type: "HDR".to_string(),
                toc_name: "CPK".to_string(),
                ..FileEntry::new()
            };
            self.file_table.push(toc_entry);
            self.read_toc(&mut reader, file_size)?;
        }

        // Read ETOC if present
        if self.etoc_offset != 0xFFFFFFFFFFFFFFFF {
            let etoc_entry = FileEntry {
                file_name: "ETOC_HDR".to_string(),
                file_offset: self.etoc_offset,
                file_type: "HDR".to_string(),
                toc_name: "CPK".to_string(),
                ..FileEntry::new()
            };
            self.file_table.push(etoc_entry);
            self.read_etoc(&mut reader, file_size)?;
        }

        // Read ITOC if present
        if self.itoc_offset != 0xFFFFFFFFFFFFFFFF {
            let itoc_entry = FileEntry {
                file_name: "ITOC_HDR".to_string(),
                file_offset: self.itoc_offset,
                file_type: "HDR".to_string(),
                toc_name: "CPK".to_string(),
                ..FileEntry::new()
            };
            self.file_table.push(itoc_entry);
            self.read_itoc(&mut reader, align, file_size)?;
        }

        // Read GTOC if present
        if self.gtoc_offset != 0xFFFFFFFFFFFFFFFF {
            let gtoc_entry = FileEntry {
                file_name: "GTOC_HDR".to_string(),
                file_offset: self.gtoc_offset,
                file_type: "HDR".to_string(),
                toc_name: "CPK".to_string(),
                ..FileEntry::new()
            };
            self.file_table.push(gtoc_entry);
            self.read_gtoc(&mut reader, file_size)?;
        }

        Ok(())
    }

    fn read_utf_data<R: Read + Seek>(
        &self,
        reader: &mut EndianReader<R>,
        file_size: u64,
    ) -> Result<(Vec<u8>, bool)> {
        let pos_before_header = reader.position()?;
        reader.set_endian(true); // Little endian for header

        let _unk1 = reader.read_i32()?;
        let pos_after_unk1 = reader.position()?;

        let utf_size = reader.read_i64()?;
        let current_pos = reader.position()?;

        debug!("Position before UTF header: {}", pos_before_header);
        debug!("Position after unk1: {}", pos_after_unk1);
        debug!("UTF size: {} bytes", utf_size);
        debug!("Current position: {}", current_pos);
        debug!("Remaining bytes in file: {}", file_size - current_pos);

        // Validate UTF size
        if utf_size < 0 {
            return Err(CpkError::InvalidFormat("Negative UTF size".to_string()));
        }

        let utf_size = utf_size as u64;
        if current_pos + utf_size > file_size {
            return Err(CpkError::InvalidFormat(format!(
                "UTF size ({}) exceeds remaining file size ({})",
                utf_size,
                file_size - current_pos
            )));
        }

        if utf_size > 100_000_000 {
            return Err(CpkError::InvalidFormat(format!(
                "UTF size ({}) seems unreasonably large",
                utf_size
            )));
        }

        debug!("About to read {} bytes of UTF data", utf_size);
        let pos_before_read = reader.position()?;
        debug!("Position before reading UTF data: {}", pos_before_read);

        // Try to read the data
        let mut utf_packet = match reader.read_bytes(utf_size as usize) {
            Ok(data) => {
                debug!("Successfully read {} bytes of UTF data", data.len());
                data
            }
            Err(e) => {
                warn!("Failed to read UTF data: {}", e);
                debug!(
                    "Tried to read {} bytes from position {}",
                    utf_size, pos_before_read
                );
                debug!(
                    "File size: {}, bytes remaining: {}",
                    file_size,
                    file_size - pos_before_read
                );
                return Err(e);
            }
        };

        reader.set_endian(false); // Back to big endian

        // Check if encrypted
        let is_encrypted = !(utf_packet.len() >= 4
            && utf_packet[0] == 0x40
            && utf_packet[1] == 0x55
            && utf_packet[2] == 0x54
            && utf_packet[3] == 0x46); // @UTF

        if is_encrypted {
            debug!("UTF data is encrypted, decrypting...");
            utf_packet = self.decrypt_utf(&utf_packet);
        } else {
            debug!("UTF data is not encrypted");
        }

        // Verify the decrypted data starts with @UTF
        if utf_packet.len() < 4 || &utf_packet[0..4] != b"@UTF" {
            return Err(CpkError::InvalidFormat(
                "Invalid UTF signature after decryption".to_string(),
            ));
        }

        Ok((utf_packet, is_encrypted))
    }

    fn decrypt_utf(&self, input: &[u8]) -> Vec<u8> {
        let mut result = vec![0u8; input.len()];
        let mut m = 0x0000655f_u32;
        let t = 0x00004115_u32;

        for (i, &byte) in input.iter().enumerate() {
            result[i] = byte ^ (m & 0xff) as u8;
            m = m.wrapping_mul(t);
        }

        result
    }

    fn read_toc<R: Read + Seek>(
        &mut self,
        reader: &mut EndianReader<R>,
        file_size: u64,
    ) -> Result<()> {
        let f_toc_offset = if self.toc_offset > 0x800 {
            0x800
        } else {
            self.toc_offset
        };

        let add_offset = if self.content_offset == 0xFFFFFFFFFFFFFFFF {
            f_toc_offset
        } else if self.toc_offset == 0xFFFFFFFFFFFFFFFF {
            self.content_offset
        } else if self.content_offset < f_toc_offset {
            self.content_offset
        } else {
            f_toc_offset
        };

        reader.seek(SeekFrom::Start(self.toc_offset))?;

        let signature = reader.read_bytes(4)?;
        if &signature != b"TOC " {
            return Err(CpkError::InvalidFormat("Invalid TOC signature".to_string()));
        }

        let (utf_data, is_encrypted) = self.read_utf_data(reader, file_size)?;
        self.toc_packet = Some(utf_data.clone());

        // Update TOC header entry
        if let Some(entry) = self
            .file_table
            .iter_mut()
            .find(|e| e.file_name == "TOC_HDR")
        {
            entry.encrypted = is_encrypted;
            entry.file_size = utf_data.len() as u64;
        }

        let mut utf = Utf::new();
        utf.read_utf(&utf_data)?;

        // Parse file entries
        for row_idx in 0..utf.num_rows {
            let mut entry = FileEntry::new();
            entry.toc_name = "TOC".to_string();
            entry.file_type = "FILE".to_string();
            entry.offset = add_offset;

            if let Some(dir_name) = utf.get_column_data(row_idx as usize, "DirName") {
                entry.dir_name = dir_name.as_string().map(|s| s.to_string());
            }

            if let Some(file_name) = utf.get_column_data(row_idx as usize, "FileName") {
                entry.file_name = file_name.as_string().unwrap_or("").to_string();
            }

            if let Some(file_size) = utf.get_column_data(row_idx as usize, "FileSize") {
                debug!(
                    "Raw FileSize value for '{}': {:?}",
                    entry.file_name, file_size
                );
                entry.file_size = file_size.as_u64().unwrap_or(0);
                debug!(
                    "Converted FileSize for '{}': {}",
                    entry.file_name, entry.file_size
                );
                entry.file_size_pos = utf
                    .get_column_position(row_idx as usize, "FileSize")
                    .unwrap_or(0);
            } else {
                debug!("No FileSize column found for '{}'", entry.file_name);
            }

            if let Some(extract_size) = utf.get_column_data(row_idx as usize, "ExtractSize") {
                debug!(
                    "Raw ExtractSize value for '{}': {:?}",
                    entry.file_name, extract_size
                );
                entry.extract_size = extract_size.as_u64();
                debug!(
                    "Converted ExtractSize for '{}': {:?}",
                    entry.file_name, entry.extract_size
                );
                entry.extract_size_pos = utf.get_column_position(row_idx as usize, "ExtractSize");
            } else {
                debug!("No ExtractSize column found for '{}'", entry.file_name);
            }

            if let Some(file_offset) = utf.get_column_data(row_idx as usize, "FileOffset") {
                debug!(
                    "Raw FileOffset value for '{}': {:?}",
                    entry.file_name, file_offset
                );
                let base_offset = file_offset.as_u64().unwrap_or(0);
                entry.file_offset = base_offset + add_offset;
                debug!(
                    "Converted FileOffset for '{}': 0x{:X} (base: 0x{:X} + add_offset: 0x{:X})",
                    entry.file_name, entry.file_offset, base_offset, add_offset
                );
                entry.file_offset_pos = utf
                    .get_column_position(row_idx as usize, "FileOffset")
                    .unwrap_or(0);
            } else {
                debug!("No FileOffset column found for '{}'", entry.file_name);
            }

            if let Some(id) = utf.get_column_data(row_idx as usize, "ID") {
                entry.id = id.as_u32();
            }

            if let Some(user_string) = utf.get_column_data(row_idx as usize, "UserString") {
                entry.user_string = user_string.as_string().map(|s| s.to_string());
            }

            debug!(
                "Adding file entry: '{}' (size: {}, offset: 0x{:X})",
                entry.file_name, entry.file_size, entry.file_offset
            );

            self.file_table.push(entry);
        }

        Ok(())
    }

    fn read_etoc<R: Read + Seek>(
        &mut self,
        reader: &mut EndianReader<R>,
        file_size: u64,
    ) -> Result<()> {
        reader.seek(SeekFrom::Start(self.etoc_offset))?;

        let signature = reader.read_bytes(4)?;
        if &signature != b"ETOC" {
            return Err(CpkError::InvalidFormat(
                "Invalid ETOC signature".to_string(),
            ));
        }

        let (utf_data, is_encrypted) = self.read_utf_data(reader, file_size)?;
        self.etoc_packet = Some(utf_data.clone());

        // Update ETOC header entry
        if let Some(entry) = self
            .file_table
            .iter_mut()
            .find(|e| e.file_name == "ETOC_HDR")
        {
            entry.encrypted = is_encrypted;
            entry.file_size = utf_data.len() as u64;
        }

        let mut utf = Utf::new();
        utf.read_utf(&utf_data)?;

        // Update file entries with LocalDir information
        let file_indices: Vec<_> = self
            .file_table
            .iter()
            .enumerate()
            .filter(|(_, e)| e.file_type == "FILE")
            .map(|(idx, _)| idx)
            .collect();

        for (i, idx) in file_indices.into_iter().enumerate() {
            if let Some(local_dir) = utf.get_column_data(i, "LocalDir") {
                self.file_table[idx].local_dir = local_dir.as_string().map(|s| s.to_string());
            }
        }

        Ok(())
    }

    fn read_itoc<R: Read + Seek>(
        &mut self,
        reader: &mut EndianReader<R>,
        align: u16,
        file_size: u64,
    ) -> Result<()> {
        reader.seek(SeekFrom::Start(self.itoc_offset))?;

        let signature = reader.read_bytes(4)?;
        if &signature != b"ITOC" {
            return Err(CpkError::InvalidFormat(
                "Invalid ITOC signature".to_string(),
            ));
        }

        let (utf_data, is_encrypted) = self.read_utf_data(reader, file_size)?;
        self.itoc_packet = Some(utf_data.clone());

        // Update ITOC header entry
        if let Some(entry) = self
            .file_table
            .iter_mut()
            .find(|e| e.file_name == "ITOC_HDR")
        {
            entry.encrypted = is_encrypted;
            entry.file_size = utf_data.len() as u64;
        }

        let mut utf = Utf::new();
        utf.read_utf(&utf_data)?;

        // Read DataL and DataH
        let mut size_table = HashMap::new();
        let mut extract_size_table = HashMap::new();
        let mut ids = Vec::new();

        if let Some(data_l) = utf.get_column_data(0, "DataL") {
            if let Some(data_l_bytes) = data_l.as_data() {
                let mut data_utf = Utf::new();
                data_utf.read_utf(data_l_bytes)?;

                for row_idx in 0..data_utf.num_rows {
                    if let Some(id) = data_utf.get_column_data(row_idx as usize, "ID") {
                        if let Some(file_size) =
                            data_utf.get_column_data(row_idx as usize, "FileSize")
                        {
                            let id_val = id.as_u16().unwrap_or(0) as u32;
                            size_table.insert(id_val, file_size.as_u16().unwrap_or(0) as u64);
                            ids.push(id_val);
                        }
                        if let Some(extract_size) =
                            data_utf.get_column_data(row_idx as usize, "ExtractSize")
                        {
                            let id_val = id.as_u16().unwrap_or(0) as u32;
                            extract_size_table
                                .insert(id_val, extract_size.as_u16().unwrap_or(0) as u64);
                        }
                    }
                }
            }
        }

        if let Some(data_h) = utf.get_column_data(0, "DataH") {
            if let Some(data_h_bytes) = data_h.as_data() {
                let mut data_utf = Utf::new();
                data_utf.read_utf(data_h_bytes)?;

                for row_idx in 0..data_utf.num_rows {
                    if let Some(id) = data_utf.get_column_data(row_idx as usize, "ID") {
                        if let Some(file_size) =
                            data_utf.get_column_data(row_idx as usize, "FileSize")
                        {
                            let id_val = id.as_u16().unwrap_or(0) as u32;
                            size_table.insert(id_val, file_size.as_u32().unwrap_or(0) as u64);
                            if !ids.contains(&id_val) {
                                ids.push(id_val);
                            }
                        }
                        if let Some(extract_size) =
                            data_utf.get_column_data(row_idx as usize, "ExtractSize")
                        {
                            let id_val = id.as_u16().unwrap_or(0) as u32;
                            extract_size_table
                                .insert(id_val, extract_size.as_u32().unwrap_or(0) as u64);
                        }
                    }
                }
            }
        }

        // Sort IDs
        ids.sort();

        // Create file entries
        let mut base_offset = self.content_offset;
        for id in ids {
            let mut entry = FileEntry::new();
            entry.toc_name = "ITOC".to_string();
            entry.file_type = "FILE".to_string();
            entry.file_name = format!("{:04}", id);
            entry.id = Some(id);
            entry.file_offset = base_offset;

            if let Some(&file_size) = size_table.get(&id) {
                entry.file_size = file_size;
            }

            if let Some(&extract_size) = extract_size_table.get(&id) {
                entry.extract_size = Some(extract_size);
            }

            // Calculate next offset with alignment
            let file_size = entry.file_size;
            if file_size % align as u64 > 0 {
                base_offset += file_size + (align as u64 - (file_size % align as u64));
            } else {
                base_offset += file_size;
            }

            self.file_table.push(entry);
        }

        Ok(())
    }

    fn read_gtoc<R: Read + Seek>(
        &mut self,
        reader: &mut EndianReader<R>,
        _file_size: u64,
    ) -> Result<()> {
        reader.seek(SeekFrom::Start(self.gtoc_offset))?;

        let signature = reader.read_bytes(4)?;
        if &signature != b"GTOC" {
            return Err(CpkError::InvalidFormat(
                "Invalid GTOC signature".to_string(),
            ));
        }

        // Skip implementation for now (not commonly used)
        Ok(())
    }

    fn get_column_data_or_default(
        &self,
        utf: &Utf,
        row: usize,
        column_name: &str,
        default_type: u8,
    ) -> CellValue {
        utf.get_column_data_or_default(row, column_name, default_type)
    }

    pub fn extract_file<P: AsRef<Path>>(&self, cpk_path: P, target: &str) -> Result<()> {
        let target_lower = target.to_lowercase();
        let entries: Vec<_> = self
            .file_table
            .iter()
            .filter(|e| e.file_type == "FILE")
            .filter(|e| {
                let full_path = match (&e.dir_name, &e.file_name) {
                    (Some(dir), file_name) => format!("{}/{}", dir, file_name),
                    (None, file_name) => file_name.clone(),
                };
                full_path.to_lowercase() == target_lower
            })
            .collect();

        if entries.is_empty() {
            return Err(CpkError::FileNotFound(target.to_string()));
        }

        let file = File::open(cpk_path)?;
        let mut reader = BufReader::new(file);

        for entry in entries {
            self.extract_single_file(&mut reader, entry)?;
        }

        Ok(())
    }

    pub fn extract_all<P: AsRef<Path>>(&self, cpk_path: P) -> Result<()> {
        let file = File::open(cpk_path)?;
        let mut reader = BufReader::new(file);

        for entry in &self.file_table {
            if entry.file_type != "FILE" {
                continue;
            }
            self.extract_single_file(&mut reader, entry)?;
        }

        Ok(())
    }

    fn extract_single_file<R: Read + Seek>(&self, reader: &mut R, entry: &FileEntry) -> Result<()> {
        let output_path = match (&entry.dir_name, &entry.file_name) {
            (Some(dir), file_name) => {
                create_dir_all(dir)?;
                format!("{}/{}", dir, file_name)
            }
            (None, file_name) => file_name.clone(),
        };

        debug!("Extracting file: {}", output_path);
        debug!("  Offset: 0x{:X}", entry.file_offset);
        debug!("  Size: {}", entry.file_size);
        debug!("  Extract Size: {:?}", entry.extract_size);

        // Check for zero-sized files
        if entry.file_size == 0 {
            warn!("File {} has zero size, skipping", output_path);
            return Ok(());
        }

        // Seek to file position
        reader.seek(SeekFrom::Start(entry.file_offset))?;

        // Read the full file data
        let mut data = vec![0u8; entry.file_size as usize];
        match reader.read_exact(&mut data) {
            Ok(()) => {
                debug!("Successfully read {} bytes", data.len());
            }
            Err(e) => {
                return Err(CpkError::Io(e));
            }
        }

        // Check if file is compressed and decompress if needed
        if data.len() >= 8 && &data[0..8] == b"CRILAYLA" {
            info!(
                "Decompressing CRILAYLA file: {} (compressed size: {})",
                output_path,
                data.len()
            );

            // Read the uncompressed size from the header for validation
            if data.len() >= 16 {
                let uncompressed_size =
                    u32::from_le_bytes([data[8], data[9], data[10], data[11]]) as usize;
                let header_offset =
                    u32::from_le_bytes([data[12], data[13], data[14], data[15]]) as usize;

                debug!(
                    "CRILAYLA header: uncompressed_size={}, header_offset={}",
                    uncompressed_size, header_offset
                );

                // Validate the header makes sense
                if header_offset + 0x110 > data.len() {
                    return Err(CpkError::Compression(format!(
                        "Invalid CRILAYLA header: header_offset={} + 0x110 > data.len()={}",
                        header_offset,
                        data.len()
                    )));
                }
            }

            data = decompress_crilayla(&data)?;
            info!("Decompressed to {} bytes", data.len());
        }

        info!("Extracting: {} ({} bytes)", output_path, data.len());
        std::fs::write(&output_path, &data)?;

        Ok(())
    }

    pub fn replace_file<P: AsRef<Path>>(
        &mut self,
        _cpk_path: P,
        _target: &str,
        _replacement_path: P,
        _output_path: P,
    ) -> Result<()> {
        // This is a simplified implementation
        // A full implementation would need to handle UTF table updates
        Err(CpkError::Unsupported(
            "File replacement not yet implemented".to_string(),
        ))
    }
}
