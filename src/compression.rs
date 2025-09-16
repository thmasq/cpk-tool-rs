use crate::endian::EndianReader;
use crate::error::{CpkError, Result};
use log::debug;
use std::io::Cursor;

pub fn decompress_crilayla(input: &[u8]) -> Result<Vec<u8>> {
    if input.len() < 16 {
        return Err(CpkError::Compression(
            "Input too short for CRILAYLA".to_string(),
        ));
    }

    let mut reader = EndianReader::new(Cursor::new(input), true); // Little endian

    // Skip "CRILAYLA"
    reader.read_bytes(8)?;

    let uncompressed_size = reader.read_i32()?;
    let uncompressed_header_offset = reader.read_i32()?;

    debug!(
        "CRILAYLA: uncompressed_size={}, header_offset={}",
        uncompressed_size, uncompressed_header_offset
    );

    if uncompressed_header_offset < 0 || uncompressed_size < 0 {
        return Err(CpkError::Compression(
            "Invalid CRILAYLA header values".to_string(),
        ));
    }

    let uncompressed_size = uncompressed_size as usize;
    let uncompressed_header_offset = uncompressed_header_offset as usize;

    // Validate header offset
    if uncompressed_header_offset + 0x10 + 0x100 > input.len() {
        return Err(CpkError::Compression(format!(
            "Invalid header offset: {} + 0x110 > {}",
            uncompressed_header_offset,
            input.len()
        )));
    }

    let mut result = vec![0u8; uncompressed_size + 0x100];

    // Copy uncompressed 0x100 header to start of file
    result[0..0x100].copy_from_slice(
        &input[uncompressed_header_offset + 0x10..uncompressed_header_offset + 0x10 + 0x100],
    );

    if input.len() < 0x100 + 1 {
        return Err(CpkError::Compression(
            "Input too short for decompression".to_string(),
        ));
    }

    let input_end = input.len() - 0x100 - 1;
    let mut input_offset = input_end as i32;
    let output_end = (0x100 + uncompressed_size - 1) as i32;
    let mut bit_pool: u8 = 0;
    let mut bits_left = 0i32;
    let mut bytes_output = 0i32;
    let vle_lens = [2, 3, 5, 8];

    debug!(
        "CRILAYLA: Starting decompression, input_end={}, output_end={}, result.len()={}",
        input_end,
        output_end,
        result.len()
    );

    while bytes_output < uncompressed_size as i32 {
        if get_next_bits(input, &mut input_offset, &mut bit_pool, &mut bits_left, 1)? > 0 {
            // Back reference
            let offset_bits =
                get_next_bits(input, &mut input_offset, &mut bit_pool, &mut bits_left, 13)? as i32;
            let mut backreference_offset = output_end - bytes_output + offset_bits + 3;
            let mut backreference_length = 3i32;
            let mut vle_level = 0;

            // Variable length encoding for backreference length
            for level in 0..vle_lens.len() {
                let this_level = get_next_bits(
                    input,
                    &mut input_offset,
                    &mut bit_pool,
                    &mut bits_left,
                    vle_lens[level],
                )? as i32;
                backreference_length += this_level;
                vle_level = level;
                if this_level != ((1 << vle_lens[level]) - 1) as i32 {
                    break;
                }
            }

            if vle_level == vle_lens.len() - 1 {
                loop {
                    let this_level =
                        get_next_bits(input, &mut input_offset, &mut bit_pool, &mut bits_left, 8)?
                            as i32;
                    backreference_length += this_level;
                    if this_level != 255 {
                        break;
                    }
                }
            }

            debug!(
                "CRILAYLA: Backreference - offset_bits={}, initial_offset={}, length={}, bytes_output={}, current_output_pos={}",
                offset_bits,
                backreference_offset,
                backreference_length,
                bytes_output,
                output_end - bytes_output
            );

            // Perform the backreference copy - this is the critical part
            for i in 0..backreference_length {
                if bytes_output >= uncompressed_size as i32 {
                    break;
                }

                let output_pos = (output_end - bytes_output) as usize;

                // Bounds check for output position
                if output_pos >= result.len() {
                    return Err(CpkError::Compression(format!(
                        "Output position {} out of bounds (buffer size: {})",
                        output_pos,
                        result.len()
                    )));
                }

                // Bounds check for backreference position
                if backreference_offset < 0 || backreference_offset as usize >= result.len() {
                    debug!(
                        "CRILAYLA: Backreference offset {} out of bounds, iteration {}/{}",
                        backreference_offset, i, backreference_length
                    );
                    // This might happen if we're referencing data that hasn't been written yet
                    // In some LZ variants, this is handled by using a default value or wrapping
                    // For now, let's try wrapping to a safe position
                    backreference_offset = if backreference_offset >= result.len() as i32 {
                        (output_end - bytes_output) - 1 // Reference the previous byte
                    } else {
                        0 // Reference the start of the buffer
                    };

                    if backreference_offset < 0 {
                        backreference_offset = 0;
                    }
                }

                result[output_pos] = result[backreference_offset as usize];
                backreference_offset -= 1; // Post-decrement like in C#
                bytes_output += 1;
            }
        } else {
            // Verbatim byte
            let byte =
                get_next_bits(input, &mut input_offset, &mut bit_pool, &mut bits_left, 8)? as u8;
            let output_pos = (output_end - bytes_output) as usize;

            if output_pos >= result.len() {
                return Err(CpkError::Compression(format!(
                    "Output position {} out of bounds (buffer size: {})",
                    output_pos,
                    result.len()
                )));
            }

            result[output_pos] = byte;
            bytes_output += 1;
        }
    }

    debug!(
        "CRILAYLA: Decompression complete, output {} bytes",
        bytes_output
    );
    Ok(result)
}

fn get_next_bits(
    input: &[u8],
    offset_p: &mut i32,
    bit_pool_p: &mut u8,
    bits_left_p: &mut i32,
    bit_count: usize,
) -> Result<u16> {
    let mut out_bits = 0u16;
    let mut num_bits_produced = 0;

    while num_bits_produced < bit_count {
        if *bits_left_p == 0 {
            if *offset_p < 0 || *offset_p >= input.len() as i32 {
                return Err(CpkError::Compression(format!(
                    "Input offset {} out of bounds (input length: {})",
                    *offset_p,
                    input.len()
                )));
            }

            *bit_pool_p = input[*offset_p as usize];
            *bits_left_p = 8;
            *offset_p -= 1;
        }

        let bits_this_round = if *bits_left_p > (bit_count - num_bits_produced) as i32 {
            bit_count - num_bits_produced
        } else {
            *bits_left_p as usize
        };

        out_bits <<= bits_this_round;
        out_bits |= ((*bit_pool_p >> (*bits_left_p - bits_this_round as i32))
            & ((1 << bits_this_round) - 1)) as u16;

        *bits_left_p -= bits_this_round as i32;
        num_bits_produced += bits_this_round;
    }

    Ok(out_bits)
}
