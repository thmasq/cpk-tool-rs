use crate::endian::EndianReader;
use crate::error::{CpkError, Result};
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

    let uncompressed_size = reader.read_u32()? as usize;
    let uncompressed_header_offset = reader.read_u32()? as usize;

    if uncompressed_header_offset + 0x100 > input.len() {
        return Err(CpkError::Compression("Invalid header offset".to_string()));
    }

    let mut result = vec![0u8; uncompressed_size + 0x100];

    // Copy uncompressed header
    result[0..0x100].copy_from_slice(
        &input[uncompressed_header_offset + 0x10..uncompressed_header_offset + 0x110],
    );

    let input_end = input.len() - 0x100 - 1;
    let mut input_offset = input_end;
    let output_end = 0x100 + uncompressed_size - 1;
    let mut bit_pool = 0u8;
    let mut bits_left = 0;
    let mut bytes_output = 0;
    let vle_lens = [2, 3, 5, 8];

    while bytes_output < uncompressed_size {
        if get_next_bits(input, &mut input_offset, &mut bit_pool, &mut bits_left, 1)? > 0 {
            // Back reference
            let backreference_offset = output_end - bytes_output
                + get_next_bits(input, &mut input_offset, &mut bit_pool, &mut bits_left, 13)?
                    as usize
                + 3;
            let mut backreference_length = 3;
            let mut vle_level = 0;

            for (level, &len) in vle_lens.iter().enumerate() {
                let this_level =
                    get_next_bits(input, &mut input_offset, &mut bit_pool, &mut bits_left, len)?;
                backreference_length += this_level as usize;
                vle_level = level;
                if this_level != ((1 << len) - 1) {
                    break;
                }
            }

            if vle_level == vle_lens.len() - 1 {
                loop {
                    let this_level =
                        get_next_bits(input, &mut input_offset, &mut bit_pool, &mut bits_left, 8)?;
                    backreference_length += this_level as usize;
                    if this_level != 255 {
                        break;
                    }
                }
            }

            for _ in 0..backreference_length {
                if bytes_output >= uncompressed_size {
                    break;
                }
                result[output_end - bytes_output] = result[backreference_offset.wrapping_sub(1)];
                bytes_output += 1;
            }
        } else {
            // Verbatim byte
            let byte = get_next_bits(input, &mut input_offset, &mut bit_pool, &mut bits_left, 8)?;
            result[output_end - bytes_output] = byte as u8;
            bytes_output += 1;
        }
    }

    Ok(result)
}

fn get_next_bits(
    input: &[u8],
    offset: &mut usize,
    bit_pool: &mut u8,
    bits_left: &mut usize,
    bit_count: usize,
) -> Result<u16> {
    let mut out_bits = 0u16;
    let mut num_bits_produced = 0;

    while num_bits_produced < bit_count {
        if *bits_left == 0 {
            if *offset == 0 {
                return Err(CpkError::Compression("Unexpected end of data".to_string()));
            }
            *bit_pool = input[*offset];
            *bits_left = 8;
            *offset = offset.saturating_sub(1);
        }

        let bits_this_round = if *bits_left > (bit_count - num_bits_produced) {
            bit_count - num_bits_produced
        } else {
            *bits_left
        };

        out_bits <<= bits_this_round;
        out_bits |=
            ((*bit_pool >> (*bits_left - bits_this_round)) & ((1 << bits_this_round) - 1)) as u16;

        *bits_left -= bits_this_round;
        num_bits_produced += bits_this_round;
    }

    Ok(out_bits)
}
