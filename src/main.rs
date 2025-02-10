use std::{
    env,
    fs::{self, File},
    io::{self, BufReader, Read, Seek, SeekFrom, Write},
    path::Path,
};

struct PackageHeader {
    version: u32,
    tree_size: u32,
    file_data_section_size: u32,
    archive_md5_section_size: u32,
    other_md5_section_size: u32,
    signature_section_size: u32,
    header_size: u64,
}

struct PackageEntry {
    full_path: String,
    crc32: u32,
    small_data: Vec<u8>,
    archive_index: u16,
    offset: u32,
    length: u32,
}

fn read_u16<R: Read>(reader: &mut R) -> io::Result<u16> {
    let mut buf = [0; 2];
    reader.read_exact(&mut buf)?;
    Ok(u16::from_le_bytes(buf))
}

fn read_u32<R: Read>(reader: &mut R) -> io::Result<u32> {
    let mut buf = [0; 4];
    reader.read_exact(&mut buf)?;
    Ok(u32::from_le_bytes(buf))
}

fn read_null_terminated_string<R: Read>(reader: &mut R) -> io::Result<String> {
    let mut buf = Vec::new();
    loop {
        let mut byte = [0];
        reader.read_exact(&mut byte)?;
        if byte[0] == 0 {
            break;
        }
        buf.push(byte[0]);
    }
    Ok(String::from_utf8(buf).unwrap_or_default())
}

fn read_header<R: Read + Seek>(reader: &mut R) -> io::Result<PackageHeader> {
    let magic = read_u32(reader)?;
    if magic != 0x55AA1234 {
        return Err(io::Error::new(io::ErrorKind::InvalidData, "Invalid VPK signature"));
    }
    let version = read_u32(reader)?;
    let tree_size = read_u32(reader)?;
    let (mut file_data_section_size, mut archive_md5_section_size, mut other_md5_section_size, mut signature_section_size) = (0, 0, 0, 0);
    if version == 1 {
        // ничего доп.
    } else if version == 2 {
        file_data_section_size = read_u32(reader)?;
        archive_md5_section_size = read_u32(reader)?;
        other_md5_section_size = read_u32(reader)?;
        signature_section_size = read_u32(reader)?;
    } else if version == 0x00030002 {
        return Err(io::Error::new(io::ErrorKind::InvalidData, "Customized VPK not supported"));
    } else {
        return Err(io::Error::new(io::ErrorKind::InvalidData, format!("Bad VPK version: {}", version)));
    }
    let header_size = reader.stream_position()?;
    Ok(PackageHeader {
        version,
        tree_size,
        file_data_section_size,
        archive_md5_section_size,
        other_md5_section_size,
        signature_section_size,
        header_size,
    })
}

fn read_entries<R: Read>(reader: &mut R) -> io::Result<Vec<PackageEntry>> {
    let mut entries = Vec::new();
    loop {
        let type_name = read_null_terminated_string(reader)?;
        if type_name.is_empty() {
            break;
        }
        loop {
            let directory_name = read_null_terminated_string(reader)?;
            if directory_name.is_empty() {
                break;
            }
            loop {
                let file_name = read_null_terminated_string(reader)?;
                if file_name.is_empty() {
                    break;
                }
                let crc32 = read_u32(reader)?;
                let small_data_size = read_u16(reader)?;
                let archive_index = read_u16(reader)?;
                let offset = read_u32(reader)?;
                let length = read_u32(reader)?;
                let terminator = read_u16(reader)?;
                if terminator != 0xFFFF {
                    return Err(io::Error::new(io::ErrorKind::InvalidData, "Invalid terminator"));
                }
                let mut small_data = vec![0u8; small_data_size as usize];
                if small_data_size > 0 {
                    reader.read_exact(&mut small_data)?;
                }
                let full_path = if directory_name == " " {
                    format!("{}.{}", file_name, type_name)
                } else {
                    format!("{}/{}.{}", directory_name, file_name, type_name)
                };
                entries.push(PackageEntry {
                    full_path,
                    crc32,
                    small_data,
                    archive_index,
                    offset,
                    length,
                });
            }
        }
    }
    Ok(entries)
}

fn main() -> io::Result<()> {
    let args: Vec<String> = env::args().skip(1).collect();
    if args.len() < 2 {
        eprintln!("Usage: vpk_unpacker <source.vpk> <target_dir>");
        return Ok(());
    }
    let source = &args[0];
    let target = &args[1];

    if !Path::new(source).exists() {
        eprintln!("Source file not found.");
        return Ok(());
    }
    if !Path::new(target).exists() {
        fs::create_dir_all(target)?;
    }

    let file = File::open(source)?;
    let mut reader = BufReader::new(file);

    let header = read_header(&mut reader)?;
    let entries = read_entries(&mut reader)?;

    // Определяем начало секции с данными файлов:
    let file_data_section_offset = header.header_size + header.tree_size as u64;

    for entry in entries {
        // Работаем только с неразбитым VPK (archive_index == 0x7FFF)
        if entry.archive_index != 0x7FFF {
            continue;
        }
        let mut output = entry.small_data.clone();
        if entry.length > 0 {
            let pos = file_data_section_offset + entry.offset as u64;
            let current = reader.stream_position()?;
            reader.seek(SeekFrom::Start(pos))?;
            let mut data = vec![0u8; entry.length as usize];
            reader.read_exact(&mut data)?;
            output.extend_from_slice(&data);
            reader.seek(SeekFrom::Start(current))?;
        }
        let out_path = Path::new(target).join(&entry.full_path);
        if let Some(parent) = out_path.parent() {
            fs::create_dir_all(parent)?;
        }
        fs::write(out_path, output)?;
    }

    println!("All files extracted.");
    Ok(())
}
