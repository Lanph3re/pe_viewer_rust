use memmap::MmapOptions;
use std::{
    fs::File,
    io::{self, prelude::*},
};

// Module that contains PE Structs and functions
mod pe {
    // PE Header
    pub struct PeFile<'a> {
        pub map: &'a [u8],
        pub image_dos_header: ImageDosHeader,
        pub image_nt_header: ImageNtHeader,
    }

    // IMAGE_DOS_HEADER
    pub struct ImageDosHeader {
        e_magic: u16, // Should be MZ
        e_cblp: u16,
        e_cp: u16,
        e_crlc: u16,
        e_cparhdr: u16,
        e_minalloc: u16,
        e_maxalloc: u16,
        e_ss: u16,
        e_sp: u16,
        e_csum: u16,
        e_ip: u16,
        e_cs: u16,
        e_lfarlc: u16,
        e_ovno: u16,
        e_res: [u16; 4],
        e_oemid: u16,
        e_oeminfo: u16,
        e_res2: [u16; 10],
        e_lfanew: u32, // Offset to IMAGE_NT_HEADER
    }

    // Characteristics in IMAGE_FILE_HEADER
    const CHARACTERISTICS: [(&str, u16); 16] = [
        ("IMAGE_FILE_RELOCS_STRIPPED", 0x0001),
        ("IMAGE_FILE_EXECUTABLE_IMAGE", 0x0002),
        ("IMAGE_FILE_LINE_NUMS_STRIPPED", 0x0004),
        ("IMAGE_FILE_LOCAL_SYMS_STRIPPED", 0x0008),
        ("IMAGE_FILE_AGGRESIVE_WS_TRIM", 0x0010),
        ("IMAGE_FILE_LARGE_ADDRESS_AWARE", 0x0020),
        ("IMAGE_FILE_16BIT_MACHINE", 0x0040),
        ("IMAGE_FILE_BYTES_REVERSED_LO", 0x0080),
        ("IMAGE_FILE_32BIT_MACHINE", 0x0100),
        ("IMAGE_FILE_DEBUG_STRIPPED", 0x0200),
        ("IMAGE_FILE_REMOVABLE_RUN_FROM_SWAP", 0x0400),
        ("IMAGE_FILE_NET_RUN_FROM_SWAP", 0x08000),
        ("IMAGE_FILE_SYSTEM", 0x1000),
        ("IMAGE_FILE_DLL", 0x2000),
        ("IMAGE_FILE_UP_SYSTEM_ONLY", 0x4000),
        ("IMAGE_FILE_BYTES_REVERSED_HI", 0x8000),
    ];

    // Machine filed in IMAGE_FILE_HEADER
    const MACHINE: [(&str, u16); 32] = [
        ("UNKNOWN", 0x0),
        ("I860", 0x014d),
        ("I386", 0x014c),
        ("R3000", 0x0162),
        ("R4000", 0x0166),
        ("R10000", 0x0168),
        ("WCEMIPSV2", 0x0169),
        ("ALPHA", 0x0184),
        ("SH3", 0x01a2),
        ("SH3DSP", 0x01a3),
        ("SH3E", 0x01a4),
        ("SH4", 0x01a6),
        ("SH5", 0x01a8),
        ("ARM", 0x01c0),
        ("THUMB", 0x01c2),
        ("ARMNT", 0x01c4),
        ("ARM64", 0xaa64),
        ("AM33", 0x01d3),
        ("POWERPC", 0x01f0),
        ("POWERPCFP", 0x01f1),
        ("IA64", 0x0200),
        ("MIPS16", 0x0266),
        ("ALPHA64", 0x0284),
        ("MIPSFPU", 0x0366),
        ("MIPSFPU16", 0x0466),
        ("AXP64", 0x0284),
        ("TRICORE", 0x0520),
        ("CEF", 0x0cef),
        ("EBC", 0x0ebc),
        ("AMD64", 0x8664),
        ("M32R", 0x9041),
        ("CEE", 0xc0e),
    ];

    // IMAGE_FILE_HEADER
    struct ImageFileHeader {
        machine: u16,
        number_of_sections: u16,
        time_data_stamp: u32,
        pointer_to_symbol_table: u32,
        number_of_symbols: u32,
        size_of_optional_header: u16,
        characteristics: u16,
    }

    // IMAGE_DATA_DIRECTORY
    struct ImageDataDirectory {
        virtual_address: u32,
        size: u32,
    }

    impl Default for ImageDataDirectory {
        fn default() -> Self {
            Self {
                virtual_address: 0,
                size: 0,
            }
        }
    }

    // IMAGE_OPTIONAL_HEADER
    // Binary has one of two structs in this enum
    // based on file(32bit or 64bit)
    const IMAGE_NUMBEROF_DIRECTORY_ENTRIES: usize = 16;

    enum ImageOptionalHeader {
        ImageOptionalHeader32 {
            magic: u16,
            major_linker_version: u8,
            minor_linker_version: u8,
            size_of_code: u32,
            size_of_initialized_data: u32,
            size_of_uninitialized_data: u32,
            address_of_entry_point: u32,
            base_of_code: u32,
            base_of_data: u32,
            image_base: u32,
            section_alignment: u32,
            file_alignment: u32,
            major_operating_system_version: u16,
            minor_operating_system_version: u16,
            major_image_version: u16,
            minor_image_version: u16,
            major_subsystem_version: u16,
            minor_subsystem_version: u16,
            win32_version_value: u32,
            size_of_image: u32,
            size_of_headers: u32,
            checksum: u32,
            subsystem: u16,
            dll_characteristics: u16,
            size_of_stack_reserve: u32,
            size_of_stack_commit: u32,
            size_of_heap: u32,
            size_of_heap_commit: u32,
            loader_flags: u32,
            number_of_rva_and_sizes: u32,
            data_directory: [ImageDataDirectory; IMAGE_NUMBEROF_DIRECTORY_ENTRIES],
        },
        ImageOptionalHeader64 {
            magic: u16,
            major_linker_version: u8,
            minor_linker_version: u8,
            size_of_code: u32,
            size_of_initialized_data: u32,
            size_of_uninitialized_data: u32,
            address_of_entry_point: u32,
            base_of_code: u32,
            image_base: u64,
            section_alignment: u32,
            file_alignment: u32,
            major_operating_system_version: u16,
            minor_operating_system_version: u16,
            major_image_version: u16,
            minor_image_version: u16,
            major_subsystem_version: u16,
            minor_subsystem_version: u16,
            win32_version_value: u32,
            size_of_image: u32,
            size_of_headers: u32,
            checksum: u32,
            subsystem: u16,
            dll_characteristics: u16,
            size_of_stack_reserve: u64,
            size_of_stack_commit: u64,
            size_of_heap: u64,
            size_of_heap_commit: u64,
            loader_flags: u32,
            number_of_rva_and_sizes: u32,
            data_directory: [ImageDataDirectory; IMAGE_NUMBEROF_DIRECTORY_ENTRIES],
        },
    }

    pub struct ImageNtHeader {
        signature: u32, // PE Signature: 0x50450000 ("PE")
        image_file_header: ImageFileHeader,
        image_optional_header: ImageOptionalHeader,
    }

    impl<'a> PeFile<'a> {
        pub fn new(file: &'a [u8]) -> PeFile {
            let temp_dos = load_image_dos_header(file);

            let nt_offset = temp_dos.e_lfanew as usize;
            let temp_nt = load_image_nt_header(&file[nt_offset..]);

            let pe_file = PeFile {
                map: file,
                image_dos_header: temp_dos,
                image_nt_header: temp_nt,
            };

            pe_file
        }

        pub fn print_hex_dump(&self) {
            let mut cut = 0;

            for byte in self.map.iter() {
                if cut % 16 == 0 {
                    print!("\n{:08X} |", cut);
                }

                print!(" {:02X}", byte);

                cut = cut + 1;
            }

            println!("\n");
        }

        pub fn print_image_dos_header(&self) {
            let h = &self.image_dos_header;

            println!("\nIMAGE_DOS_HEADER");
            println!("==========================================");
            println!(
                "Signature                    : {:#04X}{}",
                h.e_magic,
                if h.e_magic == 0x5A4D { " 'MZ'" } else { "" }
            );
            println!("Bytes one Last Page of File  : {:#04X}", h.e_cblp);
            println!("Pages in File                : {:#04X}", h.e_cp);
            println!("Relocations                  : {:#04X}", h.e_crlc);
            println!("Size of Header in Paragraphs : {:#04X}", h.e_cparhdr);
            println!("Minimum Extra Paragraphs     : {:#04X}", h.e_minalloc);
            println!("Maximum Extra Paragraphs     : {:#04X}", h.e_maxalloc);
            println!("Initial(relative) SS         : {:#04X}", h.e_ss);
            println!("Initial SP                   : {:#04X}", h.e_sp);
            println!("Checksum                     : {:#04X}", h.e_csum);
            println!("Initial IP                   : {:#04X}", h.e_ip);
            println!("Initial(relative) CS         : {:#04X}", h.e_cs);
            println!("Offset to Relocation Table   : {:#04X}", h.e_lfarlc);
            println!("Reserved                     : {:#04X}", h.e_res[0]);
            println!("Overlay Number               : {:#04X}", h.e_ovno);
            println!("OEM Identifier               : {:#04X}", h.e_oemid);
            println!("OEM Information              : {:#04X}", h.e_oeminfo);
            println!("Reserved                     : {:#04X}", h.e_res2[0]);
            println!("Offset to New EXE Header     : {:#04X}\n", h.e_lfanew);
        }

        pub fn print_image_nt_header(&self) {
            let h = &self.image_nt_header;

            println!("\nIMAGE_NT_HEADER");
            println!("============================================");
            println!(
                "Signature                    : {:#08X}{}",
                h.signature,
                if h.signature == 0x4550 { " 'PE'" } else { "" }
            );
            println!("IMAGE_FILE_HEADER");

            // Find machine name
            let name: &str = {
                let mut tmp: &str = "";

                for machine in MACHINE.iter() {
                    if h.image_file_header.machine == machine.1 {
                        tmp = machine.0;
                    }
                }
                tmp
            };

            println!(
                "    Machine                  : {:#04X} '{}'",
                h.image_file_header.machine, name
            );
            println!(
                "    Number of Sections       : {:#04X}",
                h.image_file_header.number_of_sections
            );
            println!(
                "    Time Date Stamp          : {:#08X}",
                h.image_file_header.time_data_stamp
            );
            println!(
                "    Pointer to Symbol Table  : {:#08X}",
                h.image_file_header.pointer_to_symbol_table
            );
            println!(
                "    Number of Symbols        : {:#08X}",
                h.image_file_header.number_of_symbols
            );
            println!(
                "    Size of Optional Header  : {:#04X}",
                h.image_file_header.size_of_optional_header
            );

            // Find chracteristics of binary
            let mut characteristics = String::new();
            for characteristic in CHARACTERISTICS.iter() {
                if (h.image_file_header.characteristics & characteristic.1) != 0 {
                    characteristics += "\n        ";
                    characteristics += characteristic.0;
                }
            }
            print!(
                "    Characteristics          : {:#04X}",
                h.image_file_header.characteristics
            );
            println!("        {}", characteristics);
            match &h.image_optional_header {
                ImageOptionalHeader::ImageOptionalHeader32 {
                    magic,
                    major_linker_version,
                    minor_linker_version,
                    size_of_code,
                    size_of_initialized_data,
                    size_of_uninitialized_data,
                    address_of_entry_point,
                    base_of_code,
                    base_of_data,
                    image_base,
                    section_alignment,
                    file_alignment,
                    major_operating_system_version,
                    minor_operating_system_version,
                    major_image_version,
                    minor_image_version,
                    major_subsystem_version,
                    minor_subsystem_version,
                    win32_version_value,
                    size_of_image,
                    size_of_headers,
                    checksum,
                    subsystem,
                    dll_characteristics,
                    size_of_stack_reserve,
                    size_of_stack_commit,
                    size_of_heap,
                    size_of_heap_commit,
                    loader_flags,
                    number_of_rva_and_sizes,
                    data_directory,
                } => {
                    println!("IMAGE_OPTIONAL_HEADER32");
                }
                ImageOptionalHeader::ImageOptionalHeader64 {
                    magic,
                    major_linker_version,
                    minor_linker_version,
                    size_of_code,
                    size_of_initialized_data,
                    size_of_uninitialized_data,
                    address_of_entry_point,
                    base_of_code,
                    image_base,
                    section_alignment,
                    file_alignment,
                    major_operating_system_version,
                    minor_operating_system_version,
                    major_image_version,
                    minor_image_version,
                    major_subsystem_version,
                    minor_subsystem_version,
                    win32_version_value,
                    size_of_image,
                    size_of_headers,
                    checksum,
                    subsystem,
                    dll_characteristics,
                    size_of_stack_reserve,
                    size_of_stack_commit,
                    size_of_heap,
                    size_of_heap_commit,
                    loader_flags,
                    number_of_rva_and_sizes,
                    data_directory,
                } => {
                    println!("IMAGE_OPTIONAL_HEADER64");
                }
            }
        }
    }


    use byteorder::{LittleEndian, ReadBytesExt};
    use std::io::Cursor;
    pub fn load_image_dos_header(file: &[u8]) -> ImageDosHeader {
        let mut cursor = Cursor::new(file);

        let image_dos_header = ImageDosHeader {
            e_magic: cursor.read_u16::<LittleEndian>().unwrap(),
            e_cblp: cursor.read_u16::<LittleEndian>().unwrap(),
            e_cp: cursor.read_u16::<LittleEndian>().unwrap(),
            e_crlc: cursor.read_u16::<LittleEndian>().unwrap(),
            e_cparhdr: cursor.read_u16::<LittleEndian>().unwrap(),
            e_minalloc: cursor.read_u16::<LittleEndian>().unwrap(),
            e_maxalloc: cursor.read_u16::<LittleEndian>().unwrap(),
            e_ss: cursor.read_u16::<LittleEndian>().unwrap(),
            e_sp: cursor.read_u16::<LittleEndian>().unwrap(),
            e_csum: cursor.read_u16::<LittleEndian>().unwrap(),
            e_ip: cursor.read_u16::<LittleEndian>().unwrap(),
            e_cs: cursor.read_u16::<LittleEndian>().unwrap(),
            e_lfarlc: cursor.read_u16::<LittleEndian>().unwrap(),
            e_ovno: cursor.read_u16::<LittleEndian>().unwrap(),
            e_res: {
                let mut tmp: [u16; 4] = [0; 4];
                cursor.read_u16_into::<LittleEndian>(&mut tmp).unwrap();
                tmp
            },
            e_oemid: cursor.read_u16::<LittleEndian>().unwrap(),
            e_oeminfo: cursor.read_u16::<LittleEndian>().unwrap(),
            e_res2: {
                let mut tmp: [u16; 10] = [0; 10];
                cursor.read_u16_into::<LittleEndian>(&mut tmp).unwrap();
                tmp
            },
            e_lfanew: cursor.read_u32::<LittleEndian>().unwrap(),
        };

        image_dos_header
    }

    pub fn load_image_nt_header(file: &[u8]) -> ImageNtHeader {
        let mut cursor = Cursor::new(file);

        let temp_signature = cursor.read_u32::<LittleEndian>().unwrap();

        let temp_file = ImageFileHeader {
            machine: cursor.read_u16::<LittleEndian>().unwrap(),
            number_of_sections: cursor.read_u16::<LittleEndian>().unwrap(),
            time_data_stamp: cursor.read_u32::<LittleEndian>().unwrap(),
            pointer_to_symbol_table: cursor.read_u32::<LittleEndian>().unwrap(),
            number_of_symbols: cursor.read_u32::<LittleEndian>().unwrap(),
            size_of_optional_header: cursor.read_u16::<LittleEndian>().unwrap(),
            characteristics: cursor.read_u16::<LittleEndian>().unwrap(),
        };

        let temp_optional = match temp_file.size_of_optional_header {
            0xE0 => ImageOptionalHeader::ImageOptionalHeader32 {
                magic: cursor.read_u16::<LittleEndian>().unwrap(),
                major_linker_version: cursor.read_u8().unwrap(),
                minor_linker_version: cursor.read_u8().unwrap(),
                size_of_code: cursor.read_u32::<LittleEndian>().unwrap(),
                size_of_initialized_data: cursor.read_u32::<LittleEndian>().unwrap(),
                size_of_uninitialized_data: cursor.read_u32::<LittleEndian>().unwrap(),
                address_of_entry_point: cursor.read_u32::<LittleEndian>().unwrap(),
                base_of_code: cursor.read_u32::<LittleEndian>().unwrap(),
                base_of_data: cursor.read_u32::<LittleEndian>().unwrap(),
                image_base: cursor.read_u32::<LittleEndian>().unwrap(),
                section_alignment: cursor.read_u32::<LittleEndian>().unwrap(),
                file_alignment: cursor.read_u32::<LittleEndian>().unwrap(),
                major_operating_system_version: cursor.read_u16::<LittleEndian>().unwrap(),
                minor_operating_system_version: cursor.read_u16::<LittleEndian>().unwrap(),
                major_image_version: cursor.read_u16::<LittleEndian>().unwrap(),
                minor_image_version: cursor.read_u16::<LittleEndian>().unwrap(),
                major_subsystem_version: cursor.read_u16::<LittleEndian>().unwrap(),
                minor_subsystem_version: cursor.read_u16::<LittleEndian>().unwrap(),
                win32_version_value: cursor.read_u32::<LittleEndian>().unwrap(),
                size_of_image: cursor.read_u32::<LittleEndian>().unwrap(),
                size_of_headers: cursor.read_u32::<LittleEndian>().unwrap(),
                checksum: cursor.read_u32::<LittleEndian>().unwrap(),
                subsystem: cursor.read_u16::<LittleEndian>().unwrap(),
                dll_characteristics: cursor.read_u16::<LittleEndian>().unwrap(),
                size_of_stack_reserve: cursor.read_u32::<LittleEndian>().unwrap(),
                size_of_stack_commit: cursor.read_u32::<LittleEndian>().unwrap(),
                size_of_heap: cursor.read_u32::<LittleEndian>().unwrap(),
                size_of_heap_commit: cursor.read_u32::<LittleEndian>().unwrap(),
                loader_flags: cursor.read_u32::<LittleEndian>().unwrap(),
                number_of_rva_and_sizes: cursor.read_u32::<LittleEndian>().unwrap(),
                data_directory: {
                    let mut temp_data_directory: [ImageDataDirectory;
                        IMAGE_NUMBEROF_DIRECTORY_ENTRIES] = Default::default();

                    for i in 0..IMAGE_NUMBEROF_DIRECTORY_ENTRIES {
                        temp_data_directory[i].virtual_address =
                            cursor.read_u32::<LittleEndian>().unwrap();
                        temp_data_directory[i].size = cursor.read_u32::<LittleEndian>().unwrap();
                    }

                    temp_data_directory
                },
            },
            0xF0 => ImageOptionalHeader::ImageOptionalHeader64 {
                magic: cursor.read_u16::<LittleEndian>().unwrap(),
                major_linker_version: cursor.read_u8().unwrap(),
                minor_linker_version: cursor.read_u8().unwrap(),
                size_of_code: cursor.read_u32::<LittleEndian>().unwrap(),
                size_of_initialized_data: cursor.read_u32::<LittleEndian>().unwrap(),
                size_of_uninitialized_data: cursor.read_u32::<LittleEndian>().unwrap(),
                address_of_entry_point: cursor.read_u32::<LittleEndian>().unwrap(),
                base_of_code: cursor.read_u32::<LittleEndian>().unwrap(),
                image_base: cursor.read_u64::<LittleEndian>().unwrap(),
                section_alignment: cursor.read_u32::<LittleEndian>().unwrap(),
                file_alignment: cursor.read_u32::<LittleEndian>().unwrap(),
                major_operating_system_version: cursor.read_u16::<LittleEndian>().unwrap(),
                minor_operating_system_version: cursor.read_u16::<LittleEndian>().unwrap(),
                major_image_version: cursor.read_u16::<LittleEndian>().unwrap(),
                minor_image_version: cursor.read_u16::<LittleEndian>().unwrap(),
                major_subsystem_version: cursor.read_u16::<LittleEndian>().unwrap(),
                minor_subsystem_version: cursor.read_u16::<LittleEndian>().unwrap(),
                win32_version_value: cursor.read_u32::<LittleEndian>().unwrap(),
                size_of_image: cursor.read_u32::<LittleEndian>().unwrap(),
                size_of_headers: cursor.read_u32::<LittleEndian>().unwrap(),
                checksum: cursor.read_u32::<LittleEndian>().unwrap(),
                subsystem: cursor.read_u16::<LittleEndian>().unwrap(),
                dll_characteristics: cursor.read_u16::<LittleEndian>().unwrap(),
                size_of_stack_reserve: cursor.read_u64::<LittleEndian>().unwrap(),
                size_of_stack_commit: cursor.read_u64::<LittleEndian>().unwrap(),
                size_of_heap: cursor.read_u64::<LittleEndian>().unwrap(),
                size_of_heap_commit: cursor.read_u64::<LittleEndian>().unwrap(),
                loader_flags: cursor.read_u32::<LittleEndian>().unwrap(),
                number_of_rva_and_sizes: cursor.read_u32::<LittleEndian>().unwrap(),
                data_directory: {
                    let mut temp_data_directory: [ImageDataDirectory;
                        IMAGE_NUMBEROF_DIRECTORY_ENTRIES] = Default::default();

                    for i in 0..IMAGE_NUMBEROF_DIRECTORY_ENTRIES {
                        temp_data_directory[i].virtual_address =
                            cursor.read_u32::<LittleEndian>().unwrap();
                        temp_data_directory[i].size = cursor.read_u32::<LittleEndian>().unwrap();
                    }

                    temp_data_directory
                },
            },
            _ => {
                print!("Invalid value: size of optional header");
                std::process::exit(-1);
            }
        };

        let image_nt_header = ImageNtHeader {
            signature: temp_signature,
            image_file_header: temp_file,
            image_optional_header: temp_optional,
        };

        image_nt_header
    }
}

pub fn read_num() -> i32 {
    let stdin = io::stdin();
    let mut buf = String::new();

    stdin.read_line(&mut buf).expect("Stdin::read_line failed");

    match buf.trim().parse() {
        Ok(num) => num,
        Err(_) => -1,
    }
}

pub fn pe_viewer(path: &str) {
    let file = match File::open(path) {
        Ok(file) => file,
        Err(_) => {
            print!("[Error] Can't open the binary or binary not found");
            std::process::exit(-1);
        }
    };
    let file_data = unsafe { MmapOptions::new().map(&file).expect("memmap failed") };
    let pe_file = pe::PeFile::new(&file_data);

    loop {
        print!("1. Hex dump\n");
        print!("2. IMAGE_DOS_HEADER\n");
        print!("3. IMAGE_NT_HEADER\n");
        print!("4. Exit\n");
        print!("> ");
        io::stdout().flush().expect("Stdout::flush failed");

        let cmd: i32 = read_num();

        match cmd {
            1 => pe_file.print_hex_dump(),
            2 => pe_file.print_image_dos_header(),
            3 => pe_file.print_image_nt_header(),
            4 => break,
            _ => println!("Invalid input\n"),
        };
    }
}