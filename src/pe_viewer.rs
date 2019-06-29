use memmap::MmapOptions;
use std:: {
    io:: {
        self,
        prelude::*
    },
    fs::File,
};

// Module that contains PE Structs and functions
mod pe {
    // PE Header
    pub struct PeFile<'a> {
        pub map: &'a [u8],
        pub image_dos_header: ImageDosHeader,
    }

    // IMAGE_DOS_HEADER
    pub struct ImageDosHeader {
        e_magic: u16,   // Should be MZ
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
        e_lfanew: u32,  // Offset to IMAGE_NT_HEADER
    }
    
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

    // IMAGE_OPTIONAL_HEADER
    // Binary has one of two structs in this enum
    // based on file(32bit or 64bit)
    const IMAGE_NUMBEROF_DIRECTORY_ENTRIES: usize = 16;

    enum OptionalHeader {
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
        image_optional_header: OptionalHeader,
    }

    impl<'a> PeFile<'a> {
        pub fn new(file: &'a [u8]) -> PeFile {
            let temp_dos = load_image_dos_header(file);

            let pe_file = PeFile {
                map: file,
                image_dos_header: temp_dos
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
            let header = &self.image_dos_header;

            println!("\nIMAGE_DOS_HEADER");
            println!("====================================");
            println!("Signature                    : {:04X}", header.e_magic);
            println!("Bytes one Last Page of File  : {:04X}", header.e_cblp);
            println!("Pages in File                : {:04X}", header.e_cp);
            println!("Relocations                  : {:04X}", header.e_crlc);
            println!("Size of Header in Paragraphs : {:04X}", header.e_cparhdr);
            println!("Minimum Extra Paragraphs     : {:04X}", header.e_minalloc);
            println!("Maximum Extra Paragraphs     : {:04X}", header.e_maxalloc);
            println!("Initial(relative) SS         : {:04X}", header.e_ss);
            println!("Initial SP                   : {:04X}", header.e_sp);
            println!("Checksum                     : {:04X}", header.e_csum);
            println!("Initial IP                   : {:04X}", header.e_ip);
            println!("Initial(relative) CS         : {:04X}", header.e_cs);
            println!("Offset to Relocation Table   : {:04X}", header.e_lfarlc);
            println!("Reserved                     : {:04X}", header.e_res[0]);
            println!("Overlay Number               : {:04X}", header.e_ovno);
            println!("OEM Identifier               : {:04X}", header.e_oemid);
            println!("OEM Information              : {:04X}", header.e_oeminfo);
            println!("Reserved                     : {:04X}", header.e_res2[0]);
            println!("Offset to New EXE Header     : {:04X}\n", header.e_lfanew);
        }
    }

    use std::io::Cursor;
    use byteorder::{LittleEndian, ReadBytesExt};

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

    /* pub fn load_image_nt_header(file: &[u8]) -> ImageNtHeader {
        let image_nt_header = ImageNtHeader {};

        image_nt_header
    } */
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
        },
    };
    let file_data = unsafe { MmapOptions::new().map(&file).expect("memmap failed") };
    let pe_file = pe::PeFile::new(&file_data);

    loop {
        print!("1. Hex dump\n");
        print!("2. IMAGE_DOS_HEADER\n");
        print!("3. Exit\n");
        print!("> ");
        io::stdout().flush().expect("Stdout::flush failed");

        let cmd: i32 = read_num();

        match cmd {
            1 => pe_file.print_hex_dump(),
            2 => pe_file.print_image_dos_header(),
            3 => break,
            _ => println!("Invalid input\n"),
        };
    };
}