use memmap::MmapOptions;
use std:: {
    io:: {
        self,
        prelude::*
    },
    fs::File
};

mod pe {
    pub struct PeFile<'a> {
        pub map: &'a [u8],
        pub image_dos_header: ImageDosHeader
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

    pub struct ImageDosHeader {
        e_magic: u16,
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
        e_lfanew: u32
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
            e_lfanew: cursor.read_u32::<LittleEndian>().unwrap()
        };

        image_dos_header
    }
}

pub fn read_num() -> i32 {
    let stdin = io::stdin();
    let mut buf = String::new();

    stdin.read_line(&mut buf).expect("stdin::read_line failed");
    
    match buf.trim().parse() {
        Ok(num) => num,
        Err(_) => -1
    }
}

pub fn pe_viewer(path: &str) -> io::Result<()> {
    let file = File::open(path)?;
    let file_data = unsafe { MmapOptions::new().map(&file)? };
    let pe_file = pe::PeFile::new(&file_data);

    loop {
        print!("1. Hex dump\n");
        print!("2. IMAGE_DOS_HEADER\n");
        print!("3. Exit\n");
        print!("> ");
        io::stdout().flush()?;

        let cmd: i32 = read_num();

        match cmd {
            1 => pe_file.print_hex_dump(),
            2 => pe_file.print_image_dos_header(),
            3 => break,
            _ => println!("Invalid input\n")
        };
    }

    Ok(())
}
