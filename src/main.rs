use std::slice::Iter;
use std::fs::File;
use std::io::Read;
use std::mem;
use leb128;
use regex::Regex;
use zip::ZipArchive;
use std::io;
use std::collections::HashMap;

fn parseDex<R: Read>(mut f : R, reg : &str) {
    let mut buffer : Vec<u8> = vec![];
    f.read_to_end(&mut buffer).expect("Could not read into buffer");

    let mut config: DexHeader = unsafe { mem::zeroed() };
    
    fill_type_from_raw_pointer(&mut config, &buffer[0]);
    
    println!("magic:\n {}", std::str::from_utf8(&config.magic).unwrap());
    unsafe {
        println!("Adler32: 0x{:x}", config.checksum);
        println!("Signature: {:x?}", config.signature);
        println!("File size: {}", config.file_size);

        println!("----");
        println!("Found {} strings", config.string_ids_size);
        println!("Found {} types", config.type_ids_size);
        println!("Found {} methods", config.method_ids_size);
        println!("Found {} classes", config.class_defs_size);
        println!("----");
    }
    //read file again and print string table
    
    //skip the header
   
    let mut file_contents = buffer;
    //f.read_to_end(&mut file_contents).expect("Could not read file");
    
    let mut match_table = HashMap::new();

    let mut i = 0;
    let mut offset =  config.string_ids_off as isize;
    let mut string_table : Vec<u32> = vec![];
    while i < config.string_ids_size {
        let mut size = 0;

        fill_type_from_raw_pointer(&mut size, &file_contents[(offset) as usize]);
        string_table.push(size);
        offset = offset + 4;
        i = i+1;
    }
    let mut strings = vec![];
    for entry in string_table {
        let mut r = RawPointerRead::readable_raw_pointer(&mut file_contents[entry as usize]);
        let string_size = leb128::read::unsigned(&mut r).expect("Could not parse leb128") as u32;
        let mut tmp = vec![0;10];
        let lebbytes = leb128::write::unsigned(&mut tmp, string_size as u64).unwrap();
        let mut r = RawPointerRead::readable_raw_pointer(&mut file_contents[entry as usize + lebbytes as usize]);
        let mut buf : Vec<u8> = Vec::with_capacity(string_size as usize);
        for _ in 0..(string_size) {
            buf.push(0);
        }
        r.read(&mut buf).expect("Could not read buffer");
        let se = StringEntry
        {
            utf16_size : string_size,
            dat : buf
        };
        if se.utf16_size > 0 {
            //println!("found {} long string: {} at offset {}, leb was {} bytes", se.utf16_size, std::str::from_utf8(&se.dat).unwrap_or(""), entry, lebbytes);
        }

        if reg != "" {
            let re = Regex::new(reg).unwrap();
            if se.utf16_size > 0 {
                let the_string = std::str::from_utf8(&se.dat).unwrap_or("");
                if re.is_match(the_string) {
                   // println!("Found match: {}", the_string);
                   let m = Match { value : String::from(the_string) , origin : StringType::UTF8String  };
                   match_table.insert(strings.len(), m);
                }
            }
        }
        strings.push(se);
    }
   
   i = 0;
   offset = config.type_ids_off as isize;
   let mut types = vec![];
   let mut index : u32 = 0;
   while i < config.type_ids_size {
       fill_type_from_raw_pointer(&mut index, &file_contents[offset as usize]);
       let the_type = std::str::from_utf8(&strings[index as usize].dat).expect("type should be there");
       types.push(the_type);
       offset += 4;
       i += 1;

       //see if index is in hashmap
       if let Some(entry) = match_table.get_mut(&(index as usize)){
           entry.origin = StringType::Type;
       }
   }

   offset = config.proto_ids_off as isize;
   i = 0;
   let mut protos : Vec<Proto> = vec![];
   while i < config.proto_ids_size {
        let mut proto : Proto = unsafe {std::mem::zeroed()};
        fill_type_from_raw_pointer(&mut proto, &file_contents[offset as usize]);
        //println!("Found prototype: {} {}()", types[proto.return_type_idx as usize], std::str::from_utf8(&strings[proto.shorty_idx as usize].dat).expect("type should be there") );
        protos.push(proto);
        i += 1;
        offset += std::mem::size_of::<Proto>() as isize;
   }

   offset = config.method_ids_off as isize;
   i = 0;
   let mut methods = vec![];
   while i < config.method_ids_size {
       let mut method : Method = unsafe {std::mem::zeroed()};
       fill_type_from_raw_pointer(&mut method, &file_contents[offset as usize]);
       //println!("Found method: {}", method.get_description(&types,&strings, &protos));
        if let Some(val) = match_table.get_mut(&(method.name_idx as usize)) {
            val.origin = StringType::Method;
        }
        methods.push(method);
        i += 1;
        offset += std::mem::size_of::<Method>() as isize;
   }

    for m in match_table {
        println!("Found Match ({}): {}", m.1.origin.to_string(), m.1.value);
    }
}


enum StringType {
    Unknown,
    Method,
    Type,
    UTF8String
}

impl ToString for StringType {
    fn to_string(&self) -> String {
        match self {
            StringType::Unknown => {
                String::from("Unknown")
            },
            StringType::Method => {
                String::from("Method")
            },
            StringType::Type => {
                String::from("Type")
            },
            StringType::UTF8String => {
                String::from("UTF8String")
            }
        }
    }
}

struct Match {
    value : String,
    origin : StringType
}

fn extract_zip(mut f : File, reg : &str) {
    let mut archive = ZipArchive::new(f).expect("Expected a zip file");
        for i in 0..archive.len() {
            let mut file = archive.by_index(i).expect("Error Accessing file");
            if file.name().contains(".dex") {
                println!("\n\n-------\n\nFound DEX {}", file.name());
                parseDex(file, reg); 
            } else if file.name().contains(".apk") {
                println!("\n\n--------\n\nfound APK in apk -> extract it ({})", file.name());
                let mut outfile = std::fs::File::create("tmp.zip").unwrap();
                io::copy(&mut file, &mut outfile).expect("could not copy file to tmp location");
                
                let file = File::open("tmp.zip").expect("file does not exist");
                extract_zip(file, reg);
            }
    }
}

fn main(){
    let args : Vec<String> = std::env::args().collect();
    if args.len() < 2{
        eprintln!("wrong number of arguments");
        return;
    }
     let mut f = File::open(&args[1]).expect("File must exist");

    if args[1].contains(".apk") || args[1].contains(".zip") {
        //we have a zip
        println!("Found a zip, extract it");
        println!("\n\nZIP: {}\n\n", args[1]);
        if args.len() > 2 {
            extract_zip(f, &args[2]);
        } else {
            extract_zip(f, "");
        }
        println!("--------------\n\nZIP FINISHED\n\n");
    } else {
       if args.len() > 2 {
            parseDex(f, &args[2]);
        } else {
            parseDex(f, "");
        }
    }
}

 pub fn fill_type_from_raw_pointer<T>(obj : &mut T, data : *const u8) {
     unsafe {
            let obj_ptr = std::slice::from_raw_parts_mut(obj as *mut _ as *mut u8, std::mem::size_of::<T>());
            std::slice::from_raw_parts(data, std::mem::size_of::<T>()).read_exact(obj_ptr).expect("Could not read/write object");
     }
}

struct DexFile {
    string_table : Vec<StringEntry>,
    type_table : Vec<String>,
    proto_table : Vec<String>,
    field_table :Vec<String>,
    method_table : Vec<String>,
    class_table : Vec<Class>
}

#[repr(C, packed)]
#[derive(Debug)]
struct Class {
    class_idx : u32,
    access_flags : u32,
    superclass_idx : u32,
    interfaces_off : u32,
    source_file_idx : u32,
    annotations_off : u32,
    class_data_off : u32,
    static_values_off : u32
}
#[repr(C, packed)]
#[derive(Debug)]
struct Method {
    class_idx : u16,
    proto_idx : u16,
    name_idx : u32
}

impl Method {
    pub fn get_description(&self, types: &Vec<&str>, strings : &Vec<StringEntry>, proto_types : &Vec<Proto>) -> String {
        let class_name  =&types[self.class_idx as usize];
        let ret_type = std::str::from_utf8(&strings[proto_types[self.proto_idx as usize].return_type_idx as usize].dat).unwrap();
        let name = std::str::from_utf8(&strings[self.name_idx as usize].dat).unwrap();
        let short_idx = std::str::from_utf8(&strings[proto_types[self.proto_idx as usize].shorty_idx as usize].dat).unwrap();
        format!("{}: {} {}(...)[{}]", class_name, ret_type, name, short_idx)
    }
}
#[repr(C, packed)]
#[derive(Debug)]
struct Proto {
    shorty_idx : u32,
    return_type_idx : u32,
    parameters_off : u32
}
struct StringEntry {
    utf16_size : u32,
    dat : Vec<u8>
}

struct RawPointerRead {
    ptr : *mut u8
}

impl RawPointerRead {
    pub fn readable_raw_pointer(ptr : &mut u8) -> RawPointerRead{
        RawPointerRead {
            ptr
        }
    }
}

impl Read for RawPointerRead {
    fn read(&mut self, buf: &mut [u8]) -> std::io::Result<usize> {
        unsafe {
            std::slice::from_raw_parts(self.ptr, buf.len()).read_exact(buf).expect("could not write buffer");
            if buf.len() > 0 {
            }
            else {
                println!( "zero sized buffer");
            }
            self.ptr = self.ptr.offset(buf.len() as isize);
        }
        return Ok(buf.len());
    }
}

#[repr(C, packed)]
#[derive(Debug)]
struct DexHeader {
    magic : [u8;8],
    checksum : u32,
    signature : [u8;20],
    file_size : u32,
    header_size : u32,
    endian_tag : u32,
    link_size : u32,
    link_off : u32,
    map_off : u32,
    string_ids_size : u32,
    string_ids_off : u32,
    type_ids_size : u32,
    type_ids_off : u32,
    proto_ids_size : u32,
    proto_ids_off : u32,
    fields_ids_size : u32,
    fields_ids_off : u32,
    method_ids_size : u32,
    method_ids_off : u32,
    class_defs_size : u32,
    class_defs_off : u32,
    data_size : u32,
    data_off : u32,
}


fn decode(buf : &mut Iter<u8>) -> u64 {
    let mut result : u64 = 0;
    let mut shift = 0;
    loop {
       let byte = buf.next().unwrap();
        result |= ((0b0111_1111 & byte) << shift) as u64;
        if 0b1000_0000 & byte == 0 {
            break;
        }
        shift += 7;
    }
    result
}
