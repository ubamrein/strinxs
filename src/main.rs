use std::fs::File;
use std::io::{Read, Write, Seek};
use std::mem;
use leb128;
use regex::Regex;
use zip::ZipArchive;
use std::collections::HashMap;
use chrono::*;
use std::io::Cursor;

fn parse_dex<R: Read>(mut f : R, reg : &str){
    let mut buffer : Vec<u8> = vec![];
    f.read_to_end(&mut buffer).expect("Could not read dex file");
    parse_dex_buf(buffer, reg);
}

fn parse_dex_buf(buffer : Vec<u8>, reg : &str) {
    
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
   
    let file_contents = buffer;
    //f.read_to_end(&mut file_contents).expect("Could not read file");
    
    let mut match_table = HashMap::new();
    let re = Regex::new(reg).unwrap();
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
        let mut r : &[u8] = &file_contents[entry as usize..]; 
        let string_size = leb128::read::unsigned(&mut r).expect("Could not parse leb128") as u32;
        let mut tmp = vec![0;10];
        let lebbytes = leb128::write::unsigned(&mut tmp, string_size as u64).unwrap();
        let mut r = &file_contents[entry as usize + lebbytes as usize..];
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
            if se.utf16_size > 0 {
                let the_string = std::str::from_utf8(&se.dat).unwrap_or("");
                if re.is_match(the_string) {
                   // println!("Found match: {}", the_string);
                   let m = Match { value : String::from(the_string) , origin : StringType::UTF8String, desc : String::from(""), class : String::from(""), function_name: String::from(""), argc: 0  };
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
        if let Some(entry) = match_table.get_mut(&(proto.shorty_idx as usize)) {
            entry.origin = StringType::ProtoType;
        }
        protos.push(proto);
       
        i += 1;
        offset += std::mem::size_of::<Proto>() as isize;
   }

   offset = config.method_ids_off as isize;
   i = 0;
   let mut methods = vec![];
   let mut add =1;
   while i < config.method_ids_size {
       let mut method : Method = unsafe {std::mem::zeroed()};
       fill_type_from_raw_pointer(&mut method, &file_contents[offset as usize]);
       //println!("Found method: {}", method.get_description(&types,&strings, &protos));
       if let Some(val) = match_table.get_mut(&(method.name_idx as usize)) {
            val.origin = StringType::Method;
            val.desc = method.get_description(&types, &strings, &protos);
            val.class = method.get_classname(&types);
            val.function_name = method.get_function_name(&strings);
            val.argc = method.get_prototype(&strings, &protos).len() -1 ;
        }
        else if let Some(the_proto_type) = protos.get(method.proto_idx as usize) {
            if let Some(val) = match_table.get_mut(&(the_proto_type.shorty_idx as usize)) {
                //val.desc = method.get_description(&types, &strings, &protos);
                let m = Match { value : String::from("Proto in Method") , origin : StringType::Method, desc : method.get_description(&types, &strings, &protos), class: method.get_classname(&types), function_name : method.get_function_name(&strings), argc : val.value.len() -1 };
                match_table.insert(strings.len() + add, m);
                add += 1;
            }
        }
        methods.push(method);
        i += 1;
        offset += std::mem::size_of::<Method>() as isize;
   }
    let mut frida_script = String::from("Java.perform(function () {\n");
    let mut have_script = false;
    for m in match_table {
        println!("Found Match ({}): {} -> {}", m.1.origin.to_string(), m.1.value, m.1.desc.to_string());
        match m.1.origin {
            StringType::Method => {
                have_script = true;
                let mut arg_str = String::from("");
                for i in 0..m.1.argc {
                    arg_str += &format!("a{},",i);
                }
                arg_str.pop();
                let script = format!("\tvar ret = this.{}({}); console.log(ret); return ret;",m.1.function_name,arg_str);
                let mut class_string =  m.1.class.replace("/","_");
                class_string.pop();
                frida_script += &format!("\tvar dyn_{} = Java.use(\"{}\");\n", class_string, &(m.1.class.replace("/",".").replace(";",""))[1..]);   
                frida_script += &format!("\tdyn_{}.{}.implementation = function({}){{ {} }};\n\n", class_string, m.1.function_name,arg_str, script);
            },
            _ => {
                continue;
            }
        }
       
    }
    frida_script += "\n});";
    if have_script {
        let mut outfile = std::fs::File::create(format!("hook_{}_.js", Utc::now().timestamp_millis())).unwrap();
        outfile.write(frida_script.as_bytes()).expect("Could not write frida hook");
    }
}

enum StringType {
    Method,
    Type,
    UTF8String,
    ProtoType
}

impl ToString for StringType {
    fn to_string(&self) -> String {
        match self {
            StringType::Method => {
                String::from("Method")
            },
            StringType::Type => {
                String::from("Type")
            },
            StringType::UTF8String => {
                String::from("UTF8String")
            },
            StringType::ProtoType => {
                String::from("ProtoType")
            }
        }
    }
}

struct Match {
    value : String,
    origin : StringType,
    desc : String,
    class : String,
    function_name : String,
    argc : usize
}

fn extract_zip<R: Read+Seek>(f : R, reg : &str) {
    let mut archive = ZipArchive::new(f).expect("Expected a zip file");
    for i in 0..archive.len() {
        let mut file = archive.by_index(i).expect("Error Accessing file");
        let mut zip_bytes : Vec<u8> = vec![];
        file.read_to_end(&mut zip_bytes).expect("Could not read");

        let ptr = zip_bytes.as_slice();
        if check_for_dex_signature(ptr){
            println!("\n\n-------\n\nFound DEX {}", file.name());
            parse_dex_buf(zip_bytes, reg); 
        } else if check_for_zip_signature(ptr){
            println!("\n\n--------\n\nfound APK in apk -> extract it ({})", file.name());
            let cursor = Cursor::new(zip_bytes);
            extract_zip(cursor, reg);
        }
        else if reg != ""{
           match_unknown_file(zip_bytes.as_slice(), file.name(), reg);
        }
    }
}

fn match_unknown_file<T:Read>(mut file : T, file_name: &str, reg : &str) {
    let re = Regex::new(reg).unwrap();
    let mut zip_bytes : Vec<u8> = vec![];
    file.read_to_end(&mut zip_bytes).expect("Could not read");
    //do our best at just looking at uft stuff
    let lossy_string = String::from_utf8_lossy(&zip_bytes);
    if re.is_match(&lossy_string) {
        let matches = re.find_iter(&lossy_string);
        println!("\n\n--------\n\nfound regex in unsupported type({})", file_name);
        for the_match in matches {
            println!("Match: {}, from 0x{:x} to 0x{:x}", the_match.as_str(), the_match.start(), the_match.end());
        }
    }
} 

fn check_for_dex_signature<T:Read>(mut ptr : T) -> bool{
    let mut buf: [u8;3] = [0,0,0];
    match ptr.read_exact(&mut buf) {
        Err(_) => false,
        _ => {
            let [a,b,c] = buf;
            a == 'd' as u8 && b == 'e' as u8 && c == 'x' as u8
        }
    }
}

fn check_for_zip_signature<T: Read>(mut ptr : T) -> bool {
    let mut buf: [u8;2] = [0,0];
    match ptr.read_exact(&mut buf)
    {
        Err(_) => false,
        _ => {
            let [a,b] = buf;
            a == 'P' as u8 && b == 'K' as u8
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
     let mut zip_bytes : Vec<u8> = vec![];
     f.read_to_end(&mut zip_bytes).expect("Could not read");
     let ptr = zip_bytes.as_slice();
    if  check_for_zip_signature(ptr) {
        //we have a zip
        println!("Found a zip, extract it");
        println!("\n\nZIP: {}\n\n", args[1]);
        if args.len() > 2 {
            extract_zip(f, &args[2]);
        } else {
            extract_zip(f, "");
        }
        println!("--------------\n\nZIP FINISHED\n\n");
    } else if check_for_dex_signature(ptr) {
        f.seek(std::io::SeekFrom::Start(0)).expect("Could not Seek to beginning");
        if args.len() > 2 {
            parse_dex(f, &args[2]);
        } else {
            parse_dex(f, "");
        }
    }
    else if args.len() > 2 {
        match_unknown_file(ptr, &args[1], &args[2]);
    }
}

 pub fn fill_type_from_raw_pointer<T>(obj : &mut T, data : *const u8) {
     unsafe {
            let obj_ptr = std::slice::from_raw_parts_mut(obj as *mut _ as *mut u8, std::mem::size_of::<T>());
            std::slice::from_raw_parts(data, std::mem::size_of::<T>()).read_exact(obj_ptr).expect("Could not read/write object");
     }
}

// struct DexFile {
//     string_table : Vec<StringEntry>,
//     type_table : Vec<String>,
//     proto_table : Vec<String>,
//     field_table :Vec<String>,
//     method_table : Vec<String>,
//     class_table : Vec<Class>
// }

// #[repr(C, packed)]
// #[derive(Debug)]
// struct Class {
//     class_idx : u32,
//     access_flags : u32,
//     superclass_idx : u32,
//     interfaces_off : u32,
//     source_file_idx : u32,
//     annotations_off : u32,
//     class_data_off : u32,
//     static_values_off : u32
// }
#[repr(C, packed)]
struct Method {
    class_idx : u16,
    proto_idx : u16,
    name_idx : u32
}

impl Method {
    pub fn get_description(&self, types: &Vec<&str>, strings : &Vec<StringEntry>, proto_types : &Vec<Proto>) -> String {
        let class_name  =&types[self.class_idx as usize];
        let ret_type = types[proto_types[self.proto_idx as usize].return_type_idx as usize];
        let name = std::str::from_utf8(&strings[self.name_idx as usize].dat).unwrap();
        let short_idx = std::str::from_utf8(&strings[proto_types[self.proto_idx as usize].shorty_idx as usize].dat).unwrap();
        format!("In Class {}  Return Type: {}  Name: {}(...)[{}]", class_name, ret_type, name,short_idx)
    }

    pub fn get_classname(&self,types: &Vec<&str>) -> String {
        let class_name  =&types[self.class_idx as usize];
        format!("{}",class_name)
    }
    pub fn get_function_name(&self,strings : &Vec<StringEntry>) -> String {
        let name = std::str::from_utf8(&strings[self.name_idx as usize].dat).unwrap();
        format!("{}", name)
    }
    pub fn get_prototype(&self, strings: &Vec<StringEntry>, proto_types : &Vec<Proto>) -> String{
        let proto = &proto_types[self.proto_idx as usize];
        let name = std::str::from_utf8(&strings[proto.shorty_idx as usize].dat).unwrap();
        format!("{}", name)
    }
}
#[repr(C, packed)]
struct Proto {
    shorty_idx : u32,
    return_type_idx : u32,
    parameters_off : u32
}
struct StringEntry {
    utf16_size : u32,
    dat : Vec<u8>
}

#[repr(C, packed)]
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


// fn decode(buf : &mut Iter<u8>) -> u64 {
//     let mut result : u64 = 0;
//     let mut shift = 0;
//     loop {
//        let byte = buf.next().unwrap();
//         result |= ((0b0111_1111 & byte) << shift) as u64;
//         if 0b1000_0000 & byte == 0 {
//             break;
//         }
//         shift += 7;
//     }
//     result
// }
