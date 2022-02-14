use crate::bitfield::*;
use crate::file_ext::*;
use crate::hash::*;
use anyhow::{bail, Context, Result};
use bitflags::*;
use std::collections::*;
use std::convert::{TryFrom, TryInto};
use std::fs::File;
use std::io::{Read, Seek, Write};
use std::char::{REPLACEMENT_CHARACTER};

fn as_hex(array: &[u8], len: usize) -> String {
    let mut s = String::new();
    if len % 4 == 0 {
        if len > 4 {
            /*
            s += "[in-order-hexBE]";
            for i in 0..(len/4){
                for j in (0..4).rev(){
                    s += &(format!("{:01$X}", array[i*4+j] as u8, 2));
                }
                if i < (len/4) - 1 { s += " " }
            }*/
            s += "[hexLE]"; //remain order
            for i in 0..len { //.rev() to get BE
                if i % 4 == 0 && i > 0 { s += " " }
                s += &(format!("{:01$X}", array[i] as u8, 2));
            }
        }else{ //len = 4
            s += "[hexBE]"; //remain order
            for i in (0..len).rev(){
                s += &(format!("{:01$X}", array[i] as u8, 2));
            }
        }
    }else{
        s += "[hexLE]"; //remain order
        for i in 0..len { //.rev() to get BE
            s += &(format!("{:01$X} ", array[i] as u8, 2));
        }
    }

    s
}

bitflags! {
    struct FieldAttribute: u16 {
        const PRIVATE_SCOPE            = 0x0000;
        const PRIVATE                  = 0x0001;
        const FAM_AND_ASSEM            = 0x0002;
        const ASSEMBLY                 = 0x0003;
        const FAMILY                   = 0x0004;
        const FAM_OR_ASSEM             = 0x0005;
        const PUBLIC                   = 0x0006;
        const MEMBER_ACCESS_MASK       = 0x0007;

        const STATIC                   = 0x0010;
        const READONLY                 = 0x0020;
        const LITERAL                  = 0x0040;
        const NO_SERIALIZE             = 0x0080;
        const HAS_RVA                  = 0x0100;
        const SPECIAL                  = 0x0200;
        const RT_SPECIAL               = 0x0400;
        const POINTER                  = 0x0800;
        const MARSHAL                  = 0x1000;
        const PINVOKE                  = 0x2000;
        const EXPOSE_MEMBER            = 0x4000;
        const DEFAULT                  = 0x8000;
        const RESERVED_MASK            = 0x9500;
        const NO_RESERVE               = 0x0000;
    }
}

bitflags! {
    struct ParamAttribute: u16 {
        const IN                = 0x0001;
        const OUT               = 0x0002;
        const LCID              = 0x0004;
        const RETVAL            = 0x0008;
        const OPTIONAL          = 0x0010;
        const HAS_DEFAULT       = 0x1000;
        const HAS_FIELD_MARSHAL = 0x2000;
    }
}

bitflags! {
    struct MethodAttribute: u16 {
        const PRIVATE_SCOPE            = 0x0000;
        const PRIVATE                  = 0x0001;
        const FAM_AND_ASSEM            = 0x0002;
        const ASSEMBLY                 = 0x0003;
        const FAMILY                   = 0x0004;
        const FAM_OR_ASSEM             = 0x0005;
        const PUBLIC                   = 0x0006;
        const MEMBER_ACCESS_MASK       = 0x0007;

        const UNMANAGED_EXPORT         = 0x0008;
        const STATIC                   = 0x0010;
        const FINAL                    = 0x0020;
        const VIRTUAL                  = 0x0040;
        const HIDE_BY_SIG              = 0x0080;
        const NEW_SLOT                 = 0x0100;
        const CHECK_ACCESS_ON_OVERRIDE = 0x0200;
        const ABSTRACT                 = 0x0400;
        const SPECIAL_NAME             = 0x0800;
        const RT_SPECIAL_NAME          = 0x1000;
        const PINVOKE_IMPL             = 0x2000;
        const HAS_SECURITY             = 0x4000;
        const REQUIRE_SEC_OBJECT       = 0x8000;
    }
}

bitflags! {
    struct TypeFlag: u32 {
        const NOT_PUBLIC           = 0x00000000;
        const PUBLIC               = 0x00000001;
        const NESTED_PUBLIC        = 0x00000002;
        const NESTED_PRIVATE       = 0x00000003;
        const NESTED_FAMILY        = 0x00000004;
        const NESTED_ASSEMBLY      = 0x00000005;
        const NESTED_FAMANDASSEM   = 0x00000006;
        const NESTED_FAMORASSEM    = 0x00000007;
        const VISIBILITY_MASK      = 0x00000007; //111 {0~7}

        const AUTO_LAYOUT          = 0x00000000;
        const SEQUENTIAL_LAYOUT    = 0x00000008;        
        const EXPLICIT_LAYOUT      = 0x00000010;
        const LAYOUT_MASK          = 0x00000018; //11000 {0, 8, 16, 24}

        const CLASS                = 0x00000000;
        const INTERFACE            = 0x00000020;
        const CLASS_SEMANTICS_MASK = 0x00000020; //100000 {0, 32} 
        // no 0x0040
        //no mask
        const ABSTRACT             = 0x00000080;
        const SEALED               = 0x00000100;
        // no 0x0200
        const SPECIAL_NAME         = 0x00000400;
        const RT_SPECIAL_NAME      = 0x00000800;
        const IMPORT               = 0x00001000;
        const SERIALIZABLE         = 0x00002000;
        const WINDOWS_RUNTIME      = 0x00004000;
        // no 0x8000

        const ANSI_CLASS           = 0x00000000;
        const UNICODE_CLASS        = 0x00010000;
        const AUTO_CLASS           = 0x00020000;
        const CUSTOM_FORMAT_CLASS  = 0x00030000;
        const STRING_FORMAT_MASK   = 0x00030000; //110000000000000000 {0, 65536, 131072, 196608}

        const HAS_SECURITY         = 0x00040000;
        // no 0x080000
        const BEFORE_FIELD_INIT    = 0x00100000;
        // no 0x200000
        //const NO_RESERVE           = 0x00000000;
        //const RESERVED_MASK        = 0x00040800; //1000000100000000000 {0, 2048, 262144, 264192}
        // no 0x200000
        const CUSTOM_FORMAT_MASK   = 0x00C00000; //110000000000000000000000 {0, 4194304, 8388608, 12582912}
        const LOCAL_HEAP           = 0x01000000;
        const FINALIZE             = 0x02000000;
        const NATIVE_TYPE          = 0x04000000;
        const MARK_FIELDS          = 0x08000000;
        const NATIVE_CTOR          = 0x10000000;
        // no 0x20000000
        const MANAGED_VTABLE       = 0x40000000;
    }
}

bitflags! {
    struct MethodImplFlag: u16 {
        const CODE_TYPE_MASK              = 0x0003;
        const IL                          = 0x0000;
        const NATIVE                      = 0x0001;
        const OPTIL                       = 0x0002;
        const RUNTIME                     = 0x0003;
        const UNMANAGED                   = 0x0004;
        const NO_INLINING                 = 0x0008;
        const FORWARD_REF                 = 0x0010;
        const SYNCHRONIZED                = 0x0020;
        const NO_OPTIMIZATION             = 0x0040;
        const PRESERVE_SIG                = 0x0080;
        const AGGRESSIVE_INLINING         = 0x0100;
        const HAS_RET_VAL                 = 0x0200;
        const EXPOSE_MEMBER               = 0x0400;
        const EMPTY_CTOR                  = 0x0800;
        const INTERNAL_CALL               = 0x1000;
        const CONTAINS_GENERIC_PARAMETERS = 0x2000;
        const HAS_THIS                    = 0x4000;
        const THREAD_SAFE                 = 0x8000;    
        
        const MANAGED_MASK                = 0x0004;
        const MANAGED                     = 0x0000;
    }
}

bitflags! {
    struct PropertyFlag: u16 {
        const SPECIAL_NAME    = 0x0200;
        const RT_SPECIAL_NAME = 0x0400;
        const HAS_DEFAULT     = 0x1000;
        const EXPOSE_MEMBER   = 0x4000;
    }
}

fn display_property_flag(flags: PropertyFlag) -> String {
    let mut s = String::new();
    if flags.contains(PropertyFlag::SPECIAL_NAME) {
        s += "[special]";
    }
    if flags.contains(PropertyFlag::RT_SPECIAL_NAME) {
        s += "[rt_special]";
    }
    if flags.contains(PropertyFlag::HAS_DEFAULT) {
        s += "[default]";
    }
    if flags.contains(PropertyFlag::EXPOSE_MEMBER) {
        s += "[expose]";
    }
    s
}

fn display_param_modifier(param_modifier: u32, return_pos: bool) -> String {
    let return_pos = if return_pos { "return:" } else { "" };
    let tag = match param_modifier {
        0 => return "".to_string(),
        1 => "ptr",
        2 => "ref",
        _ => "unknown-mod",
    };
    format!("[{}{}]", return_pos, tag)
}

fn display_type_flag(flags: TypeFlag) -> String {
    let mut s = String::new();    
    //https://docs.microsoft.com/en-us/dotnet/api/system.reflection.typeattributes?view=net-6.0

    s += match flags & TypeFlag::LAYOUT_MASK {
        TypeFlag::AUTO_LAYOUT => "[auto]", //"[StructLayoutAttribute(LayoutKind.Auto)]",
        TypeFlag::SEQUENTIAL_LAYOUT => "[sequential]", //"[StructLayoutAttribute(LayoutKind.Sequential)]",
        TypeFlag::EXPLICIT_LAYOUT => "[explicit]", //"[StructLayoutAttribute(LayoutKind.Explicit)]",
        _ => "[unknown_layout]",
    };

    if flags.contains(TypeFlag::SPECIAL_NAME) {
        s += "[special]"
    }
    if flags.contains(TypeFlag::RT_SPECIAL_NAME) {
        s += "[rt_special]"
    }
    if flags.contains(TypeFlag::IMPORT) {
        s += "[import]"
    }
    if flags.contains(TypeFlag::SERIALIZABLE) {
        s += "[serializable]"
    }
    if flags.contains(TypeFlag::WINDOWS_RUNTIME) {
        s += "[windows_runtime]"
    }

    s += match flags & TypeFlag::STRING_FORMAT_MASK {
        TypeFlag::ANSI_CLASS => "[ansi]",
        TypeFlag::UNICODE_CLASS => "[unicode]",
        TypeFlag::AUTO_CLASS => "[auto_format]",
        TypeFlag::CUSTOM_FORMAT_CLASS => "[custom_format]",
        _ => panic!(),
    };
    
    /*
    s += match flags & TypeFlag::CUSTOM_FORMAT_MASK {
        TypeFlag::CUSTOM_00 => "",
        TypeFlag::CUSTOM_01 => "[Custom01]",
        TypeFlag::CUSTOM_10 => "[Custom10]",
        TypeFlag::CUSTOM_11 => "[Custom11]",
        _ => panic!(),
    };*/
    
    if flags.contains(TypeFlag::HAS_SECURITY) {
        s += "[has_security]"
    }
    if flags.contains(TypeFlag::BEFORE_FIELD_INIT) {
        s += "[before_field_init]"
    }
    if flags.contains(TypeFlag::LOCAL_HEAP) {
        s += "[local_heap]"
    }
    if flags.contains(TypeFlag::FINALIZE) {
        s += "[finalize]"
    }
    if flags.contains(TypeFlag::NATIVE_TYPE) {
        s += "[native]"
    }
    if flags.contains(TypeFlag::MARK_FIELDS) {
        s += "[MarkFields]"
    }
    if flags.contains(TypeFlag::NATIVE_CTOR) {
        s += "[native_ctor]"
    }
    if flags.contains(TypeFlag::MANAGED_VTABLE) {
        s += "[managed_vtable]"
    }

    s += "\n";

    s += match flags & TypeFlag::VISIBILITY_MASK {
        TypeFlag::NOT_PUBLIC => "",
        TypeFlag::PUBLIC => "public ",
        TypeFlag::NESTED_PUBLIC => "/*nested*/ public ",
        TypeFlag::NESTED_PRIVATE => "/*nested*/ private ",
        TypeFlag::NESTED_FAMILY => "/*nested*/ protected ",
        TypeFlag::NESTED_ASSEMBLY => "/*nested*/ internal ",
        TypeFlag::NESTED_FAMANDASSEM => "/*nested*/ private protected ",
        TypeFlag::NESTED_FAMORASSEM => "/*nested*/ protected internal ",
        _ => panic!(),
    };
    
    if flags.contains(TypeFlag::ABSTRACT) {
        s += "abstract "
    }
    if flags.contains(TypeFlag::SEALED) {
        s += "sealed "
    }

    s += match flags & TypeFlag::CLASS_SEMANTICS_MASK {
        TypeFlag::CLASS => "class ",
        TypeFlag::INTERFACE => "interface ",
        _ => panic!(),
    };

    s
}

fn display_field_attributes(attributes: FieldAttribute) -> String {
    let mut s = String::new();

    if attributes.contains(FieldAttribute::LITERAL) {
        s += "[literal]"
    }

    if attributes.contains(FieldAttribute::NO_SERIALIZE) {
        s += "[no_serialize]"
    }

    if attributes.contains(FieldAttribute::HAS_RVA) { //RESERVED_MASK
        s += "[has_rva]"
    }

    if attributes.contains(FieldAttribute::SPECIAL) {
        s += "[special]"
    }

    if attributes.contains(FieldAttribute::RT_SPECIAL) { //RESERVED_MASK
        s += "[rt_special]"
    }

    if attributes.contains(FieldAttribute::POINTER) {
        s += "[pointer]"
    }

    if attributes.contains(FieldAttribute::MARSHAL) { //RESERVED_MASK
        s += "[marshal]"
    }

    if attributes.contains(FieldAttribute::PINVOKE) {
        s += "[pinvoke]"
    }

    if attributes.contains(FieldAttribute::EXPOSE_MEMBER) {
        s += "[expose]"
    }

    if attributes.contains(FieldAttribute::DEFAULT) { //RESERVED_MASK
        s += "[default]"
    }
    /*
    s += match attributes & FieldAttribute::RESERVED_MASK {
        FieldAttribute::NO_RESERVE => "",
        FieldAttribute::HAS_RVA => "[has_rva]",
        FieldAttribute::RT_SPECIAL => "[rt_special]",
        FieldAttribute::MARSHAL => "[marshal]",
        FieldAttribute::DEFAULT => "[default]",
        FieldAttribute::RESERVED_MASK => "[reserve?]",
        _ => panic!(),
    };*/

    s += match attributes & FieldAttribute::MEMBER_ACCESS_MASK {
        FieldAttribute::PRIVATE_SCOPE => "[hidden]private ",
        FieldAttribute::PRIVATE => "private ",
        FieldAttribute::FAM_AND_ASSEM => "private protected ",
        FieldAttribute::ASSEMBLY => "internal ",
        FieldAttribute::FAMILY => "protected ",
        FieldAttribute::FAM_OR_ASSEM => "protected internal ",
        FieldAttribute::PUBLIC => "public ",
        FieldAttribute::MEMBER_ACCESS_MASK => "[public?] ",
        _ => panic!(),
    };
   
    if attributes.contains(FieldAttribute::STATIC) {
        s += "static "
    }

    if attributes.contains(FieldAttribute::READONLY) {
        s += "readonly "
    }

    s
}

fn display_method_impl_flag(attributes: MethodImplFlag) -> String {
    let mut s = String::new();

    s += match attributes & MethodImplFlag::CODE_TYPE_MASK {
        MethodImplFlag::IL => "[il]", //implemented in IL
        MethodImplFlag::NATIVE => "[native]", //native platform-specific code
        MethodImplFlag::OPTIL => "[optil]", //optimaized IL
        MethodImplFlag::RUNTIME => "[runtime]", //auto gen by runtime (RVA must be zero)
        _ => panic!(),
    };

    /*
    s += match attributes & MethodImplFlag::MANAGED_MASK {
        MethodImplFlag::UNMANAGED => "[unmanaged]",
        MethodImplFlag::MANAGED => "",
        _ => panic!(),
    };*/

    if attributes.contains(MethodImplFlag::UNMANAGED) {
        s += "[unmanaged]"
    }

    if attributes.contains(MethodImplFlag::NO_INLINING) {
        s += "[no_inline]"
    }

    if attributes.contains(MethodImplFlag::FORWARD_REF) {
        s += "[forward_ref]"
    }
    if attributes.contains(MethodImplFlag::SYNCHRONIZED) {
        s += "[synchronized]"
    }
    if attributes.contains(MethodImplFlag::NO_OPTIMIZATION) {
        s += "[no_optimization]"
    }
    if attributes.contains(MethodImplFlag::PRESERVE_SIG) {
        s += "[preserve_sig]"
    }
    if attributes.contains(MethodImplFlag::AGGRESSIVE_INLINING) {
        s += "[inline]"
    }
    if attributes.contains(MethodImplFlag::HAS_RET_VAL) {
        s += "[ret]"
    }
    if attributes.contains(MethodImplFlag::EXPOSE_MEMBER) {
        s += "[expose]"
    }
    if attributes.contains(MethodImplFlag::EMPTY_CTOR) {
        s += "[empty_ctor]"
    }
    if attributes.contains(MethodImplFlag::INTERNAL_CALL) {
        s += "[internal_call]"
    }
    if attributes.contains(MethodImplFlag::CONTAINS_GENERIC_PARAMETERS) {
        s += "[generic]"
    }
    if attributes.contains(MethodImplFlag::HAS_THIS) {
        s += "[has_this]"
    }
    if attributes.contains(MethodImplFlag::THREAD_SAFE) {
        s += "[thread_safe]"
    }
    s
}

fn display_method_attributes(attributes: MethodAttribute) -> String {
    let mut s = String::new();

    if attributes.contains(MethodAttribute::UNMANAGED_EXPORT) {
        s += "[export]"
    }

    if attributes.contains(MethodAttribute::HIDE_BY_SIG) {
        s += "[hid_by_sig]";
    }

    if attributes.contains(MethodAttribute::NEW_SLOT) {
        s += "[new_slot]";
    }

    if attributes.contains(MethodAttribute::CHECK_ACCESS_ON_OVERRIDE) {
        s += "[check_access_override]";
    }

    if attributes.contains(MethodAttribute::SPECIAL_NAME) {
        s += "[special]";
    }

    if attributes.contains(MethodAttribute::RT_SPECIAL_NAME) {
        s += "[rt_special]";
    }

    if attributes.contains(MethodAttribute::PINVOKE_IMPL) {
        s += "[pinvoke]";
    }

    if attributes.contains(MethodAttribute::HAS_SECURITY) {
        s += "[has_security]";
    }

    if attributes.contains(MethodAttribute::REQUIRE_SEC_OBJECT) {
        s += "[require_sec_object]";
    }

    s += "\n    ";

    s += match attributes & MethodAttribute::MEMBER_ACCESS_MASK {
        MethodAttribute::PRIVATE_SCOPE => "[hidden]private ",
        MethodAttribute::PRIVATE => "private ",
        MethodAttribute::FAM_AND_ASSEM => "private protected ",
        MethodAttribute::ASSEMBLY => "internal ",
        MethodAttribute::FAMILY => "protected ",
        MethodAttribute::FAM_OR_ASSEM => "protected internal ",
        MethodAttribute::PUBLIC => "public ",
        MethodAttribute::MEMBER_ACCESS_MASK => "[public?] ",
        _ => panic!(),
    };

    if attributes.contains(MethodAttribute::STATIC) {
        s += "static ";
    }

    if attributes.contains(MethodAttribute::FINAL) {
        s += "sealed ";
    }

    if attributes.contains(MethodAttribute::VIRTUAL) {
        s += "virtual ";
    }

    if attributes.contains(MethodAttribute::ABSTRACT) {
        s += "abstract ";
    }

    s
}

fn display_param_attributes(attributes: ParamAttribute) -> String {
    let mut s = String::new();
    if attributes.contains(ParamAttribute::IN) {
        s += "in";
    }
    if attributes.contains(ParamAttribute::OUT) {
        s += "out";
    }
    if attributes.contains(ParamAttribute::LCID) {
        s += "[lcid]";
    }
    if attributes.contains(ParamAttribute::RETVAL) {
        s += "[ret]";
    }
    if attributes.contains(ParamAttribute::OPTIONAL) {
        s += "[opt]";
    }
    if attributes.contains(ParamAttribute::HAS_DEFAULT) {
        s += "[default]";
    }
    if attributes.contains(ParamAttribute::HAS_FIELD_MARSHAL) {
        s += "[marshal]";
    }
    s
}

pub struct Tdb {}

impl Tdb {
    #[allow(unused_variables, dead_code)]
    pub fn new<F: Read + Seek>(mut file: F, base_address: u64, map: Option<String>) -> Result<Tdb> {
        if &file.read_magic()? != b"TDB\0" {
            bail!("Wrong magic for TDB file");
        }

        if file.read_u32()? != 0x46 {
            bail!("Wrong version for TDB file");
        }

        if file.read_u32()? != 0 { //initialized, zero when its not runtime
            //bail!("Expected 0");
        }

        let type_instance_count = file.read_u32()?;
        let method_membership_count = file.read_u32()?;
        let field_membership_count = file.read_u32()?;
        let type_count = file.read_u32()?;
        let field_count = file.read_u32()?;
        let method_count = file.read_u32()?;
        let property_count = file.read_u32()?;
        let property_membership_count = file.read_u32()?;
        let event_count = file.read_u32()?;
        let param_count = file.read_u32()?;
        let attribute_count = file.read_u32()?;
        let constant_count = file.read_u32()?;
        let (attribute_list_count, data_attribute_list_count) =
            file.read_u32()?.bit_split((16, 16));
        let q_count = file.read_u32()?;
        let assembly_count = file.read_u32()?;

        let dev_entry = file.read_u32()?;
        /*
        println!("type_instance_count = {}", type_instance_count);
        println!("method_membership_count = {}", method_membership_count);
        println!("field_membership_count = {}", field_membership_count);
        println!("type_count = {}", type_count);
        println!("field_count = {}", field_count);
        println!("method_count = {}", method_count);
        println!("property_count = {}", property_count);
        println!("property_membership_count = {}", property_membership_count);
        println!("event_count = {}", event_count);
        println!("param_count = {}", param_count);
        println!("attribute_count = {}", attribute_count);
        println!("constant_count = {}", constant_count);
        println!("attribute_list_count = {}", attribute_list_count);
        println!("data_attribute_list_count = {}", data_attribute_list_count);
        println!("q_count = {}", q_count);

        if file.read_u32()? != 0 {
            bail!("Expected 0");
        }
        */

        let app_entry = file.read_u32()?; //appEntry
        let string_table_len = file.read_u32()?;
        let heap_len = file.read_u32()?;

        let assembly_offset = file.read_u64()? - base_address;
        let type_instance_offset = file.read_u64()? - base_address;
        let type_offset = file.read_u64()? - base_address;
        let method_membership_offset = file.read_u64()? - base_address;
        let method_offset = file.read_u64()? - base_address;
        let field_membership_offset = file.read_u64()? - base_address;
        let field_offset = file.read_u64()? - base_address;
        let property_membership_offset = file.read_u64()? - base_address;
        let property_offset = file.read_u64()? - base_address;
        let event_offset = file.read_u64()? - base_address;
        let param_offset = file.read_u64()? - base_address;
        let attribute_offset = file.read_u64()? - base_address;
        let constant_offset = file.read_u64()? - base_address;
        let attribute_list_offset = file.read_u64()? - base_address;
        let data_attribute_list_offset = file.read_u64()? - base_address;
        let string_table_offset = file.read_u64()? - base_address;
        let heap_offset = file.read_u64()? - base_address;
        let q_offset = file.read_u64()? - base_address;
        let _ = file.read_u64()?;

        struct Assembly {
            name_offset: u32,
            full_path_offset: u32,
            dll_name_offset: u32,
        }
        file.seek_noop(assembly_offset)?;
        let assemblies = (0..assembly_count)
            .map(|_| {
                file.read_u64()?;
                file.read_u64()?;

                file.read_u64()?;
                file.read_u64()?;

                file.read_u32()?;
                let name_offset = file.read_u32()?;
                let full_path_offset = file.read_u32()?;
                file.read_u32()?;

                let dll_name_offset = file.read_u32()?;
                file.read_u32()?;
                file.read_u64()?;

                file.read_u64()?;
                file.read_u64()?;

                file.read_u64()?;
                Ok(Assembly {
                    name_offset,
                    full_path_offset,
                    dll_name_offset,
                })
            })
            .collect::<Result<Vec<_>>>()?;

        struct TypeInstance {
            base_type_instance_index: usize,
            parent_type_instance_index: usize,
            underlying_type: u64,
            object_type: u64,
            arrayize_type_instance_index: usize, 
            dearrayize_type_instance_index: usize,
            type_index: usize,
            special_type_id: u64,
            b: u32,
            interface_list_offset: usize,
            method_membership_start_index: usize,
            field_membership_start_index: usize,
            template_argument_list_offset: usize,
            hash: u32,
            crc32: u32,
            flags: TypeFlag,
            event_start_index: usize,
            event_count: usize,
            property_membership_start_index: usize,
            property_count: usize,
            default_ctor_method_membership_index: usize,
        }
        file.seek_assert_align_up(type_instance_offset, 16)?;
        let type_instances = (0..type_instance_count)
            .map(|i| {
                let (index, base_type_instance_index, parent_type_instance_index, underlying_type, object_type) =
                    file.read_u64()?.bit_split((18, 18, 18, 7, 3));

                if index != u64::from(i) {
                    bail!("Unexpected index");
                }

                let (
                    arrayize_type_instance_index,
                    dearrayize_type_instance_index,
                    type_index,
                    special_type_id,
                ) = file.read_u64()?.bit_split((18, 18, 18, 10));

                let flags = file.read_u32()?; //type_flags
                let x = file.read_u32()?; //size {zero when its not runtime}
                if x != 0 {
                    // bail!("Expected 0: {}", index);
                }
                let hash = file.read_u32()?; 
                let crc32 = file.read_u32()?;

                let default_ctor_method_membership_index = file.read_u32()?;
                let b = file.read_u32()?; //vt
                let method_membership_start_index = file.read_u32()?;
                let field_membership_start_index = file.read_u32()?;

                let (property_count, property_membership_start_index) =
                    file.read_u32()?.bit_split((12, 20));
                let (event_count, event_start_index) = file.read_u32()?.bit_split((12, 20));
                let interface_list_offset = file.read_u32()?;
                let template_argument_list_offset = file.read_u32()?;

                let x = file.read_u64()?; //type {zero when its not runtime}
                if x != 0 {
                    //bail!("Expected 0: {}", index);
                }
                let x = file.read_u64()?; //managed_vt {zero when its not runtime}
                if x != 0 {
                    //bail!("Expected 0: {}", index);
                }
                Ok(TypeInstance {
                    base_type_instance_index: base_type_instance_index.try_into()?,
                    parent_type_instance_index: parent_type_instance_index.try_into()?,
                    underlying_type, //new //base tyoe of <T>
                    object_type, //new
                    arrayize_type_instance_index: arrayize_type_instance_index.try_into()?,
                    dearrayize_type_instance_index: dearrayize_type_instance_index.try_into()?,
                    type_index: type_index.try_into()?,
                    special_type_id,
                    b, //vt byte pool?
                    interface_list_offset: interface_list_offset.try_into()?,
                    method_membership_start_index: method_membership_start_index.try_into()?,
                    field_membership_start_index: field_membership_start_index.try_into()?,
                    template_argument_list_offset: template_argument_list_offset.try_into()?,
                    hash,
                    crc32,
                    flags: TypeFlag::from_bits(flags).context("Unknown type flag")?,
                    event_start_index: event_start_index.try_into()?,
                    event_count: event_count.try_into()?,
                    property_count: property_count.try_into()?,
                    property_membership_start_index: property_membership_start_index.try_into()?,
                    default_ctor_method_membership_index: default_ctor_method_membership_index
                        .try_into()?,
                })
            })
            .collect::<Result<Vec<_>>>()?;

        struct MethodMembership {
            type_instance_index: usize,
            method_index: usize,
            param_list_offset: usize,
            address: u64,
        }
        file.seek_assert_align_up(method_membership_offset, 16)?;
        let method_memberships = (0..method_membership_count)
            .map(|_| {
                let (type_instance_index, method_index, param_list_offset) =
                    file.read_u64()?.bit_split((18, 20, 26));
                let address = file.read_u64()?;
                Ok(MethodMembership {
                    type_instance_index: type_instance_index.try_into()?,
                    method_index: method_index.try_into()?,
                    param_list_offset: param_list_offset.try_into()?,
                    address,
                })
            })
            .collect::<Result<Vec<_>>>()?;

        struct FieldMembership {
            type_instance_index: usize,
            field_index: usize,
            position: u64,
        }
        file.seek_assert_align_up(field_membership_offset, 16)?;
        let field_memberships = (0..field_membership_count)
            .map(|_| {
                let (type_instance_index, field_index, position) =
                    file.read_u64()?.bit_split((18, 20, 26));
                Ok(FieldMembership {
                    type_instance_index: type_instance_index.try_into()?,
                    field_index: field_index.try_into()?,
                    position,
                })
            })
            .collect::<Result<Vec<_>>>()?;

        struct Type {
            name_offset: u32,
            namespace_offset: u32,
            len: usize,
            static_field_size: u32,

            assembly_index: u8,
            array_dimension: u8,
            method_count: usize,

            field_count: usize,

            interface_id: i16,
            native_vtable_count: u16,
            attribute_list_index: usize,
            vtable_count: u16,

            flag_a: u64,
            flag_b: u64,
        }

        file.seek_assert_align_up(type_offset, 16)?;
        let types = (0..type_count)
            .map(|_| {
                let name_offset = file.read_u32()?;
                let namespace_offset = file.read_u32()?;
                let len = file.read_u32()?;
                let static_field_size = file.read_u32()?;

                let assembly_index = file.read_u8()?;
                let array_dimension = file.read_u8()?;
                let method_count = file.read_u16()?;
                let field_count = file.read_u32()?;
                let interface_id = file.read_i16()?;
                let native_vtable_count = file.read_u16()?;
                let attribute_list_index = file.read_u16()?;
                let vtable_count = file.read_u16()?;

                let flag_a = file.read_u64()?;
                let flag_b = file.read_u64()?;
                Ok(Type {
                    name_offset,
                    namespace_offset,
                    len: len.try_into()?,
                    static_field_size,
                    assembly_index,
                    array_dimension,
                    method_count: method_count.try_into()?,
                    field_count: field_count.try_into()?,
                    interface_id,
                    native_vtable_count,
                    attribute_list_index: attribute_list_index.try_into()?,
                    vtable_count,
                    flag_a,
                    flag_b,
                })
            })
            .collect::<Result<Vec<_>>>()?;

        struct Method {
            attribute_list_index: usize,
            vtable_slot: i16,
            attributes: MethodAttribute,
            impl_flag: MethodImplFlag,
            name_offset: u32,
        }
        file.seek_assert_align_up(method_offset, 16)?;
        let methods = (0..method_count)
            .map(|_| {
                let attribute_list_index = file.read_u16()?;
                let vtable_slot = file.read_i16()?;
                let attributes = file.read_u16()?;
                let impl_flag = file.read_u16()?;
                let name_offset = file.read_u32()?;
                Ok(Method {
                    attribute_list_index: attribute_list_index.try_into()?,
                    vtable_slot,
                    attributes: MethodAttribute::from_bits(attributes)
                        .context("Unknown method attr")?,
                    impl_flag: MethodImplFlag::from_bits(impl_flag)
                        .context("Unknown method impl flag")?,
                    name_offset,
                })
            })
            .collect::<Result<Vec<_>>>()?;

        struct Field {
            attribute_list_index: usize,
            attributes: FieldAttribute,
            type_instance_index: usize,
            constant_index: usize,
            constant_index_hi: u32,
            name_offset: u32,
        }
        file.seek_assert_align_up(field_offset, 16)?;
        let fields = (0..field_count)
            .map(|_| {
                let attribute_list_index = file.read_u16()?;
                let attributes = file.read_u16()?; //flags
                let (type_instance_index, constant_index_lo) = file.read_u32()?.bit_split((18, 14)); 
                let (name_offset, constant_index_hi) = file.read_u32()?.bit_split((30, 2));  // is there a high bits of this for something else?
                let constant_index = constant_index_lo as u32 | ((constant_index_hi as u32) << 14); // assume there a high bits of constant_index
                Ok(Field {
                    attribute_list_index: attribute_list_index.try_into()?,
                    attributes: FieldAttribute::from_bits(attributes)
                        .context("Unknown field attribute")?,
                    type_instance_index: type_instance_index.try_into()?,
                    constant_index: constant_index.try_into()?,
                    constant_index_hi,
                    name_offset,
                })
            })
            .collect::<Result<Vec<_>>>()?;

        struct PropertyMembership {
            property_index: usize,
            get_method_membership_index: usize,
            set_method_membership_index: usize,
        }
        file.seek_assert_align_up(property_membership_offset, 16)?;
        let property_memberships = (0..property_membership_count)
            .map(|_| {
                let (property_index, get_method_membership_index, set_method_membership_index) =
                    file.read_u64()?.bit_split((20, 22, 22));
                Ok(PropertyMembership {
                    property_index: property_index.try_into()?,
                    get_method_membership_index: get_method_membership_index.try_into()?,
                    set_method_membership_index: set_method_membership_index.try_into()?,
                })
            })
            .collect::<Result<Vec<_>>>()?;

        struct Property {
            flags: PropertyFlag,
            attribute_list_index: usize,
            name_offset: u32,
        }
        file.seek_assert_align_up(property_offset, 16)?;
        let properties = (0..property_count)
            .map(|_| {
                let flags = file.read_u16()?;
                let attribute_list_index = file.read_u16()?;
                let name_offset = file.read_u32()?;
                Ok(Property {
                    flags: PropertyFlag::from_bits(flags).context("Unknown property flag")?,
                    attribute_list_index: attribute_list_index.try_into()?,
                    name_offset,
                })
            })
            .collect::<Result<Vec<_>>>()?;

        struct Event {
            name_offset: u32,
            add_method_membership_index: usize,
            remove_method_membership_index: usize,
        }
        file.seek_assert_align_up(event_offset, 16)?;
        let events = (0..event_count)
            .map(|_| {
                let a = file.read_u32()?;
                if a != 0 {
                    //bail!("expected 0")
                }
                let name_offset = file.read_u32()?;
                let add_method_membership_index = file.read_u32()?;
                let remove_method_membership_index = file.read_u32()?;
                Ok(Event {
                    name_offset,
                    add_method_membership_index: add_method_membership_index.try_into()?,
                    remove_method_membership_index: remove_method_membership_index.try_into()?,
                })
            })
            .collect::<Result<Vec<_>>>()?;

        struct Attribute {
            ctor_method_index: usize,
            arguments_offset: usize,
        }
        file.seek_assert_align_up(attribute_offset, 16)?;
        let attributes = (0..attribute_count)
            .map(|_| {
                let ctor_method_index = file.read_u32()?;
                let arguments_offset = file.read_u32()?;
                Ok(Attribute {
                    ctor_method_index: ctor_method_index.try_into()?,
                    arguments_offset: arguments_offset.try_into()?,
                })
            })
            .collect::<Result<Vec<_>>>()?;

        struct Param {
            attribute_list_index: usize,
            default_const_index: usize,
            name_offset: u32,
            modifier: u32,
            type_instance_index: usize,
            attribute: ParamAttribute, //paramFlag
        }
        file.seek_assert_align_up(param_offset, 16)?;
        let params = (0..param_count)
            .map(|_| {
                let attribute_list_index = file.read_u16()?;
                let default_const_index = file.read_u16()?;
                let (name_offset, modifier) = file.read_u32()?.bit_split((30, 2));
                let (type_instance_index, attribute) = file.read_u32()?.bit_split((18, 14));
                Ok(Param {
                    attribute_list_index: attribute_list_index.try_into()?,
                    default_const_index: default_const_index.try_into()?,
                    name_offset,
                    modifier,
                    type_instance_index: type_instance_index.try_into()?,
                    attribute: ParamAttribute::from_bits(u16::try_from(attribute)?)
                        .context("Unknown param attr")?,
                })
            })
            .collect::<Result<Vec<_>>>()?;

        #[derive(Clone, Copy)]
        enum Constant {
            Integral(usize),
            String(u32),
        }

        let read_constant = |file: &mut F| -> Result<Constant> {
            let raw = file.read_i32()?;
            Ok(if raw >= 0 {
                Constant::Integral(usize::try_from(raw)?)
            } else {
                Constant::String(u32::try_from(-raw)?)
            })
        };

        file.seek_assert_align_up(constant_offset, 16)?;
        let constants = (0..constant_count)
            .map(|_| read_constant(&mut file))
            .collect::<Result<Vec<_>>>()?;

        file.seek_assert_align_up(attribute_list_offset, 16)?;
        let attribute_lists = (0..attribute_list_count)
            .map(|_| file.read_u32())
            .collect::<Result<Vec<_>>>()?;

        file.seek_assert_align_up(data_attribute_list_offset, 16)?;
        let data_attribute_lists = (0..data_attribute_list_count)
            .map(|_| file.read_u32())
            .collect::<Result<Vec<_>>>()?;

        file.seek_assert_align_up(string_table_offset, 16)?;
        let mut string_table = vec![0; string_table_len.try_into()?];
        file.read_exact(&mut string_table)?;

        let read_string = move |offset: u32| {
            let offset = usize::try_from(offset)?;
            if offset >= string_table.len() {
                bail!("offset out of bount");
            }
            let mut end = offset;
            while string_table[end] != 0 {
                end += 1;
                if end >= string_table.len() {
                    bail!("end out of bound");
                }
            }
            Ok(std::str::from_utf8(&string_table[offset..end])?.to_owned())
        };

        file.seek_assert_align_up(heap_offset, 16)?;
        let mut heap = vec![0; heap_len.try_into()?];
        file.read_exact(&mut heap)?;

        file.seek_assert_align_up(q_offset, 16)?;
        let qs = (0..q_count)
            .map(|_| file.read_u32())
            .collect::<Result<Vec<_>>>()?;

        let mut symbols: Vec<Option<String>> = vec![None; type_instances.len()];

        fn build_symbol(
            symbols: &mut [Option<String>],
            index: usize,
            type_instances: &[TypeInstance],
            types: &[Type],
            heap: &[u8],
            read_string: impl Fn(u32) -> Result<String> + Copy,
        ) -> Result<String> {
            if index > symbols.len() {
                bail!("Index out of bound: {}", index);
            }
            if let Some(s) = &symbols[index] {
                return Ok(s.clone());
            }

            if index == 0 {
                symbols[index] = Some("".to_string());
                return Ok("".to_string());
            }

            let ti = &type_instances[index];
            let ty = types
                .get(ti.type_index)
                .context("Type index out of bound")?;

            if ti.dearrayize_type_instance_index != 0 {
                let element_name = build_symbol(
                    symbols,
                    ti.dearrayize_type_instance_index,
                    type_instances,
                    types,
                    heap,
                    read_string,
                )
                .context(format!("Build dearrayize symbol for {}", index))?;

                let mut suffix = "[".to_string();
                for _ in 1..ty.array_dimension {
                    suffix += ","
                }
                suffix += "]";

                let full_name = element_name + &suffix;

                symbols[index] = Some(full_name.clone());

                return Ok(full_name);
            }

            let parent = if ti.parent_type_instance_index != 0 {
                Some(
                    build_symbol(
                        symbols,
                        ti.parent_type_instance_index,
                        type_instances,
                        types,
                        heap,
                        read_string,
                    )
                    .context(format!("Build parent symbol for {}", index))?,
                )
            } else {
                None
            };

            let namespace = read_string(ty.namespace_offset)?;

            if !namespace.is_empty() && parent.is_some() {
                bail!("Parent collision");
            }

            let parent_string = if let Some(parent) = parent {
                parent + "."
            } else if !namespace.is_empty() {
                namespace + "."
            } else {
                "".to_string()
            };

            let mut full_name = parent_string + &read_string(ty.name_offset)?;

            if ti.template_argument_list_offset != 0 {
                let mut template_argument_list = &heap[ti.template_argument_list_offset..];
                let (template_type_instance_index, targ_count) =
                    template_argument_list.read_u32()?.bit_split((18, 14));

                let template_type_instance_index: usize =
                    template_type_instance_index.try_into()?;
                if template_type_instance_index != index {
                    let mut targs = vec![];
                    for _ in 0..targ_count {
                        let targ_type_instance_id: usize =
                            template_argument_list.read_u32()?.try_into()?;
                        let targ = build_symbol(
                            symbols,
                            targ_type_instance_id,
                            type_instances,
                            types,
                            heap,
                            read_string,
                        )
                        .context(format!("Build targ symbol for {}", index))?;
                        targs.push(targ);
                    }

                    full_name += "<";
                    full_name += &targs.join(",");
                    full_name += ">";
                }
            }

            symbols[index] = Some(full_name.clone());

            Ok(full_name)
        }

        for i in 0..type_instances.len() {
            build_symbol(
                &mut symbols,
                i,
                &type_instances,
                &types,
                &heap,
                &read_string,
            )?;
        }

        fn read_vint<F: ReadExt>(mut f: F) -> Result<usize> {
            let a = f.read_u8()?.into();
            if a < 128 {
                Ok(a)
            } else {
                let b: usize = f.read_u8()?.into();
                Ok(((a - 128) << 8) + b)
            }
        }

        let print_attribute = |attribute_i: usize, return_pos: bool| -> Result<()> {
            if attribute_i == 0 {
                return Ok(());
            }
            let attribute = &attributes[attribute_i];
            let ctor = &method_memberships[attribute.ctor_method_index];
            let mut attribute_args = &heap[attribute.arguments_offset..];
            let args_len = read_vint(&mut attribute_args)?;
            let mut args_data = &attribute_args[0..args_len];
            let start = args_data.read_u16()?;
            if start != 1 {
                bail!("unexpected attribute arg start {}", start)
            }
            let symbol = symbols[ctor.type_instance_index].as_ref().unwrap();
            let return_pos = if return_pos { "return:" } else { "" };
            print!("[{}{}(", return_pos, symbol);

            let mut mp = &heap[ctor.param_list_offset..];
            let param_count = mp.read_u16()?;
            let _abi_id = mp.read_u16()?;
            let _return_value_index = usize::try_from(mp.read_u32()?)?;

            let print_arg = |primitive_type: &str, args_data: &mut &[u8]| -> Result<()> {
                match primitive_type {
                    "System.UInt32" => {
                        print!("{}", args_data.read_u32()?);
                    }
                    "System.Int32" => {
                        print!("{}", args_data.read_i32()?);
                    }
                    "System.Boolean" => {
                        print!("{}", args_data.read_bool()?);
                    }
                    "System.Single" => {
                        print!("{}", args_data.read_f32()?);
                    }
                    "System.String" | "System.Type" => {
                        let len = read_vint(&mut *args_data)?;
                        let mut buf = vec![0; len];
                        args_data.read_exact(&mut buf)?;
                        let v = std::str::from_utf8(&buf)?;
                        print!("\"{}\"", v);
                    }
                    _ => {
                        // TODO: Other type
                        // And for enums, we should look up the base type
                        print!("{}", args_data.read_i32()?);
                    }
                }
                Ok(())
            };

            for param_i in 0..param_count {
                let param_index = usize::try_from(mp.read_u32()?)?;
                let param = &params[param_index];
                let param_symbol = symbols[param.type_instance_index].as_ref().unwrap();

                if param_symbol.ends_with("[]") {
                    let element_type = &param_symbol[0..param_symbol.len() - 2];
                    print!("[");
                    let len = args_data.read_u32()?;
                    for _ in 0..len {
                        print_arg(element_type, &mut args_data)?;
                        print!(",");
                    }
                    print!("]");
                } else {
                    print_arg(param_symbol, &mut args_data)?;
                }
                print!(",");
            }

            let positional_arg_count = args_data.read_u16()?;
            for _ in 0..positional_arg_count {
                let magic = args_data.read_u8()?;
                if magic != 84 {
                    print!("unexpected magic {}", magic);
                    break;
                }
                let arg_type = args_data.read_u8()?;
                let name_length = read_vint(&mut args_data)?;
                let mut name_buf = vec![0; name_length];
                args_data.read_exact(&mut name_buf)?;
                print!("{}=", std::str::from_utf8(&name_buf)?);
                match arg_type {
                    2 => {
                        print!("{}", args_data.read_bool()?);
                    }
                    14 => {
                        let v_length = read_vint(&mut args_data)?;
                        let mut v_buf = vec![0; v_length];
                        args_data.read_exact(&mut v_buf)?;
                        print!("{}", std::str::from_utf8(&v_buf)?);
                    }
                    _ => break, //TODO: what else type? Probably via.clr.ElementType
                }

                print!(",");
            }

            if !args_data.is_empty() {
                print!("$%$ leftover {:?}", args_data);
            }
            print!(")]");
            Ok(())
        };

        let print_attributes = |attribute_list_offset: u32, return_pos: bool| -> Result<()> {
            let attribute_list_offset = attribute_list_offset.try_into()?;
            let mut attribute_list = &heap[attribute_list_offset..];
            let attribute_count = attribute_list.read_u32()?;
            let attribute_list = (0..attribute_count)
                .map(|_| attribute_list.read_u32())
                .collect::<Result<Vec<_>>>()?;
            for attribute_i in attribute_list {
                print_attribute(attribute_i.try_into()?, return_pos)?;
            }
            Ok(())
        };

        let print_constants = |value: &[u8], len: usize, data_type: &String| -> Result<()> {
            let hex_value = as_hex(&value, len);

            print!(" = {:?} /*", value);
            match data_type.as_str() {
                //"System.Boolean" => {
                //}
                "System.UInt16" => {
                    print!(" uint: {}", u16::from_le_bytes(value[0..2].try_into().unwrap()));
                }
                "System.Int16" => {
                    print!(" int: {}", i16::from_le_bytes(value[0..2].try_into().unwrap()));
                }
                "System.Char" => {
                    let u = u16::from_le_bytes(value[0..2].try_into().unwrap()); //to let utf16 decode
                    let c = char::decode_utf16([u].iter().cloned())
                                                .map(|r| r.unwrap_or(REPLACEMENT_CHARACTER))
                                                .collect::<String>();
                    print!(" char: {}, {}", c, hex_value);
                }
                "System.UInt32" => {
                    print!(" uint: {}", u32::from_le_bytes(value[0..4].try_into().unwrap()));
                }
                "System.Int32" => {
                    print!(" int: {}", i32::from_le_bytes(value[0..4].try_into().unwrap()));
                }
                "System.Single" => {
                    print!(" float: {}", f32::from_le_bytes(value[0..4].try_into().unwrap()));
                }
                _ => {
                    match len {
                        1 => {
                        }
                        2 => {
                            print!(" {}, {}", u16::from_le_bytes(value[0..2].try_into().unwrap()), hex_value)
                        }
                        4 => {
                            let uint_value = u32::from_le_bytes(value[0..4].try_into().unwrap());
                            let float_value = f32::from_le_bytes(value[0..4].try_into().unwrap());
                            let int_value = i32::from_le_bytes(value[0..4].try_into().unwrap());
                            let is_positive = int_value >> 31 == 0;
                            let display_float;
                            let display_int;
                            if is_positive { //positive
                                if (float_value < 0.0001) | (float_value > 10000.0) { //not float
                                    display_float = false;
                                    if int_value > 10000 { display_int = false } else { display_int = true }
                                } else {
                                    display_float = true;
                                    if int_value > 10000 { display_int = false } else { display_int = true }
                                }
                                if display_int { print!(" uint: {}", uint_value) }
                                if display_float { print!(" float: {}", float_value) }
                            }else{ 
                                if (float_value > -0.0001) | (float_value < -10000.0) { //not float
                                    display_float = false;
                                    if int_value < -10000 { display_int = false } else { display_int = true }
                                } else {
                                    display_float = true;
                                    if int_value < -10000 { display_int = false } else { display_int = true }
                                }
                                if display_int { print!(" int: {}", int_value) }
                                if display_float { print!(" float: {}", float_value) }
                            }
                            print!(" {}", hex_value);
                        }
                        _ => print!(" {}", hex_value),
                    }
                }
            }
            print!(" */");
            Ok(())
        };
        let mut function_map: BTreeMap<u64, Vec<String>> = BTreeMap::new();

        let mut order: Vec<_> = (0..type_instances.len()).collect();
        order.sort_by_key(|&i| symbols[i].as_ref().unwrap());

        for i in order {
            let type_instance = &type_instances[i];
            let ty = types
                .get(type_instance.type_index)
                .context("Type index out of bound")?;
            println!("/// $Type_Instance[{}]", i);
            let full_name = &symbols[i].as_ref().unwrap();
            let calc_hash = hash_as_utf8(full_name);
            if i != 0 && calc_hash != type_instance.hash {
                bail!("Mismatched hash for TI[{}]", i)
            }
            println!("/// [MMH3(UTF8), CRC]: {:08X} {:08X}", calc_hash, type_instance.crc32); //mmh3utf8
            if ty.attribute_list_index != 0 {
                print_attributes(attribute_lists[ty.attribute_list_index], false)?;
                println!();
            }
            print!("{}", display_type_flag(type_instance.flags));

            println!(
                "{}: {}",
                full_name,
                symbols[type_instance.base_type_instance_index]
                    .as_ref()
                    .unwrap()
            );
            let is_enum = (symbols[type_instance.base_type_instance_index].as_ref().unwrap()).eq_ignore_ascii_case("System.Enum");

            let mut interface_list = &heap[type_instance.interface_list_offset..];
            let interface_count = interface_list.read_u32()?;
            for _ in 0..interface_count {
                let (interface_type_instance_id, interface_vtable_slot_start) =
                    interface_list.read_u32()?.bit_split((18, 14));
                let interface_type_instance_id: usize = interface_type_instance_id.try_into()?;
                println!(
                    "    ,{} /* ^{} */",
                    &symbols[interface_type_instance_id].as_ref().unwrap(),
                    interface_vtable_slot_start,
                );
            }

            println!("{{");

            if type_instance.dearrayize_type_instance_index != 0 || full_name.contains('!') {
                println!("    // Omitted ");
                println!("}}");
                println!();
                continue;
            }

            println!("    // Special(systemTypeId) = {}", type_instance.special_type_id);

            if type_instance.template_argument_list_offset != 0 {
                let mut template_argument_list =
                    &heap[type_instance.template_argument_list_offset..];
                let (template_type_instance_id, targ_count) =
                    template_argument_list.read_u32()?.bit_split((18, 14));
                let template_type_instance_id: usize = template_type_instance_id.try_into()?;
                println!(
                    "    // Template = {}",
                    symbols[template_type_instance_id].as_ref().unwrap()
                );
                if template_type_instance_id == i {
                    for _ in 0..targ_count {
                        let flag = template_argument_list.read_u32()?;
                        let name_offset = template_argument_list.read_u32()?;
                        println!(
                            "    // param {}, 0x{:08X}",
                            read_string(name_offset)?,
                            flag
                        );
                    }
                } else {
                    println!("    // Omitted ");
                    println!("}}");
                    println!();
                    continue;
                }
            }

            println!("    // fieldSize: {}", ty.len);

            println!(
                "    // staticFieldSize={}, interfaceId={}, nativeVTableCount={}, attribute_list_index={}, vtableCount={}",
                ty.static_field_size, ty.interface_id, ty.native_vtable_count, ty.attribute_list_index, ty.vtable_count
            );

            println!();
            println!("    /*** Method ***/");
            println!();
            for j in 0..ty.method_count {
                let method_membership_index = type_instance.method_membership_start_index + j;
                let method_membership = method_memberships
                    .get(method_membership_index)
                    .context("Method membership index out of bound")?;
                if method_membership.type_instance_index != i {
                    bail!("method_membership.type_instance_index mismatch");
                }

                let method = methods
                    .get(method_membership.method_index)
                    .context("Method index out of bound")?;

                if method.attribute_list_index != 0 {
                    print!("    ");
                    print_attributes(attribute_lists[method.attribute_list_index], false)?;
                    println!();
                }

                let mut mp = &heap[method_membership.param_list_offset..];
                let param_count = mp.read_u16()?;
                let abi_id = mp.read_u16()?;
                let return_value_index = usize::try_from(mp.read_u32()?)?;
                let return_value = &params[return_value_index];
                if return_value.attribute_list_index != 0 {
                    print!("    "); // returns attribute
                    print_attributes(attribute_lists[return_value.attribute_list_index], true)?;
                    println!();
                }

                let method_name = read_string(method.name_offset)?;

                println!(
                    "    {}{}{}{} {} (",
                    display_param_modifier(return_value.modifier, true),
                    display_method_impl_flag(method.impl_flag),
                    display_method_attributes(method.attributes),
                    symbols[return_value.type_instance_index].as_ref().unwrap(),
                    method_name
                );

                for _ in 0..param_count {
                    let param_index = usize::try_from(mp.read_u32()?)?;
                    let param = &params[param_index];
                    print!("        ");
                    if param.attribute_list_index != 0 {
                        print_attributes(attribute_lists[param.attribute_list_index], false)?;
                    }
                    print!(
                        "{}{} {} {}",
                        display_param_modifier(param.modifier, false),
                        display_param_attributes(param.attribute),
                        symbols[param.type_instance_index].as_ref().unwrap(),
                        read_string(param.name_offset)?
                    );

                    let param_type = symbols[param.type_instance_index].as_ref().unwrap();

                    if param.default_const_index != 0 {
                        let constant = constants[param.default_const_index];
                        match constant {
                            Constant::Integral(offset) => {
                                let field_type_instance =
                                    &type_instances[param.type_instance_index];
                                let len = types[field_type_instance.type_index].len;
                                let value = &heap[offset..][..len];
                                
                                print_constants(value, len, param_type)?;

                            }
                            Constant::String(offset) => {
                                let s = read_string(offset)?;
                                print!(" = \"{}\"", s);
                            }
                        }
                    }
                    println!(",");
                }

                let address = if method_membership.address != 0 {
                    function_map
                        .entry(method_membership.address)
                        .or_default()
                        .push(format!("{}.{}", full_name, method_name));
                    format!(" = 0x{:016X}", method_membership.address)
                } else {
                    "".to_string()
                };

                println!("    ){};\n", address);
            }

            println!();
            println!("    /*** Field ***/");
            println!();
            for j in 0..ty.field_count {
                let field_membership_index = type_instance.field_membership_start_index + j;
                let field_membership = field_memberships
                    .get(field_membership_index)
                    .context("Field membership index out of bound")?;
                if field_membership.type_instance_index != i {
                    bail!("field_membership.type_instance_index mismatch")
                }

                let field = fields
                    .get(field_membership.field_index)
                    .context("Field index out of bound")?;

                if field.attribute_list_index != 0 {
                    print!("    ");
                    print_attributes(data_attribute_lists[field.attribute_list_index], false)?;
                    println!();
                }

                print!(
                    "    {} {} {}",
                    display_field_attributes(field.attributes),
                    &symbols[field.type_instance_index].as_ref().unwrap(),
                    read_string(field.name_offset)?
                );

                if field.constant_index != 0 {
                    let constant = constants[field.constant_index];
                    if field.constant_index_hi != 0 {
                        print!("/*constant_index_hi:{}*/", field.constant_index_hi);
                    }
                    
                    let field_type = symbols[field.type_instance_index].as_ref().unwrap();

                    match constant {
                        Constant::Integral(offset) => {
                            let field_type_instance = &type_instances[field.type_instance_index];
                            let len = types[field_type_instance.type_index].len;
                            let value = &heap[offset..][..len];
                            let hex_value = as_hex(&value, len);
                            if is_enum{
                                print!(" = {:?} /*{}*/", value, hex_value);
                            }else{
                                print_constants(value, len, field_type)?;
                            }
                        }
                        Constant::String(offset) => {
                            let s = read_string(offset)?;
                            print!(" = \"{}\"", s);
                        }
                    }
                }

                println!(";");
            }

            println!();
            println!("    /*** Event ***/");
            println!();
            for j in 0..type_instance.event_count {
                let event = &events[type_instance.event_start_index + j];
                println!("    public event {};", read_string(event.name_offset)?);
            }

            println!();
            println!("    /*** Property ***/");
            println!();
            for j in 0..type_instance.property_count {
                let property_membership =
                    &property_memberships[type_instance.property_membership_start_index + j];
                let property = &properties[property_membership.property_index];
                if property.attribute_list_index != 0 {
                    print!("    ");
                    print_attributes(data_attribute_lists[property.attribute_list_index], false)?;
                    println!();
                }
                println!(
                    "    {}public property {};",
                    display_property_flag(property.flags),
                    read_string(property.name_offset)?
                );
            }

            println!("}}");
            println!();
        }

        for q in qs {
            println!("// ~ {}", read_string(q)?);
        }

        for assembly in assemblies {
            println!(
                "// <Asm> {}, {}, {}",
                read_string(assembly.name_offset)?,
                read_string(assembly.full_path_offset)?,
                read_string(assembly.dll_name_offset)?
            );
        }

        if let Some(map) = map {
            let mut map = File::create(map)?;
            for (address, names) in function_map {
                for name in names {
                    writeln!(map, "{} {:016X} f", name, address)?
                }
            }
        }

        Ok(Tdb {})
    }
}
