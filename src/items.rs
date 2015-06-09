use rustc_serialize::{Decoder, Decodable};

pub struct ContentItem {
    pub key: [u8; 32],
    pub class: String,
    pub name: String,
    pub timestamp: i64 // thats more then enough time
}

impl Decodable for ContentItem {

    fn decode<D: Decoder>(d: &mut D) -> Result<ContentItem, D::Error> {

        d.read_tuple(8, |d| {
            let key_str: String = try!(d.read_tuple_arg(0, |d| Decodable::decode(d)));
            let class =     try!(d.read_tuple_arg(1, |d| Decodable::decode(d)));
            let name =      try!(d.read_tuple_arg(2, |d| Decodable::decode(d)));
            let _ :String = try!(d.read_tuple_arg(3, |d| Decodable::decode(d)));
            let timestamp = try!(d.read_tuple_arg(4, |d| Decodable::decode(d)));

            let _ :String = try!(d.read_tuple_arg(5, |d| Decodable::decode(d)));
            let _ :u8 =     try!(d.read_tuple_arg(6, |d| Decodable::decode(d)));
            let _ :String = try!(d.read_tuple_arg(7, |d| Decodable::decode(d)));

            if key_str.len() != 32 {
                return Err(d.error("invalid key length"))
            }
            let mut key = [0u8; 32];
            //copy_memory(&mut key, key_str.as_bytes());
            let mut i = 0;
            for byte in key_str.bytes() {
                key[i] = byte;
                i += 1;
            }

            Ok(ContentItem {
                key: key,
                class: class,
                name: name,
                timestamp: timestamp
            })
        })
    }
}


#[cfg(test)]
mod unittest {

    use items::ContentItem;
    use rustc_serialize::json;

    #[test]
    fn decode_single_content_item() {
        let encoded = r#"["5E1481A4F138412697966498AEE6429F","webforms.WebForm","Example Login","",1417924112,"",0,"N"]"#;

        let ci: ContentItem = json::decode(encoded).unwrap();

        assert!(ci.key == "5E1481A4F138412697966498AEE6429F".as_bytes());
        assert!(ci.timestamp == 1417924112);
        assert!(ci.name == "Example Login");
    }


    #[test]
    fn decode_content_item_list() {
        let encoded = r#"[
            ["5E1481A4F138412697966498AEE6429F","webforms.WebForm","Example Login","",1417924112,"",0,"N"],
            ["5E1481A4F138412697966498AEE6429F","webforms.WebForm","Example Login","",1417924112,"",0,"N"],
            ["5E1481A4F138412697966498AEE6429F","webforms.WebForm","Example Login","",1417924112,"",0,"N"]
        ]"#;

        let ci: Vec<ContentItem> = json::decode(encoded).unwrap();

        for &x in [0, 1, 2].iter() {
            assert!(ci[x].key == "5E1481A4F138412697966498AEE6429F".as_bytes());
            assert!(ci[x].timestamp == 1417924112);
            assert!(ci[x].name == "Example Login");
        }
    }
}
