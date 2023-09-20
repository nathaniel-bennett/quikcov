use quikcov_common::prelude::*;



fn main() {
    env_logger::init();
    let mut args = std::env::args();

    if args.len() != 4 {
        println!("Usage: quikcov <gcno> <gcda> <outfile>");
        return
    }
    args.next();
    let gcno_file = args.next().unwrap().to_string();
    let gcda_file = args.next().unwrap().to_string();
    let outfile = args.next().unwrap().to_string();
    
    let gcno_bytes = std::fs::read(gcno_file).unwrap();
    let gcda_bytes = std::fs::read(gcda_file).unwrap();

    let gcno = Gcno::from_slice(gcno_bytes.as_slice()).unwrap();
    let mut gcda_reader = GcdaReader::new(gcno.clone());
    gcda_reader.read(gcda_bytes.as_slice()).unwrap();
    let cov = gcda_reader.into_coverage().unwrap();

    let bytes: Vec<u8> = postcard::to_stdvec(&cov).unwrap();
    std::fs::write(outfile, bytes).unwrap();
}






