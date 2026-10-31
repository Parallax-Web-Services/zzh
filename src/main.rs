fn main() {
    let args: Vec<String> = std::env::args().skip(1).collect();
    match zzh::run(&args) {
        Ok(code) => std::process::exit(code),
        Err(error) => {
            eprintln!("zzh: {error}");
            std::process::exit(1);
        }
    }
}
