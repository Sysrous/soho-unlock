fn main() -> Result<(), Box<dyn std::error::Error>> {
    if std::env::var("PROTOC").is_err() {
        for p in [
            r"D:\Dev\protoc\bin\protoc.exe",
            "/usr/bin/protoc",
            "/usr/local/bin/protoc",
        ] {
            if std::path::Path::new(p).exists() {
                std::env::set_var("PROTOC", p);
                break;
            }
        }
    }
    tonic_build::configure()
        .build_server(false)
        .build_transport(false)
        .compile_protos(&["proto/agent.proto"], &["proto/"])?;
    Ok(())
}
