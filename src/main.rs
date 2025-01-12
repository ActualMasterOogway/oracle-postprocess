use clap::Parser;
use regex::Regex;
use reqwest::blocking::Client;
use reqwest::StatusCode;
use serde_json::json;
use std::fs::File;
use std::io::{self, Write};
use std::time::SystemTime;
use std::{env, fs, process};
use quick_xml::events::Event;
use quick_xml::Reader;

/// A rbxlx postprocessor that decompiles everything inside 😋
#[derive(Parser, Debug)]
#[command(author, version, about, long_about = None)]
struct Args {
    /// Input file path
    input_file: String,

    /// Output file path
    /// Defaults to out.rbxlx
    #[arg(short, long, verbatim_doc_comment, default_value = "out.rbxlx")]
    output: String,

    /// Oracle key
    /// You can also set it with the ORACLE_KEY env variable
    /// If both are provided, one from the argument is used
    #[arg(short, long, verbatim_doc_comment)]
    key: Option<String>,

    /// Oracle decompiler url
    #[arg(long, default_value = "https://oracle.mshq.dev/decompile")]
    base_url: String,
}

fn main() {
    let args = Args::parse();

    let env_key = env::var("ORACLE_KEY").ok();
    let arg_key = args.key;

    let key = arg_key.or(env_key).unwrap_or_else(|| {
        eprintln!("Oracle key not provided");
        process::exit(1);
    });

    let mut reader = Reader::from_file(&args.input_file).unwrap_or_else(|e| {
        eprintln!("Can't read the file: {}", e);
        process::exit(1);
    });

    let mut buf = Vec::new();
    let mut output = Vec::new();
    let mut in_script = false;
    let mut script_name = String::new();
    let mut script_source = String::new();
    let mut total = 0u64;
    let mut decompiled = 0u64;

    let start = SystemTime::now();

    loop {
        match reader.read_event(&mut buf) {
            Ok(Event::Start(ref e)) if e.name() == b"Item" => {
                if let Some(class) = e.attributes().find(|attr| attr.as_ref().unwrap().key == b"class") {
                    let class = class.unwrap().unescape_and_decode_value(&reader).unwrap();
                    if class == "ModuleScript" || class == "LocalScript" || class == "Script" {
                        in_script = true;
                        total += 1;
                    }
                }
            }
            Ok(Event::Start(ref e)) if in_script && e.name() == b"Properties" => {
                script_name.clear();
                script_source.clear();
            }
            Ok(Event::Start(ref e)) if in_script && e.name() == b"string" => {
                if let Some(name) = e.attributes().find(|attr| attr.as_ref().unwrap().key == b"name") {
                    let name = name.unwrap().unescape_and_decode_value(&reader).unwrap();
                    if name == "Name" {
                        script_name = reader.read_text(e.name(), &mut Vec::new()).unwrap();
                    } else if name == "Source" {
                        script_source = reader.read_text(e.name(), &mut Vec::new()).unwrap();
                    }
                }
            }
            Ok(Event::End(ref e)) if in_script && e.name() == b"Item" => {
                in_script = false;
                decompiled += 1;
                print!(
                    "[{}/{}] Decompiling {}... ",
                    decompiled,
                    total,
                    script_name
                );
                let _ = io::stdout().flush();

                let re = Regex::new(r"-- Bytecode \(Base64\):\n-- (.*)\n\n").unwrap();
                let b64_bytecode = re
                    .captures(&script_source)
                    .and_then(|it| it.get(1).map(|it| it.as_str()));

                let watermark = script_source.lines().take(6).collect::<Vec<_>>().join("\n");

                if let Some(bytecode) = b64_bytecode {
                    let start = SystemTime::now();
                    match Client::new()
                        .post(&args.base_url)
                        .header("Authorization", format!("Bearer {}", key))
                        .body(
                            serde_json::to_string(&json!({
                                "script": bytecode
                            }))
                            .unwrap(),
                        )
                        .send()
                    {
                        Ok(dec) => {
                            match dec.status() {
                                StatusCode::OK => {
                                    if let Ok(deserialized) = dec.text() {
                                        script_source = format!("{}\n{}", watermark, deserialized);
                                    }
                                    let elapsed = start.elapsed()
                                        .expect("Time went backwards");
                                    println!("decompiled in {}ms!", elapsed.as_millis());
                                }
                                StatusCode::PAYMENT_REQUIRED
                                | StatusCode::TOO_MANY_REQUESTS
                                | StatusCode::UNAUTHORIZED => {
                                    println!("{}", dec.text().ok().unwrap_or("unlucky".into()))
                                }
                                StatusCode::INTERNAL_SERVER_ERROR => {
                                    println!("Internal server error")
                                }
                                StatusCode::BAD_REQUEST => {
                                    println!("Update the app please please please please")
                                }
                                code => println!("something went wrong: {code}"),
                            }
                        }
                        Err(e) => {
                            println!("error: {e:?}");
                        }
                    }
                } else {
                    println!("no bytecode!");
                }
            }
            Ok(Event::Eof) => break,
            _ => (),
        }
        buf.clear();
    }

    let elapsed = start.elapsed()
        .expect("Time went backwards");
    println!("Processed in {}s!", elapsed.as_secs());

    print!("Writing output to {}... ", args.output);
    let _ = io::stdout().flush();

    let mut file = File::create(args.output).unwrap();
    file.write_all(&output).unwrap();
    println!("Done!");
}
