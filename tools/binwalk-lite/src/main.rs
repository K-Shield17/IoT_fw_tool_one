use binwalk::{extractors, Binwalk};
use std::collections::{HashSet, VecDeque};
use std::env;
use std::process::ExitCode;

fn main() -> ExitCode {
    env_logger::init();
    let args: Vec<String> = env::args().collect();
    if args.len() != 3 {
        eprintln!("Usage: binwalk-lite <firmware> <extraction-directory>");
        return ExitCode::FAILURE;
    }
    let target = args[1].clone();
    let output = args[2].clone();

    let binwalker = match Binwalk::configure(Some(target), Some(output), None, None, None, false) {
        Ok(v) => v,
        Err(e) => { eprintln!("Binwalk initialization failed: {:?}", e); return ExitCode::FAILURE; }
    };

    let mut queue = VecDeque::from([binwalker.base_target_file.clone()]);
    let mut seen = HashSet::new();
    while let Some(path) = queue.pop_front() {
        if !seen.insert(path.clone()) { continue; }
        let results = binwalker.analyze(&path, true);
        match serde_json::to_string(&results) {
            Ok(line) => println!("{}", line),
            Err(e) => eprintln!("JSON serialization failed for {}: {}", path, e),
        }
        for extraction in results.extractions.values() {
            if extraction.success && !extraction.do_not_recurse {
                for child in extractors::common::get_extracted_files(&extraction.output_directory) {
                    if !seen.contains(&child) { queue.push_back(child); }
                }
            }
        }
    }
    ExitCode::SUCCESS
}
