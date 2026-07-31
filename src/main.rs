use std::process::ExitCode;

fn main() -> ExitCode {
    match xsync::cli::parse_env() {
        Ok(xsync::cli::Invocation::Help) => {
            print!("{}", xsync::cli::help());
            ExitCode::SUCCESS
        }
        Ok(xsync::cli::Invocation::Version) => {
            println!("xsync {}", env!("CARGO_PKG_VERSION"));
            ExitCode::SUCCESS
        }
        Ok(xsync::cli::Invocation::Agent) => match xsync::agent::run() {
            Ok(()) => ExitCode::SUCCESS,
            Err(error) => {
                eprintln!("xsync agent: {error}");
                ExitCode::from(error.exit_code())
            }
        },
        Ok(xsync::cli::Invocation::Run(config)) => match xsync::controller::run(&config) {
            Ok(_) => ExitCode::SUCCESS,
            Err(error) => {
                if config.progress == xsync::cli::ProgressMode::Json {
                    eprintln!(
                        "{}",
                        serde_json::json!({
                            "version": 1,
                            "event": "error",
                            "message": error.to_string(),
                            "exit_code": error.exit_code(),
                        })
                    );
                } else {
                    eprintln!("xsync: {error}");
                }
                ExitCode::from(error.exit_code())
            }
        },
        Err(error) => {
            eprintln!("xsync: {error}\nTry 'xsync --help' for usage.");
            ExitCode::from(error.exit_code())
        }
    }
}
