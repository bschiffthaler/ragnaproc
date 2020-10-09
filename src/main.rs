use libc::c_int;
use libc::kill;
use procfs::process::all_processes;
use regex::Regex;
use serde::{Deserialize, Serialize};
use std::error::Error;
use std::fs::canonicalize;
use std::fs::File;
use std::io::BufReader;
use std::io::Write;
use std::{thread, time};

#[derive(Debug, Serialize, Deserialize)]
struct ProcessTarget {
    pattern: String,
}

#[derive(Debug, Serialize, Deserialize)]
struct Config {
    minuser: Option<u32>,
    maxuser: Option<u32>,
    maxtime: Option<u64>,
    maxrss: Option<i64>,
    signal: Option<c_int>,
    poll: u64,
    deny: Vec<ProcessTarget>,
}

fn main() -> Result<(), Box<dyn Error>> {
    let config_file = File::open("ragnaproc.yaml")?;
    let reader = BufReader::new(config_file);
    let config: Config = serde_yaml::from_reader(reader)?;

    let interval = time::Duration::from_secs(config.poll);

    let mut denylist: Vec<Regex> = Vec::new();

    for target in config.deny {
        let re = Regex::new(target.pattern.as_str())?;
        denylist.push(re);
    }

    let tps: u64 = procfs::ticks_per_second()? as u64;
    let minuser = config.minuser.unwrap_or(1000);
    let maxuser = config.maxuser.unwrap_or(std::u32::MAX);
    let maxtime = config.maxtime.unwrap_or(600);
    let maxrss = config.maxrss.unwrap_or(200000000);
    let signal = config.signal.unwrap_or(2);

    println!("Polling /proc every {:?}s", &interval);
    loop {
        for p in all_processes()? {
            let stat = p.stat()?;
            if p.owner >= minuser && p.owner <= maxuser {
                let pid = stat.pid;
                let real_exe = match canonicalize(format!("/proc/{}/exe", &pid)) {
                    Ok(exe) => String::from(exe.to_str().unwrap()),
                    Err(_msg) => String::from("IOErr"),
                };
                let rss = stat.rss;
                let time = stat.utime / tps + stat.stime / tps;
                for re in &denylist {
                    if re.is_match(&real_exe) {
                        let (tty_main, tty_sub) = stat.tty_nr();

                        println!(
                            "Pattern hit [{:?}] by [{:?}] owner [{:?}] rss [{:?}] time [{:?}] tty [{:?}/{:?}]",
                            &re, &real_exe, &p.owner, &rss, &time, &tty_main, &tty_sub
                        );

                        std::fs::write(
                            format!("/dev/pts/{}", &tty_sub),
                            format!(
                                "\n\
                              Program {} should be run on SLURM.\n\
                              It will be terminated if it oversteps any of these bounds:\n\
                              CPUs: limit [{}] currently [{}]\n\
                              RSS : limit [{}] currently [{}]\n\
                              ",
                                &real_exe, &time, &maxtime, &rss, &maxrss
                            )
                            .as_str(),
                        )?;

                        if &time > &maxtime {
                            println!("  --> Time [{:?}] oversteps limit [{:?}]", &time, &maxtime);
                            println!("     --> Sending signal [{:?}]", &signal);
                            unsafe {
                                kill(pid, signal);
                            }
                        }
                        if &rss > &maxrss {
                            println!("  --> RSS [{:?}] oversteps limit [{:?}]", &rss, &maxrss);
                            println!("     --> Sending signal [{:?}]", &signal);
                            unsafe {
                                kill(pid, signal);
                            }
                        }
                    }
                }
            }
        }
        thread::sleep(interval);
    }
}
