#[allow(dead_code)]
use bpaf::Bpaf;
use std::io::{self, Write};
use std::net::{IpAddr, Ipv4Addr};
use std::sync::mpsc::{channel, Sender};
use tokio::net::TcpStream;
use tokio::task;

// Max IP port
const MAX: u16 = 65535;

// Address fallback
const IPFALLBACK: IpAddr = IpAddr::V4(Ipv4Addr::new(127, 0, 0, 1));

// CLI arguments
#[derive(Debug, Clone, Bpaf)]
#[bpaf(options)]
struct Arguments {
    // Address argument accepts -a or --address and an IpAddr type. Falls back to the above constant.
    #[bpaf(long, short, argument("Address"), fallback(IPFALLBACK))]
     address: IpAddr,
    
    // The start port of the sniffer must be greater than 0
    #[bpaf(
        long("start"),
        short('s'),
        guard(start_port_guard, "Must be greater than 0"),
        fallback(1u16)
    )]
    pub start_port: u16,

    // The end port of the sniffer must be less than or equal to 65535
    #[bpaf(
        long("end"),
        short('e'),
        guard(end_port_guard, "Must be less than or equal to 65535"),
        fallback(MAX)
    )]
    pub end_port: u16,
}

fn start_port_guard(input: &u16) -> bool {
    *input > 0
}

fn end_port_guard(input: &u16) -> bool {
    *input <= MAX
}

// Scan the port
async fn scan(tx: Sender<u16>, start_port: u16, addr: IpAddr) {
    // Attempts to connect to the address and the given port 
    match TcpStream::connect(format!("{}:{}", addr, start_port)).await {
        // If the connection is successful, print out "." and pass the port to the channel
        Ok(_) => {
            print!(".");
            io::stdout().flush().unwrap();
            tx.send(start_port).unwrap();
        }
        Err(_) => {}
    }
}

#[tokio::main]
async fn main() {
    let args = arguments().run();
    let (tx, rx) = channel();
    
    for i in args.start_port..args.end_port {
        let tx = tx.clone();
        let addr = args.address;
        task::spawn(async move { scan(tx, i, addr).await });
    }

    let mut open_ports = vec![];
    drop(tx);

    for port in rx {
        open_ports.push(port);
    }

    println!("");
    open_ports.sort();
    if open_ports.is_empty(){
        println!("No open Ports are found");
    }else{
        for port in open_ports {
            println!("{} is open", port);
        }
    }
}
