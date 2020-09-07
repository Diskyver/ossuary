// example.rs
//
// Basic example of Ossuary communication library, without authentication
//
// Establishes a non-authenticated session between a client and server over a
// TCP connection, and exchanges encrypted messages.
//
use ossuary_async::OssuaryError;
use ossuary_async::{ConnectionType, OssuaryConnection};

use tokio::{
    net::{TcpListener, TcpStream},
    spawn,
};

use tokio_util::compat::{Tokio02AsyncReadCompatExt, Tokio02AsyncWriteCompatExt};

async fn event_loop(mut conn: OssuaryConnection, stream: TcpStream) -> Result<(), std::io::Error> {
    let mut strings = vec!["message3", "message2", "message1"];
    let mut plaintext = Vec::<u8>::new();
    let start = std::time::Instant::now();
    let name = match conn.is_server() {
        true => "server",
        false => "client",
    };
    let mut stream = stream.compat();

    // Simply run for 2 seconds
    while start.elapsed().as_secs() < 5 {
        match conn.handshake_done() {
            // Handshaking
            Ok(false) => {
                let _ = conn.send_handshake(&mut stream).await.unwrap(); // you should check errors
                let _ = conn.recv_handshake(&mut stream).await;
            }
            // Transmitting on encrypted connection
            Ok(true) => {
                if let Some(plaintext) = strings.pop() {
                    let _ = conn.send_data(plaintext.as_bytes(), &mut stream);
                }
                if let Ok(_) = conn.recv_data(&mut stream, &mut plaintext).await {
                    println!(
                        "({}) received: {:?}",
                        name,
                        String::from_utf8(plaintext.clone()).unwrap()
                    );
                    plaintext.clear();
                }
                // Client issues a disconnect when finished
                if strings.is_empty() && !conn.is_server() {
                    conn.disconnect(false);
                }
            }
            // Trust-On-First-Use
            Err(OssuaryError::UntrustedServer(pubkey)) => {
                let keys: Vec<&[u8]> = vec![&pubkey];
                let _ = conn.add_authorized_keys(keys).unwrap();
            }
            Err(OssuaryError::ConnectionClosed) => {
                println!("({}) Finished succesfully", name);
                break;
            }
            // Uh-oh.
            Err(e) => panic!("({}) Handshake failed with error: {:?}", name, e),
        }
    }
    Ok(())
}

async fn server() -> Result<(), std::io::Error> {
    let mut listener = TcpListener::bind("127.0.0.1:9988").await.unwrap();
    let (stream, _) = listener.accept().await.unwrap();
    // This server lets any client connect
    let conn = OssuaryConnection::new(ConnectionType::UnauthenticatedServer, None).unwrap();
    let _ = event_loop(conn, stream);
    Ok(())
}

async fn client() -> Result<(), std::io::Error> {
    let stream = TcpStream::connect("127.0.0.1:9988").await.unwrap();
    // This client doesn't know any servers, but will use Trust-On-First-Use
    let conn = OssuaryConnection::new(ConnectionType::Client, None).unwrap();
    let _ = event_loop(conn, stream);
    Ok(())
}

#[tokio::main]
async fn main() {
    let server = spawn(server());
    std::thread::sleep(std::time::Duration::from_millis(500));
    let client = spawn(client());

    server.await;
    client.await;
}
