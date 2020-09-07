// basic.rs
//
// Basic test of Ossuary communication library, without authentication
//
// Establishes a non-authenticated session between a client and server over a
// TCP connection, and exchanges encrypted messages.
//
use ossuary_async::OssuaryError;
use ossuary_async::{ConnectionType, OssuaryConnection};

use tokio::net::{TcpListener, TcpStream};

use futures::io::{AsyncRead, AsyncWrite};

use tokio::spawn;

use tokio_util::compat::Tokio02AsyncReadCompatExt;

async fn event_loop<T>(
    mut conn: OssuaryConnection,
    mut stream: T,
    is_server: bool,
) -> Result<(), std::io::Error>
where
    T: AsyncWrite + Unpin + AsyncRead,
{
    // Run the opaque handshake until the connection is established
    loop {
        match conn.handshake_done() {
            Ok(true) => break,
            Ok(false) => {}
            Err(OssuaryError::UntrustedServer(pubkey)) => {
                // Trust-On-First-Use would be implemented here.  This
                // client trusts all servers.
                let keys: Vec<&[u8]> = vec![&pubkey];
                let _ = conn.add_authorized_keys(keys).unwrap();
            }
            Err(e) => panic!("Handshake failed with error: {:?}", e),
        }
        if conn.send_handshake(&mut stream).await.is_ok() {
            loop {
                match conn.recv_handshake(&mut stream).await {
                    Ok(_) => break,
                    Err(OssuaryError::WouldBlock(_)) => {}
                    Err(e) => panic!("Handshake failed: {:?}", e),
                }
            }
        }
    }

    // Send a message to the other party
    let strings = ("message_from_server", "message_from_client");
    let (mut plaintext, response) = match is_server {
        true => (strings.0.as_bytes(), strings.1.as_bytes()),
        false => (strings.1.as_bytes(), strings.0.as_bytes()),
    };
    let _ = conn.send_data(&mut plaintext, &mut stream);

    // Read a message from the other party
    let mut recv_plaintext = vec![];
    loop {
        match conn.recv_data(&mut stream, &mut recv_plaintext).await {
            Ok(_) => {
                println!(
                    "(basic) received: {:?}",
                    String::from_utf8(recv_plaintext.clone()).unwrap()
                );
                assert_eq!(recv_plaintext.as_slice(), response);
                break;
            }
            _ => {}
        }
    }
    conn.disconnect(false);

    Ok(())
}

async fn server() -> Result<(), std::io::Error> {
    let mut listener = TcpListener::bind("127.0.0.1:9988").await.unwrap();
    let (stream, _) = listener.accept().await.unwrap();
    // This server lets any client connect
    let conn = OssuaryConnection::new(ConnectionType::UnauthenticatedServer, None).unwrap();
    event_loop(conn, stream.compat(), true).await
}

async fn client() -> Result<(), std::io::Error> {
    let stream = TcpStream::connect("127.0.0.1:9988").await.unwrap();
    // This client doesn't know any servers, but will use Trust-On-First-Use
    let conn = OssuaryConnection::new(ConnectionType::Client, None).unwrap();
    event_loop(conn, stream.compat(), false).await
}

#[tokio::main]
async fn main() {
    let server = spawn(server());
    std::thread::sleep(std::time::Duration::from_millis(500));
    let client = spawn(client());

    server.await.unwrap().unwrap();
    client.await.unwrap().unwrap();
}
