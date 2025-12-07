// SPDX-FileCopyrightText: Copyright (c) 2017-2025 slowtec GmbH <post@slowtec.de>
// SPDX-License-Identifier: MIT OR Apache-2.0

//! Asynchronous TLS client example

use tokio::net::TcpStream;

use std::{io, net::SocketAddr, path::Path, sync::Arc};

use rustls::pki_types::{pem::PemObject, CertificateDer, PrivateKeyDer, ServerName};
use tokio_rustls::TlsConnector;

fn load_certs(path: &Path) -> anyhow::Result<Vec<CertificateDer<'static>>> {
    CertificateDer::pem_file_iter(path)?
        .collect::<Result<Vec<_>, _>>()
        .map_err(Into::into)
}

fn load_key(path: &Path) -> anyhow::Result<PrivateKeyDer<'static>> {
    PrivateKeyDer::from_pem_file(path).map_err(Into::into)
}

#[tokio::main(flavor = "current_thread")]
async fn main() -> Result<(), Box<dyn std::error::Error>> {
    use tokio_modbus::prelude::*;

    let socket_addr: SocketAddr = "127.0.0.1:8802".parse()?;

    let mut root_cert_store = tokio_rustls::rustls::RootCertStore::empty();
    let ca_cert_path = Path::new("examples/pki/cacert.pem");
    let root_certs = load_certs(ca_cert_path)?;
    root_cert_store.add_parsable_certificates(root_certs);

    let domain = "localhost";
    let cert_path = Path::new("examples/pki/snakeoil.pem");
    let key_path = Path::new("examples/pki/snakeoil.key");
    let certs = load_certs(cert_path)?;
    let key = load_key(key_path)?;

    let config = tokio_rustls::rustls::ClientConfig::builder()
        .with_root_certificates(root_cert_store)
        .with_client_auth_cert(certs, key)
        .map_err(|err| io::Error::new(io::ErrorKind::InvalidInput, err))?;
    let connector = TlsConnector::from(Arc::new(config));

    let stream = TcpStream::connect(&socket_addr).await?;
    stream.set_nodelay(true)?;

    let domain = ServerName::try_from(domain)
        .map_err(|_| io::Error::new(io::ErrorKind::InvalidInput, "invalid dnsname"))?;

    let transport = connector.connect(domain, stream).await?;

    // Tokio modbus transport layer setup
    let mut ctx = tcp::attach(transport);

    println!("Reading Holding Registers");
    let data = ctx.read_holding_registers(40000, 68).await?;
    println!("Holding Registers Data is '{data:?}'");
    ctx.disconnect().await?;

    Ok(())
}
