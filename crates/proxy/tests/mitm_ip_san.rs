//! Proving + adversarial tests for MITM leaf-cert SAN handling.
//!
//! Defect: leaf_params_for used CertificateParams::new() which creates
//! dNSName SANs for all strings. Browsers (and rustls) require
//! iPAddress SANs for IP literals per RFC 2818 §3.1. A pentester
//! proxying https://127.0.0.1 would see a TLS handshake failure.

use std::sync::Arc;

use rustls::{ClientConfig, RootCertStore};
use rustls_pki_types::{CertificateDer, ServerName, pem::PemObject};
use tokio::time::{Duration, sleep};
use tokio_rustls::TlsConnector;

use wafrift_proxy::mitm::CertificateAuthority;

mod common;

fn ensure_rustls_provider() {
    common::ensure_rustls_provider()
}

async fn start_leaf_server(
    cert_der: Vec<u8>,
    key_der: Vec<u8>,
) -> (u16, tokio::task::JoinHandle<()>) {
    common::start_leaf_server(cert_der, key_der).await
}

#[tokio::test]
async fn mitm_leaf_cert_ipv4_validates_with_rustls() {
    ensure_rustls_provider();
    let host = "127.0.0.1";
    let ca = CertificateAuthority::generate().expect("generate ca");
    let (leaf_cert, leaf_key) = ca.issue_server_cert_der(host).expect("issue leaf");
    let (server_port, handle) = start_leaf_server(leaf_cert, leaf_key).await;

    let ca_cert = CertificateDer::from_pem_slice(&ca.cert_pem()).expect("parse ca cert");
    let mut roots = RootCertStore::empty();
    roots.add(ca_cert).expect("add ca cert to root store");
    let config = ClientConfig::builder()
        .with_root_certificates(roots)
        .with_no_client_auth();
    let connector = TlsConnector::from(Arc::new(config));

    let tcp = tokio::net::TcpStream::connect(("127.0.0.1", server_port))
        .await
        .expect("connect server");
    let server_name = ServerName::IpAddress(std::net::Ipv4Addr::new(127, 0, 0, 1).into());
    let _tls = connector
        .connect(server_name, tcp)
        .await
        .expect("client handshake must succeed when cert carries iPAddress SAN");
    sleep(Duration::from_millis(25)).await;
    handle.abort();
}

#[tokio::test]
async fn mitm_leaf_cert_ipv6_loopback_validates_with_rustls() {
    ensure_rustls_provider();
    let host = "::1";
    let ca = CertificateAuthority::generate().expect("generate ca");
    let (leaf_cert, leaf_key) = ca.issue_server_cert_der(host).expect("issue leaf");
    let (server_port, handle) = start_leaf_server(leaf_cert, leaf_key).await;

    let ca_cert = CertificateDer::from_pem_slice(&ca.cert_pem()).expect("parse ca cert");
    let mut roots = RootCertStore::empty();
    roots.add(ca_cert).expect("add ca cert to root store");
    let config = ClientConfig::builder()
        .with_root_certificates(roots)
        .with_no_client_auth();
    let connector = TlsConnector::from(Arc::new(config));

    let tcp = tokio::net::TcpStream::connect(("127.0.0.1", server_port))
        .await
        .expect("connect server");
    let server_name = ServerName::IpAddress(std::net::Ipv6Addr::new(0, 0, 0, 0, 0, 0, 0, 1).into());
    let _tls = connector
        .connect(server_name, tcp)
        .await
        .expect("client handshake must succeed for IPv6 loopback iPAddress SAN");
    sleep(Duration::from_millis(25)).await;
    handle.abort();
}

#[tokio::test]
async fn mitm_leaf_cert_dns_name_still_validates() {
    // Negative twin: DNS names must still produce dNSName SANs and
    // validate normally, the IP-literal fix must not break the
    // common case.
    ensure_rustls_provider();
    let host = "example.com";
    let ca = CertificateAuthority::generate().expect("generate ca");
    let (leaf_cert, leaf_key) = ca.issue_server_cert_der(host).expect("issue leaf");
    let (server_port, handle) = start_leaf_server(leaf_cert, leaf_key).await;

    let ca_cert = CertificateDer::from_pem_slice(&ca.cert_pem()).expect("parse ca cert");
    let mut roots = RootCertStore::empty();
    roots.add(ca_cert).expect("add ca cert to root store");
    let config = ClientConfig::builder()
        .with_root_certificates(roots)
        .with_no_client_auth();
    let connector = TlsConnector::from(Arc::new(config));

    let tcp = tokio::net::TcpStream::connect(("127.0.0.1", server_port))
        .await
        .expect("connect server");
    let server_name = ServerName::try_from(host).expect("server name");
    let _tls = connector
        .connect(server_name, tcp)
        .await
        .expect("client handshake for DNS name must still work");
    sleep(Duration::from_millis(25)).await;
    handle.abort();
}
