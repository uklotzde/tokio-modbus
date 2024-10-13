// SPDX-FileCopyrightText: Copyright (c) 2017-2024 slowtec GmbH <post@slowtec.de>
// SPDX-License-Identifier: MIT OR Apache-2.0

use std::{fmt, io};

use futures_util::{SinkExt as _, StreamExt as _};
use tokio::io::{AsyncRead, AsyncWrite};
use tokio_util::codec::Framed;

use crate::{
    codec,
    frame::{rtu::*, *},
    slave::*,
    Result,
};

use super::disconnect;

/// _Modbus_ RTU client.
#[derive(Debug)]
pub struct Client<T> {
    framed: Framed<T, codec::rtu::ClientCodec>,
}

impl<T> Client<T>
where
    T: AsyncRead + AsyncWrite + Unpin,
{
    pub fn new(transport: T) -> Self {
        let framed = Framed::new(transport, codec::rtu::ClientCodec::default());
        Self { framed }
    }

    pub async fn disconnect(self) -> io::Result<()> {
        let Self { framed } = self;
        disconnect(framed).await
    }

    pub async fn send_request<'a>(
        &mut self,
        request: Request<'a>,
        server: Slave,
    ) -> io::Result<RequestContext> {
        self.send_request_pdu(request, server).await
    }

    async fn send_request_pdu<'a, R>(
        &mut self,
        request: R,
        server: Slave,
    ) -> io::Result<RequestContext>
    where
        R: Into<RequestPdu<'a>>,
    {
        let request_adu = request_adu(request, server);
        let context = request_adu.context();

        let Self { framed } = self;

        framed.read_buffer_mut().clear();
        framed.send(request_adu).await?;

        Ok(context)
    }

    pub async fn recv_response(&mut self, request_context: RequestContext) -> Result<Response> {
        let res_adu = self
            .framed
            .next()
            .await
            .unwrap_or_else(|| Err(io::Error::from(io::ErrorKind::BrokenPipe)))?;

        res_adu.try_into_response(request_context)
    }

    pub async fn call<'a>(&mut self, request: Request<'a>, server: Slave) -> Result<Response> {
        let request_context = self.send_request(request, server).await?;
        self.recv_response(request_context).await
    }
}

/// _Modbus_ RTU client with (server) context and connection state.
///
/// Client that invokes methods (request/response) on a single or many (broadcast) server(s).
///
/// The server can be switched between method calls.
#[derive(Debug)]
pub struct ClientContext<T> {
    client: Option<Client<T>>,
    server: Slave,
}

impl<T> ClientContext<T> {
    pub fn new(client: Client<T>, server: Slave) -> Self {
        Self {
            client: Some(client),
            server,
        }
    }

    #[must_use]
    pub const fn is_connected(&self) -> bool {
        self.client.is_some()
    }

    #[must_use]
    pub const fn server(&self) -> Slave {
        self.server
    }

    pub fn set_server(&mut self, server: Slave) {
        self.server = server;
    }
}

impl<T> ClientContext<T>
where
    T: AsyncWrite + Unpin,
{
    pub async fn disconnect(&mut self) -> io::Result<()> {
        let Some(client) = self.client.take() else {
            // Already disconnected.
            return Ok(());
        };
        disconnect(client.framed).await
    }
}

impl<T> ClientContext<T>
where
    T: AsyncRead + AsyncWrite + Unpin,
{
    pub async fn call(&mut self, request: Request<'_>) -> Result<Response> {
        log::debug!("Call {:?}", request);

        let Some(client) = &mut self.client else {
            return Err(io::Error::new(io::ErrorKind::NotConnected, "disconnected").into());
        };

        client.call(request, self.server).await
    }
}

impl<T> ClientContext<T>
where
    T: AsyncRead + AsyncWrite + Unpin + fmt::Debug + Send + 'static,
{
    #[must_use]
    pub fn boxed(self) -> Box<dyn crate::client::Client> {
        Box::new(self)
    }
}

impl<T> SlaveContext for ClientContext<T> {
    fn set_slave(&mut self, slave: Slave) {
        self.set_server(slave);
    }
}

#[async_trait::async_trait]
impl<T> crate::client::Client for ClientContext<T>
where
    T: fmt::Debug + AsyncRead + AsyncWrite + Send + Unpin,
{
    async fn call(&mut self, req: Request<'_>) -> Result<Response> {
        self.call(req).await
    }

    async fn disconnect(&mut self) -> io::Result<()> {
        self.disconnect().await
    }
}

fn request_adu<'a, R>(req: R, server: Slave) -> RequestAdu<'a>
where
    R: Into<RequestPdu<'a>>,
{
    let hdr = Header {
        slave_id: server.into(),
    };
    let pdu = req.into();
    RequestAdu { hdr, pdu }
}

#[cfg(test)]
mod tests {
    use core::{
        pin::Pin,
        task::{Context, Poll},
    };
    use tokio::io::{AsyncRead, AsyncWrite, ReadBuf, Result};

    use crate::Error;

    use super::*;

    #[derive(Debug)]
    struct MockTransport;

    impl Unpin for MockTransport {}

    impl AsyncRead for MockTransport {
        fn poll_read(
            self: Pin<&mut Self>,
            _: &mut Context<'_>,
            _: &mut ReadBuf<'_>,
        ) -> Poll<Result<()>> {
            Poll::Ready(Ok(()))
        }
    }

    impl AsyncWrite for MockTransport {
        fn poll_write(self: Pin<&mut Self>, _: &mut Context<'_>, _: &[u8]) -> Poll<Result<usize>> {
            Poll::Ready(Ok(2))
        }

        fn poll_flush(self: Pin<&mut Self>, _: &mut Context<'_>) -> Poll<Result<()>> {
            Poll::Ready(Ok(()))
        }

        fn poll_shutdown(self: Pin<&mut Self>, _: &mut Context<'_>) -> Poll<Result<()>> {
            unimplemented!()
        }
    }

    #[tokio::test]
    async fn handle_broken_pipe() {
        let transport = MockTransport;
        let client = Client::new(transport);
        let mut context = ClientContext::new(client, Slave::broadcast());
        let res = context.call(Request::ReadCoils(0x00, 5)).await;
        assert!(res.is_err());
        let err = res.err().unwrap();
        assert!(
            matches!(err, Error::Transport(err) if err.kind() == std::io::ErrorKind::BrokenPipe)
        );
    }
}
