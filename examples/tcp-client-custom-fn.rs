#[cfg(feature = "tcp")]
pub fn main() {
    use futures::Future;
    use tokio_core::reactor::Core;
    use tokio_modbus::prelude::*;

    let mut core = Core::new().unwrap();
    let handle = core.handle();
    let socket_addr = "192.168.0.222:502".parse().unwrap();

    let task = tcp::connect(&handle, socket_addr).and_then(|ctx| {
        println!("Fetching the coupler ID");
        ctx.call(Request::Custom(0x66, vec![0x11, 0x42]))
            .and_then(move |rsp| {
                match rsp {
                    Response::Custom(f, rsp) => {
                        println!("Result for function {} is '{:?}'", f, rsp);
                    }
                    _ => {
                        panic!("unexpeted result");
                    }
                }
                Ok(())
            })
    });

    core.run(task).unwrap();
}

#[cfg(not(feature = "tcp"))]
pub fn main() {
    println!("feature `tcp` is required to run this example");
    std::process::exit(1);
}
