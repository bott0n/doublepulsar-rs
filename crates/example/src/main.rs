#![no_std]
#![no_main]

use api::{api::Api, util::module_size, windows::NtCurrentPeb};

#[unsafe(no_mangle)]
fn main() -> u8 {
    let mut api = Api::new();

    unsafe {
        let peb = NtCurrentPeb();
        let base = (*peb).ImageBaseAddress as *mut u8;
        let size = module_size(base as usize) as usize;

        api.sleep.buffer = base;
        api.sleep.length = size;
        api.sleep.dw_milliseconds = 5000;

        #[cfg(feature = "spoof-uwd")]
        api.build_spoof_configs();

        api::log_info!(b"image base", base);
        api::log_info!(b"image size", size);

        #[cfg(feature = "sleep-foliage")]
        {
            api::log_info!(b"=== starting foliage test (3 iterations, 5s each) ===");
            for _ in 0..3 {
                hypnus::foliage::foliage_with_fiber(&mut api);
            }
            api::log_info!(b"=== foliage test complete ===");
        }

        #[cfg(feature = "sleep-ekko")]
        {
            api::log_info!(b"=== starting ekko test (3 iterations, 5s each) ===");
            for _ in 0..3 {
                hypnus::ekko::ekko_with_fiber(&mut api);
            }
            api::log_info!(b"=== ekko test complete ===");
        }

        #[cfg(feature = "sleep-zilean")]
        {
            api::log_info!(b"=== starting zilean test (3 iterations, 5s each) ===");
            for _ in 0..3 {
                hypnus::zilean::zilean_with_fiber(&mut api);
            }
            api::log_info!(b"=== zilean test complete ===");
        }
    }

    0
}

#[cfg(not(test))]
#[panic_handler]
fn panic(_info: &core::panic::PanicInfo) -> ! {
    loop {}
}
