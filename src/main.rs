#![feature(iterator_fold_self)]
#![feature(in_band_lifetimes)]
#![feature(const_fn)]

use memlib::logger::MinimalLogger;
use memlib::memory;
use memlib::overlay;

use log::*;
use anyhow::*;
use std::error::Error;
use memlib::memory::handle_interfaces::driver_handle::DriverProcessHandle;
use memory::Handle;
use memlib::overlay::imgui::{Imgui, ImguiConfig};
use memlib::overlay::window::Window;
use win_key_codes::VK_INSERT;
use msgbox::IconType;
use memlib::winutil::{HWND, get_windows};

mod sdk;
mod hacks;
mod config;

pub const PROCESS_NAME: &str = "ModernWarfare.exe";
pub const CHEAT_TICKRATE: u64 = 120;

const LOG_LEVEL: LevelFilter = LevelFilter::Debug;

fn run() -> Result<()> {
    // Initialize the logger
    MinimalLogger::init(LOG_LEVEL)?;

    // Create a handle to the game
    let handle = Handle::from_interface(DriverProcessHandle::attach(PROCESS_NAME)?);

    // let mut window = Window::hijack_nvidia().unwrap_or_else(|_| {
    //     debug!("Could not hijack nvidia, creating window");
    //     Window::create().expect("Failed to create window")
    // });
    let mut window = Window::hijack_nvidia().expect("Failed to create window");
    let cod_window = find_cod_window(handle.get_process_info().pid).expect("Could not find cod window");
    window.target_hwnd = Some(cod_window);
    window.bypass_screenshots(true);

    memlib::system::init().unwrap();

    sdk::init(handle)?;

    // Run the hack loop
    hacks::hack_main(window)?;

    Ok(())
}

fn main() {
    std::process::exit(match run() {
        Ok(_) => {
            info!("Exiting cheat");
            0
        }
        Err(err) => {
            error!("{}", err);
            msgbox::create("Error", &err.to_string(), IconType::Error);
            1
        }
    })
}


fn find_cod_window(cod_pid: u32) -> Option<HWND> {
    get_windows().into_iter()
        .filter(|window| window.pid == cod_pid)
        .filter(|window| {
            if let Some(title) = &window.title {
                if title == "MSCTFIME UI" || title == "IME" {
                    return false;
                }
            }
            true
        })
        .map(|w| w.hwnd)
        .next()
}