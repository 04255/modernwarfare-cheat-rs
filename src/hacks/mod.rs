use crate::config::Config;
use crate::sdk::*;
use anyhow::*;

use memlib::util::{LoopTimer, GlobalCell, InitCell};
use memlib::memory::{read_memory, Address, write_memory, get_process_info};
use memlib::math::{Angles2, Vector2, Vector3};
use std::sync::{Arc, Mutex};
use std::sync::mpsc::{Sender, channel};
use std::thread::spawn;
use crate::sdk::bone::Bone;
use crate::hacks::aimbot::AimbotContext;
use log::*;
use win_key_codes::VK_INSERT;
use std::time::{Instant, Duration};
use crate::sdk::globals::update_addresses_interval;
use std::borrow::BorrowMut;
use std::collections::{HashMap, VecDeque};
use window_overlay::window::OverlayWindow;
use window_overlay::imgui::Imgui;
use window_overlay::imgui::overlay::ImguiOverlay;
use window_overlay::imgui::keybind::keybind_select;
use winutil::Event;
use crate::find_cod_window;
use window_overlay::types::TextOptions;
use window_overlay::types;

pub mod aimbot;
pub mod closest_player;
pub mod no_recoil;
pub mod esp;

pub static CONFIG: InitCell<Config> = InitCell::new();
pub static STATE: InitCell<CheatState> = InitCell::new();

#[derive(Clone, Default)]
pub struct CheatState {
    pub aimbot_context: AimbotContext,
}

/// The main loop of the cheat
/// Returns an error if there is an error with any of the tick functions
pub fn hack_main() -> Result<()> {
    CONFIG.init(Config::load().unwrap_or_default());
    CONFIG.get_ref().save();
    STATE.init(Default::default());

    update_addresses_interval(Duration::from_secs(2));

    start_overlay_thread();
    no_recoil::start_no_recoil_thread();

    hack_loop();

    Ok(())
}

fn hack_loop() {
    let mut timer = LoopTimer::new(crate::CHEAT_TICKRATE);

    loop {
        timer.wait();

        let game_info = match get_game_info() {
            Ok(info) => info,
            Err(_) => {
                update_addresses_interval(Duration::from_secs(2));
                continue;
            }
        };

        let config = CONFIG.get_ref();
        let mut state = STATE.get_mut();

        let start = Instant::now();
        update_location_history(Instant::now(), config.seconds_pred_history, &game_info, &mut state.aimbot_context.location_history);

        aimbot::aimbot(&config, &game_info, &mut state.aimbot_context);
    }
}

fn update_location_history(update_time: Instant, max_history: f32, game_info: &GameInfo, history: &mut HashMap<i32, VecDeque<(Instant, Vector3)>>) {
    for player in &game_info.players {
        let entry = history.entry(player.id).or_insert_with(VecDeque::new);
        entry.push_back((update_time, player.origin));
        // Remove old entries
        while (update_time - entry.get(0).unwrap().0).as_secs_f32() > max_history {
            entry.pop_front();
        }
    }
}

/// Returns a sender for new game updates
pub fn start_overlay_thread() {
    spawn(move || {
        let cod_window = find_cod_window(get_process_info().pid).expect("Could not find cod window");

        let mut window = OverlayWindow::create().unwrap();
        window.controller.hide_screenshots(true);
        window.controller.set_target(Some(cod_window));

        let mut ctx = imgui::Context::create();
        window_overlay::imgui::themes::main_theme(&mut ctx);
        window_overlay::imgui::themes::dark_blue(&mut ctx);
        let mut imgui = Imgui::new(window, ctx);

        let event_listener = winutil::InputEventListener::new();

        imgui.run(move |ui, state, ctx| {
            use imgui::*;

            let mut config = CONFIG.get_mut().clone();

            ImguiOverlay::build(&ui, &ctx, true, |overlay| {
                if config.show_fps {
                    overlay.draw_text([5.0, 5.0], &format!("FPS: {}", ui.io().framerate as i32), TextOptions::default()
                        .font(types::Font::Pixel)
                        .style(types::TextStyle::Outlined))
                }

                let game_info = match get_game_info() {
                    Ok(n) => n,
                    Err(e) => {
                        return;
                    }
                };

                let cheat_state = STATE.get_clone();
                esp::esp(&game_info, overlay, &config, &cheat_state.aimbot_context);
                closest_player::closest_player(&game_info, &config, overlay);
            });

            for e in &event_listener {
                if let Event::KeyDown(key) = e {
                    if key == VK_INSERT {
                        ctx.ui_open = !ctx.ui_open;
                    }
                }
            }

            if !ctx.ui_open {
                return;
            }

            crate::gui::gui(ui, state, ctx, &mut config);

            // check if config was modified
            if !CONFIG.get_ref().eq(&config) {
                // save to file
                debug!("Saving config");
                config.save();

                CONFIG.set(config.clone());
            }
        });
    });
}