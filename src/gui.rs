use imgui::*;
use window_overlay::imgui::{RenderContext, RenderState};
use crate::config::Config;
use window_overlay::imgui::keybind::keybind_select;

pub fn gui(ui: &mut Ui, state: &mut RenderState, ctx: &mut RenderContext, config: &mut Config) {
    Window::new(im_str!("Cheat"))
        .size([400.0, 300.0], Condition::FirstUseEver)
        .collapsible(false)
        .focus_on_appearing(true)
        .build(&ui, || {
            let n = ui.begin_menu_bar();

            TabBar::new(im_str!("TabBar")).build(&ui, || {
                TabItem::new(im_str!("Aimbot")).build(&ui, || {
                    ui.checkbox(im_str!("Enabled"), &mut config.aimbot_config.enabled);
                    keybind_select(&ui, state, im_str!("Aimbot Key"), &mut config.aimbot_config.keybind);
                    ui.checkbox(im_str!("Aim at teammates"), &mut config.aimbot_config.teams);
                    // ComboBox::new(im_str!("Bone")).build(&ui, || {
                    //     Selectable::new(im_str!("Head")).build(&ui);
                    //     Selectable::new(im_str!("Chest")).build(&ui);
                    // })
                    Slider::new(im_str!("FOV"))
                        .display_format(&im_str!("{:.1}°", config.aimbot_config.fov))
                        .range(0.0..=180.0)
                        .build(&ui, &mut config.aimbot_config.fov);
                    Slider::new(im_str!("Speed"))
                        .range(0.0..=25.0)
                        .display_format(&im_str!("{:.2}", config.aimbot_config.speed))
                        .build(&ui, &mut config.aimbot_config.speed);
                    ui.checkbox(im_str!("Aimlock"), &mut config.aimbot_config.aim_lock);
                    Slider::new(im_str!("Max Distance")).range(0.0..=500.0)
                        .display_format(&im_str!("{:.0}m", config.aimbot_config.distance_limit))
                        .build(&ui, &mut config.aimbot_config.distance_limit);
                });
                TabItem::new(im_str!("ESP")).build(&ui, || {
                    ui.checkbox(im_str!("Enabled"), &mut config.esp_config.enabled);
                    Slider::new(im_str!("Max Distance"))
                        .range(0.0..=500.0)
                        .display_format(&im_str!("{:.0}m", config.esp_config.max_distance))
                        .build(&ui, &mut config.esp_config.max_distance);
                    Slider::new(im_str!("Extra Info Max Distance"))
                        .display_format(&im_str!("{:.0}m", config.esp_config.extra_info_distance))
                        .range(0.0..=500.0)
                        .build(&ui, &mut config.esp_config.extra_info_distance);
                    if config.aimbot_config.distance_limit > config.esp_config.max_distance {
                        config.aimbot_config.distance_limit = config.esp_config.max_distance;
                    }
                    if config.esp_config.extra_info_distance > config.esp_config.max_distance {
                        config.esp_config.extra_info_distance = config.esp_config.max_distance;
                    }
                    ui.checkbox(im_str!("Teammates"), &mut config.esp_config.teams);
                    // ui.checkbox(im_str!("Skeleton"), &mut config.esp_config.skeleton);
                });
                TabItem::new(im_str!("Misc")).build(&ui, || {
                    ui.checkbox(im_str!("Closest Player"), &mut config.closest_player_config.enabled);
                    ui.checkbox(im_str!("No Recoil"), &mut config.no_recoil_enabled);
                    ui.checkbox(im_str!("Show FPS"), &mut config.show_fps);
                    ui.checkbox(im_str!("Protect screenshots"), &mut ctx.bypass_screenshots);
                });
            });
        });
}