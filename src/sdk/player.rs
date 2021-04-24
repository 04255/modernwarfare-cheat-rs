#![allow(dead_code)]

use std::collections::HashMap;

use anyhow::*;
use log::*;
use memlib::math::{Vector2, Vector3};
use memlib::memory::{Address, dump_memory, read_memory, try_read_memory};

use crate::sdk::{GameInfo, world_to_screen, units_to_m};
use crate::sdk::bone::{Bone, get_bone_position};
use crate::sdk::internal::{get_name_struct, get_camera_position};
use crate::sdk::structs::CharacterStance;
use crate::sdk::globals;

use super::bone;
use super::offsets::character_info;
use super::structs::Name;
use crate::sdk::encryption::is_visible;

#[derive(Debug, Clone)]
pub struct Player {
    pub name: String,
    pub origin: Vector3,
    pub team: i32,
    pub id: i32,
    pub stance: CharacterStance,
    pub health: i32,
    pub ads: bool,
    pub reloading: bool,
    pub base_address: Address,
    pub visible: bool,
    pub bones: HashMap<Bone, Vector3>,
}

impl Player {
    pub fn new(base_address: Address, index: i32) -> Result<Self> {
        let valid: i32 = try_read_memory(base_address + character_info::VALID).context("Could not read is_valid")?;
        if valid != 1 {
            bail!("Valid was {}", valid);
        }

        let position_address: Address = try_read_memory(base_address + character_info::POS_PTR)?;
        if position_address == 0 {
            bail!("Position address was 0");
        }

        if position_address >= 0xFFFFFFFFFFFFFFF {
            bail!("Position address was too high");
        }
        let origin: Vector3 = try_read_memory(position_address + 0x40).context("Could not read position")?;
        if origin.is_zero() {
            bail!("Origin was {:?}", origin);
        }

        let dead_1: i32 = read_memory(base_address + character_info::DEAD_1);
        if dead_1 != 0 {
            bail!("Dead was {}", dead_1);
        }

        let dead_2: i32 = read_memory(base_address + character_info::DEAD_2);
        if dead_2 != 0 {
            bail!("Dead_2 was {}", dead_2);
        }

        let stance: CharacterStance = read_memory(base_address + character_info::STANCE);
        // let stance = CharacterStance::Standing;
        let team: i32 = read_memory(base_address + character_info::TEAM);
        let ads = read_memory::<i32>(base_address + character_info::ADS) == 1;
        let reloading = read_memory::<i32>(base_address + character_info::RELOAD) == 121;

        let name_struct = get_name_struct(index as u32);
        if name_struct.health <= 0 {
            bail!("Invalidated player because health was {}", name_struct.health);
        }
        let name = name_struct.get_name();
        let health = name_struct.health;

        let mut bones = HashMap::new();

        if super::offsets::bones::ENCRYPTED_PTR != 0 {
            // TODO: Cache?
            let mut all_bones: Vec<_> = super::bone::BONE_CONNECTIONS.iter()
                .flat_map(|(a, b)| std::array::IntoIter::new([a, b]).collect::<Vec<_>>())
                .collect();
            all_bones.dedup();

            // FIXME
            if world_to_screen(&origin).is_some() {
                for bone in all_bones {
                    let pos = get_bone_position(index, *bone as _);
                    match pos {
                        Ok(pos) => {
                            let distance = units_to_m((origin - pos).length());
                            if distance > 5.0 {
                                debug!("bone {:?} position for {} was {}m away", bone, name, distance);
                                continue;
                            }
                            bones.insert(*bone, pos);
                        }
                        Err(e) => {
                            trace!("Error getting bone {:?} position for {}: {}", bone, name, e);
                        }
                    }
                }
            }
            trace!("Found {} bone positions for {}", bones.len(), name);
        }

        // let visible = is_visible(index, globals::VISIBLE_BASE.get().unwrap()).unwrap_or_else(|e| {
        //     error!("Error calling visible for index {}: {:?}", index, e);
        //     false
        // });

        trace!("Creating new player with character_id {}", index);

        Ok(Self {
            origin,
            id: index,
            team,
            name,
            stance,
            ads,
            reloading,
            health,
            base_address,
            visible: true,
            bones,
        })
    }

    pub fn is_teammate(&self, game_info: &GameInfo, friends: &[String]) -> bool {
        for friend in friends {
            if self.name.to_lowercase().contains(&friend.to_lowercase()) {
                return true;
            }
        }

        game_info.get_local_player().team == self.team
    }

    pub fn get_bone_position(&self, bone: Bone) -> Option<&Vector3> {
        self.bones.get(&bone)
        // let pos = bone::get_bone_position(self.id, unsafe { std::mem::transmute(bone) })?;
        // let distance_from_origin = crate::sdk::units_to_m((pos - self.origin).length());
        // if distance_from_origin > 2.0 {
        //     warn!("bone {:?} ({}) {}m away from {}'s origin was read ({:?})", bone, unsafe { std::mem::transmute::<Bone, i32>(bone) }, distance_from_origin, self.name, pos);
        //     bail!("Bone was too far away from player body");
        // }
        // Ok(pos)
    }

    pub fn get_head_position(&self) -> Vector3 {
        match self.get_bone_position(Bone::Head) {
            Some(pos) => *pos,
            None => {
                self.estimate_head_position()
            }
        }
    }

    /// Gets the bounding box of the player from bottom left to top right
    /// Returns None if world_to_screen fails
    pub fn get_bounding_box(&self) -> Option<(Vector2, Vector2)> {
        self.get_bounding_box_fallback()
        // match self.get_bounding_box_bones() {
        //     Some(val) => Some(val),
        //     None => self.get_bounding_box_fallback()
        // }
    }

    /// Gets the player bounding box using bone locations
    fn get_bounding_box_bones(&self) -> Option<(Vector2, Vector2)> {
        // THe bones kind of flicker atm, so we will just use fallback
        return None;
        /*
        let bones = vec![Bone::Head, Bone::Neck, Bone::Chest, Bone::Mid, Bone::Tummy,
                         Bone::RightFoot1, Bone::RightFoot2, Bone::RightFoot3, Bone::RightFoot4,
                         Bone::LeftFoot1, Bone::LeftFoot2, Bone::LeftFoot3, Bone::LeftFoot4,
                         Bone::LeftHand1, Bone::LeftHand2, Bone::LeftHand3, Bone::LeftHand4,
                         Bone::RightHand1, Bone::RightHand2, Bone::RightHand3, Bone::RightHand4];
        let mut bone_locations = Vec::new();

        for bone in bones {
            bone_locations.push(game.world_to_screen(&self.get_bone_position(&game, bone).ok()?)?);
        }

        Some(memlib::util::get_boudning_box(bone_locations))
         */
    }

    fn get_bounding_box_fallback(&self) -> Option<(Vector2, Vector2)> {
        let head_pos = self.get_head_position();
        let head_pos = world_to_screen(&(head_pos + Vector3 { x: 0.0, y: 0.0, z: 10.0 }))?;
        let feet_pos = world_to_screen(&(self.origin))?;

        let height = feet_pos.y - head_pos.y;
        let width = match self.stance {
            CharacterStance::Standing => height / 4.0,
            CharacterStance::Crouching => height / 2.5,
            CharacterStance::Downed => height * 2.0,
            CharacterStance::Crawling => height * 2.5,
        };

        let size = 1.0;

        let left_x = feet_pos.x - width - size;
        let right_x = feet_pos.x + width + size;
        let top_y = head_pos.y - size;
        let bottom_y = feet_pos.y + size;

        Some((
            Vector2 { x: left_x, y: bottom_y },
            Vector2 { x: right_x, y: top_y }
        ))
    }

    pub fn estimate_head_position(&self) -> Vector3 {
        let delta_z = match self.stance {
            CharacterStance::Standing => 58.0,
            CharacterStance::Crouching => 40.0,
            CharacterStance::Crawling => 10.0,
            CharacterStance::Downed => 20.0,
        };
        self.origin + Vector3 { x: 0.0, y: 0.0, z: delta_z }
    }
}

impl Name {
    pub fn get_name(&self) -> String {
        String::from_utf8(self.name.to_vec())
            .unwrap_or_else(|_| "".to_string())
            .trim_matches(char::from(0))
            .to_string()
    }
}