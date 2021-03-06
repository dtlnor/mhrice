use super::*;
use crate::{rsz_bitflags, rsz_enum, rsz_struct};
use serde::*;

rsz_struct! {
    #[rsz("via.physics.RequestSetColliderUserData")]
    #[derive(Debug, Serialize)]
    pub struct RequestSetColliderUserData {
        pub name: String,
        pub zero: Zero,
    }
}

rsz_struct! {
    #[rsz("via.physics.UserData")]
    #[derive(Debug, Serialize)]
    pub struct PhysicsUserData {
        pub name: String,
    }
}

rsz_struct! {
    #[rsz("snow.hit.userdata.EmHitDamageRSData")]
    #[derive(Debug, Serialize)]
    pub struct EmHitDamageRsData {
        pub base: PhysicsUserData,
        pub parts_group: u16,
    }
}

rsz_enum! {
    #[rsz(i32)]
    #[derive(Debug, Serialize)]
    pub enum CustomShapeType {
        None = 0,
        Cylinder = 1,
        HoledCylinder = 2,
        TrianglePole = 3,
        Donuts = 4,
        DonutsCylinder = 5,
    }
}

rsz_enum! {
    #[rsz(i32)]
    #[derive(Debug, Serialize)]
    pub enum LimitedHitAttr {
        None = 0,
        LimitedStan = 1,
    }
}

rsz_enum! {
    #[rsz(i32)]
    #[derive(Debug, Serialize)]
    pub enum HitSoundAttr {
        Default = 0,
        Silence = 1,
        Yarn = 2,
        Em082BubbleBreakOnce = 3,
        Em082OnibiBubbleBreakOnce = 4,
        Em082BubbleBreakMultiple = 5,
        Em082BubbleBreakMultipleLast = 6,
        EnemyIndex036IceArm = 7,
        EnemyIndex035FloatingRock = 8,
        EnemyIndex038FloatingRock = 9,
        EnemyIndex042CarryRock = 10,
        EnemyIndex042CaryyPot = 11,
        Max = 12,
        Invalid = 13,
    }
}

rsz_bitflags! {
    #[derive(Serialize)]
    pub struct DamageAttr: u16 {
        const ALLOW_DISABLE = 1;
        const NO_BREAK_CONST_OBJECT = 2;
        const NO_BREAK_CONST_OBJECT_UNIQUE = 4;
    }
}

rsz_enum! {
    #[rsz(i32)]
    #[derive(Debug, Serialize)]
    pub enum BaseHitMarkType {
        Normal = 0,
        Moderate = 1,
        Max = 2,
        Invalid = 3,
    }
}

rsz_struct! {
    #[rsz("snow.hit.userdata.EmHitDamageShapeData")]
    #[derive(Debug, Serialize)]
    pub struct EmHitDamageShapeData {
        pub base: PhysicsUserData,
        pub custom_shape_type: CustomShapeType,
        pub ring_radius: f32,
        pub limited_hit_attr: LimitedHitAttr,
        pub hit_sound_attr: HitSoundAttr,
        pub hit_pos_correction: f32,
        pub meat: i32,
        pub damage_attr: DamageAttr,
        pub base_hit_mark_type: BaseHitMarkType,
    }
}
