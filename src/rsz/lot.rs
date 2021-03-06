use super::*;
use crate::rsz_enum;
use crate::rsz_struct;
use serde::*;

rsz_enum! {
    #[rsz(i32)]
    #[derive(Debug, Serialize, Copy, Clone, PartialEq, Eq, Hash)]
    pub enum QuestRank {
        Low = 0,
        High = 1,
    }
}

rsz_enum! {
    #[rsz(i32)]
    #[derive(Debug, Serialize, Copy, Clone, PartialEq, Eq, Hash)]
    pub enum EnemyRewardPopTypes {
        None = 0,
        MainBody = 1,
        PartsLoss1 = 2,
        PartsLoss2 = 3,
        DropItem = 4,
        DropItem2 = 5,
        DropItem3 = 6,
        DropItem4 = 7,
        DropItem5 = 8,
        DropItem6 = 9,
        Unique1 = 10,
    }
}

rsz_enum! {
    // see snow.data.PartsBreakInfo.BrokenPartsTypes
    #[rsz(i32)]
    #[derive(Debug, Serialize, PartialEq, Eq, Clone, Copy, Hash)]
    pub enum BrokenPartsTypes {
        None = 0,
        RandomId(i32) = 1..=100,
    }
}

rsz_enum! {
    #[rsz(i32)]
    #[derive(Debug, Serialize)]
    pub enum BreakLvTypes {
        None = 0,
        Lv1 = 1,
        // There is also Lv2 and Lv3, but seems unused?
    }
}

rsz_struct! {
    #[rsz("snow.data.MonsterLotTableUserData.Param")]
    #[derive(Debug, Serialize)]
    pub struct MonsterLotTableUserDataParam {
        pub em_types: EmTypes,
        pub quest_rank: QuestRank,
        pub target_reward_item_id_list: Vec<ItemId>,
        pub target_reward_num_list: Vec<u32>,
        pub target_reward_probability_list: Vec<u32>,
        pub enemy_reward_type_list: Vec<EnemyRewardPopTypes>,
        pub hagitory_reward_item_id_list: Vec<ItemId>,
        pub hagitory_reward_num_list: Vec<u32>,
        pub hagitory_reward_probability_list: Vec<u32>,
        pub capture_reward_item_id_list: Vec<ItemId>,
        pub capture_reward_num_list: Vec<u32>,
        pub capture_reward_probability_list: Vec<u32>,
        pub parts_break_list: Vec<BrokenPartsTypes>,
        pub parts_break_lv_list: Vec<BreakLvTypes>,
        pub parts_break_reward_item_id_list: Vec<ItemId>,
        pub parts_break_reward_num_list: Vec<u32>,
        pub parts_break_reward_probability_list: Vec<u32>,
        pub parts_break_reward_type_list: [EnemyRewardPopTypes; 0], // seems unused
        pub drop_reward_type_list: Vec<EnemyRewardPopTypes>,
        pub drop_reward_item_id_list: Vec<ItemId>,
        pub drop_reward_num_list: Vec<u32>,
        pub drop_reward_probability_list: Vec<u32>,
        pub otomo_reward_item_id_list: Vec<ItemId>,
        pub otomo_reward_num_list: Vec<u32>,
        pub otomo_reward_probability_list: Vec<u32>,
    }
}

rsz_struct! {
    #[rsz("snow.data.MonsterLotTableUserData")]
    #[derive(Debug, Serialize)]
    pub struct MonsterLotTableUserData {
        pub param: Vec<MonsterLotTableUserDataParam>,
    }
}

rsz_struct! {
    #[rsz("snow.enemy.EnemyDropItemInfoData.EnemyDropItemTableData.EnemyDropItemInfo")]
    #[derive(Debug, Serialize)]
    pub struct EnemyDropItemInfo {
        pub percentage: u32,
        pub enemy_reward_pop_type: EnemyRewardPopTypes,
        pub drop_item_model_type: i32, // snow.enemy.SystemEnemyDropItemMoveData.ModelTypes
    }
}

rsz_struct! {
    #[rsz("snow.enemy.EnemyDropItemInfoData.EnemyDropItemTableData")]
    #[derive(Debug, Serialize)]
    pub struct EnemyDropItemTableData {
        pub percentage: u32,
        pub enemy_drop_item_info_list: Vec<EnemyDropItemInfo>,
        pub max_num: i32,
    }
}

rsz_struct! {
    #[rsz("snow.enemy.EnemyDropItemInfoData")]
    #[derive(Debug, Serialize)]
    pub struct EnemyDropItemInfoData {
        pub enemy_drop_item_table_data_tbl: Vec<EnemyDropItemTableData>,
        pub marionette_rewad_pop_type: EnemyRewardPopTypes,
    }
}

rsz_struct! {
    #[rsz("snow.enemy.EnemyPartsBreakRewardData.EnemyPartsBreakRewardInfo.PartsBreakGroupConditionInfo")]
    #[derive(Debug, Serialize)]
    pub struct PartsBreakGroupConditionInfo {
        pub parts_group: u16,
        pub parts_break_level: u16,
    }
}

rsz_enum! {
    #[rsz(i32)]
    #[derive(Debug, Serialize)]
    pub enum EnemyPartsBreakRewardDataConditionType {
        All = 0,
        Other = 1,
    }
}

rsz_struct! {
    #[rsz("snow.enemy.EnemyPartsBreakRewardData.EnemyPartsBreakRewardInfo")]
    #[derive(Debug, Serialize)]
    pub struct EnemyPartsBreakRewardInfo {
        pub parts_break_condition_list: Vec<PartsBreakGroupConditionInfo>,
        pub condition_type: EnemyPartsBreakRewardDataConditionType ,
        pub broken_parts_type: BrokenPartsTypes,
    }
}

rsz_struct! {
    #[rsz("snow.enemy.EnemyPartsBreakRewardData")]
    #[derive(Debug, Serialize)]
    pub struct EnemyPartsBreakRewardData {
        pub enemy_parts_break_reward_infos: Vec<EnemyPartsBreakRewardInfo>,
    }
}

rsz_struct! {
    #[rsz("snow.data.PartsTypeTextUserData.TextInfo")]
    #[derive(Debug, Serialize)]
    pub struct PartsTypeTextUserDataTextInfo {
       pub enemy_type_list: Vec<EmTypes>,
       #[serde(skip)]
       aligner: Aligner<8>,
       pub text: Guid,
       pub text_for_monster_list: Guid,
    }
}

rsz_struct! {
    #[rsz("snow.data.PartsTypeTextUserData.PartsTypeInfo")]
    #[derive(Debug, Serialize)]
    pub struct PartsTypeInfo {
        pub broken_parts_types: BrokenPartsTypes,
        pub text_infos: Vec<PartsTypeTextUserDataTextInfo>
    }
}

rsz_struct! {
    #[rsz("snow.data.PartsTypeTextUserData")]
    #[derive(Debug, Serialize)]
    pub struct PartsTypeTextUserData {
        pub params: Vec<PartsTypeInfo>
    }
}
