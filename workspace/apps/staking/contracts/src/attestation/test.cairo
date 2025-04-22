use core::array::ArrayTrait;
use core::fmt::Formatter;
use core::num::traits::Zero;
use core::option::OptionTrait;
use core::traits::TryInto;
use openzeppelin::token::erc20::interface::{IERC20Dispatcher, IERC20DispatcherTrait};
use snforge_std::cheatcodes::events::{EventSpyTrait, EventsFilterTrait};
use snforge_std::test_address;
use staking::attestation::attestation::Attestation;
use staking::attestation::errors::Error;
use staking::attestation::interface::{
    IAttestationDispatcher, IAttestationDispatcherTrait, IAttestationSafeDispatcher,
    IAttestationSafeDispatcherTrait,
};
use staking::constants::MIN_ATTESTATION_WINDOW;
use staking::event_test_utils::{
    assert_attestation_window_changed_event, assert_number_of_events,
    assert_staker_attestation_successful_event,
};
use staking::reward_supplier::interface::{
    IRewardSupplierDispatcher, IRewardSupplierDispatcherTrait,
};
use staking::staking::interface::{
    IStakingAttestationDispatcher, IStakingAttestationDispatcherTrait, IStakingDispatcher,
    IStakingDispatcherTrait,
};
use staking::staking::objects::EpochInfoTrait;
use staking::test_utils;
use staking::test_utils::{approve, fund};
use staking::types::{Amount, Commission};
use starknet::{ContractAddress, contract_address_const, get_block_number};
use starkware_utils::components::replaceability::interface::{
    IReplaceableDispatcher, IReplaceableDispatcherTrait,
};
use starkware_utils::components::roles::interface::{IRolesDispatcher, IRolesDispatcherTrait};
use starkware_utils::errors::Describable;
use starkware_utils_testing::test_utils::{
    advance_block_number_global, assert_panic_with_error, cheat_caller_address_once,
};
use test_utils::constants::DUMMY_ADDRESS;
use test_utils::{
    StakingInitConfig, advance_block_into_attestation_window, advance_epoch_global,
    calculate_block_offset, general_contract_system_deployment, stake_for_testing_using_dispatcher,
};

// Helper function to generate unique test addresses
fn test_address_with_index(i: u32) -> ContractAddress {
    // Use different contract_address_const values for each index
    match i {
        0 => contract_address_const::<0x1000>(),
        1 => contract_address_const::<0x1001>(),
        2 => contract_address_const::<0x1002>(),
        3 => contract_address_const::<0x1003>(),
        4 => contract_address_const::<0x1004>(),
        5 => contract_address_const::<0x1005>(),
        6 => contract_address_const::<0x1006>(),
        7 => contract_address_const::<0x1007>(),
        8 => contract_address_const::<0x1008>(),
        9 => contract_address_const::<0x1009>(),
        _ => contract_address_const::<0x1000>(),
    }
}

#[test]
fn test_attest() {
    /// this test is a lie. it runs through the code but doesn't check the block hash correctly.
    /// the test runner currently doesn't support get_block_hash_syscall.
    /// this test should be fixed when the test runner is fixed.
    /// https://github.com/foundry-rs/starknet-foundry/issues/684
    let mut cfg: StakingInitConfig = Default::default();
    general_contract_system_deployment(ref :cfg);
    let staking_contract = cfg.test_info.staking_contract;
    let staking_dispatcher = IStakingDispatcher { contract_address: staking_contract };
    let token_address = cfg.staking_contract_info.token_address;
    stake_for_testing_using_dispatcher(:cfg, :token_address, :staking_contract);
    let attestation_contract = cfg.test_info.attestation_contract;
    let attestation_dispatcher = IAttestationDispatcher { contract_address: attestation_contract };
    let operational_address = cfg.staker_info.operational_address;
    let staker_address = cfg.test_info.staker_address;
    let mut spy = snforge_std::spy_events();
    // advance epoch to make sure the staker has a balance.
    advance_epoch_global();
    // advance into the attestation window.
    advance_block_into_attestation_window(:cfg, stake: cfg.test_info.stake_amount);
    cheat_caller_address_once(
        contract_address: attestation_contract, caller_address: operational_address,
    );
    let epoch = staking_dispatcher.get_current_epoch();
    attestation_dispatcher.attest(block_hash: Zero::zero());
    let is_attestation_done = attestation_dispatcher
        .is_attestation_done_in_curr_epoch(:staker_address);
    assert!(is_attestation_done == true);
    let events = spy.get_events().emitted_by(contract_address: attestation_contract).events;
    assert_number_of_events(actual: events.len(), expected: 1, message: "attest");
    assert_staker_attestation_successful_event(spied_event: events[0], :staker_address, :epoch);
}

#[test]
fn test_attest_assertions() {
    let mut cfg: StakingInitConfig = Default::default();
    general_contract_system_deployment(ref :cfg);
    let staking_contract = cfg.test_info.staking_contract;
    let token_address = cfg.staking_contract_info.token_address;
    stake_for_testing_using_dispatcher(:cfg, :token_address, :staking_contract);
    let attestation_contract = cfg.test_info.attestation_contract;
    let attestation_dispatcher = IAttestationDispatcher { contract_address: attestation_contract };
    let attestation_safe_dispatcher = IAttestationSafeDispatcher {
        contract_address: attestation_contract,
    };
    let operational_address = cfg.staker_info.operational_address;
    // set attestation window to 20 blocks.
    let new_attestation_window = 20;
    cheat_caller_address_once(
        contract_address: attestation_contract, caller_address: cfg.test_info.app_governor,
    );
    attestation_dispatcher.set_attestation_window(attestation_window: new_attestation_window);

    // TODO: Catch ATTEST_STARTING_EPOCH - attest in epoch 0.
    // advance epoch to make sure the staker has a balance.
    advance_epoch_global();
    // advance just before the attestation window.
    let block_offset = calculate_block_offset(
        stake: cfg.test_info.stake_amount.into(),
        epoch_id: cfg.staking_contract_info.epoch_info.current_epoch().into(),
        staker_address: cfg.test_info.staker_address.into(),
        epoch_len: cfg.staking_contract_info.epoch_info.epoch_len_in_blocks().into(),
        attestation_window: new_attestation_window,
    );
    advance_block_number_global(blocks: block_offset + MIN_ATTESTATION_WINDOW.into() - 1);

    // catch ATTEST_OUT_OF_WINDOW - attest before the attestation window.
    cheat_caller_address_once(
        contract_address: attestation_contract, caller_address: operational_address,
    );
    let result = attestation_safe_dispatcher.attest(block_hash: Zero::zero());
    assert_panic_with_error(:result, expected_error: Error::ATTEST_OUT_OF_WINDOW.describe());

    // advance past the attestation window.
    advance_block_number_global(
        blocks: (new_attestation_window - MIN_ATTESTATION_WINDOW + 2).into(),
    );

    // catch ATTEST_OUT_OF_WINDOW - attest after the attestation window.
    cheat_caller_address_once(
        contract_address: attestation_contract, caller_address: operational_address,
    );
    let result = attestation_safe_dispatcher.attest(block_hash: Zero::zero());
    assert_panic_with_error(:result, expected_error: Error::ATTEST_OUT_OF_WINDOW.describe());

    // advance to next epoch.
    let epoch_info = IStakingDispatcher { contract_address: staking_contract }.get_epoch_info();
    let next_epoch_starting_block = epoch_info.current_epoch_starting_block()
        + epoch_info.epoch_len_in_blocks().into();
    advance_block_number_global(blocks: next_epoch_starting_block - get_block_number());
    // advance into the attestation window.
    let block_offset = calculate_block_offset(
        stake: cfg.test_info.stake_amount.into(),
        epoch_id: cfg.staking_contract_info.epoch_info.current_epoch().into(),
        staker_address: cfg.test_info.staker_address.into(),
        epoch_len: cfg.staking_contract_info.epoch_info.epoch_len_in_blocks().into(),
        attestation_window: new_attestation_window,
    );
    advance_block_number_global(blocks: block_offset + MIN_ATTESTATION_WINDOW.into());
    // successful attest.
    cheat_caller_address_once(
        contract_address: attestation_contract, caller_address: operational_address,
    );
    attestation_dispatcher.attest(block_hash: Zero::zero());
    // TODO: Catch ATTEST_WRONG_BLOCK_HASH.
    // Catch ATTEST_IS_DONE.
    cheat_caller_address_once(
        contract_address: attestation_contract, caller_address: operational_address,
    );
    let result = attestation_safe_dispatcher.attest(block_hash: Zero::zero());
    assert_panic_with_error(:result, expected_error: Error::ATTEST_IS_DONE.describe());
}

#[test]
fn test_is_attestation_done_in_curr_epoch() {
    let mut cfg: StakingInitConfig = Default::default();
    general_contract_system_deployment(ref :cfg);
    let staking_contract = cfg.test_info.staking_contract;
    let token_address = cfg.staking_contract_info.token_address;
    stake_for_testing_using_dispatcher(:cfg, :token_address, :staking_contract);
    let attestation_contract = cfg.test_info.attestation_contract;
    let attestation_dispatcher = IAttestationDispatcher { contract_address: attestation_contract };
    let staker_address = cfg.test_info.staker_address;
    let operational_address = cfg.staker_info.operational_address;
    // advance epoch to make sure the staker has a balance.
    advance_epoch_global();
    // advance into the attestation window.
    advance_block_into_attestation_window(:cfg, stake: cfg.test_info.stake_amount);
    cheat_caller_address_once(
        contract_address: attestation_contract, caller_address: operational_address,
    );
    attestation_dispatcher.attest(block_hash: Zero::zero());
    let is_attestation_done = attestation_dispatcher
        .is_attestation_done_in_curr_epoch(:staker_address);
    assert!(is_attestation_done == true);
}

#[test]
fn test_is_attestation_done_in_curr_epoch_zero_epoch() {
    let mut cfg: StakingInitConfig = Default::default();
    general_contract_system_deployment(ref :cfg);
    let attestation_contract = cfg.test_info.attestation_contract;
    let attestation_safe_dispatcher = IAttestationSafeDispatcher {
        contract_address: attestation_contract,
    };
    let result = attestation_safe_dispatcher
        .is_attestation_done_in_curr_epoch(staker_address: DUMMY_ADDRESS());
    assert_panic_with_error(
        :result, expected_error: "Attestation for starting epoch is not allowed",
    );
}

#[test]
fn test_get_last_epoch_attestation_done() {
    let mut cfg: StakingInitConfig = Default::default();
    general_contract_system_deployment(ref :cfg);
    let staking_contract = cfg.test_info.staking_contract;
    let token_address = cfg.staking_contract_info.token_address;
    stake_for_testing_using_dispatcher(:cfg, :token_address, :staking_contract);
    let attestation_contract = cfg.test_info.attestation_contract;
    let attestation_dispatcher = IAttestationDispatcher { contract_address: attestation_contract };
    let staker_address = cfg.test_info.staker_address;
    let operational_address = cfg.staker_info.operational_address;
    // advance epoch to make sure the staker has a balance.
    advance_epoch_global();
    // advance into the attestation window.
    advance_block_into_attestation_window(:cfg, stake: cfg.test_info.stake_amount);
    cheat_caller_address_once(
        contract_address: attestation_contract, caller_address: operational_address,
    );
    attestation_dispatcher.attest(block_hash: Zero::zero());
    let last_epoch_attesation_done = attestation_dispatcher
        .get_last_epoch_attestation_done(:staker_address);
    assert!(last_epoch_attesation_done == 1);
}

#[test]
fn test_constructor() {
    let cfg: StakingInitConfig = Default::default();
    let mut state = Attestation::contract_state_for_testing();
    Attestation::constructor(
        ref state,
        staking_contract: cfg.test_info.staking_contract,
        governance_admin: cfg.test_info.governance_admin,
        attestation_window: MIN_ATTESTATION_WINDOW,
    );
    assert!(state.staking_contract.read() == cfg.test_info.staking_contract);
}

#[test]
#[should_panic(expected: "Attestation window is too small, must be larger then 10 blocks")]
fn test_constructor_assertions() {
    let cfg: StakingInitConfig = Default::default();
    let mut state = Attestation::contract_state_for_testing();
    Attestation::constructor(
        ref state,
        staking_contract: cfg.test_info.staking_contract,
        governance_admin: cfg.test_info.governance_admin,
        attestation_window: MIN_ATTESTATION_WINDOW - 1,
    );
}

#[test]
fn test_contract_admin_role() {
    let mut cfg: StakingInitConfig = Default::default();
    general_contract_system_deployment(ref :cfg);

    // Assert the correct governance admins is set.
    let attestation_roles_dispatcher = IRolesDispatcher {
        contract_address: cfg.test_info.attestation_contract,
    };
    assert!(
        attestation_roles_dispatcher.is_governance_admin(account: cfg.test_info.governance_admin),
    );
}

#[test]
fn test_contract_upgrade_delay() {
    let mut cfg: StakingInitConfig = Default::default();
    general_contract_system_deployment(ref :cfg);

    // Assert the upgrade delay is properly set.
    let attestation_replaceable_dispatcher = IReplaceableDispatcher {
        contract_address: cfg.test_info.attestation_contract,
    };
    assert!(attestation_replaceable_dispatcher.get_upgrade_delay() == 0);
}

#[test]
fn test_validate_next_epoch_attestation_block() {
    let mut cfg: StakingInitConfig = Default::default();
    general_contract_system_deployment(ref :cfg);
    let staking_contract = cfg.test_info.staking_contract;
    let token_address = cfg.staking_contract_info.token_address;
    stake_for_testing_using_dispatcher(:cfg, :token_address, :staking_contract);
    advance_epoch_global();
    let attestation_contract = cfg.test_info.attestation_contract;
    let attestation_dispatcher = IAttestationDispatcher { contract_address: attestation_contract };

    // calculate the next planned attestation block number.
    let staking_dispatcher = IStakingDispatcher { contract_address: staking_contract };
    let epoch_info = staking_dispatcher.get_epoch_info();
    let next_epoch_starting_block = epoch_info.current_epoch_starting_block()
        + epoch_info.epoch_len_in_blocks().into();
    let planned_attestation_block_number = next_epoch_starting_block
        + calculate_block_offset(
            stake: cfg.test_info.stake_amount.into(),
            epoch_id: cfg.staking_contract_info.epoch_info.current_epoch().into() + 1,
            staker_address: cfg.test_info.staker_address.into(),
            epoch_len: cfg.staking_contract_info.epoch_info.epoch_len_in_blocks().into(),
            attestation_window: MIN_ATTESTATION_WINDOW,
        );
    let operational_address = cfg.staker_info.operational_address;
    assert!(
        attestation_dispatcher
            .validate_next_epoch_attestation_block(
                :operational_address, block_number: planned_attestation_block_number,
            ),
    );
    assert!(
        !attestation_dispatcher
            .validate_next_epoch_attestation_block(
                :operational_address, block_number: planned_attestation_block_number - 1,
            ),
    );
    assert!(
        !attestation_dispatcher
            .validate_next_epoch_attestation_block(
                :operational_address, block_number: planned_attestation_block_number + 1,
            ),
    );
}

#[test]
fn test_set_attestation_window() {
    let mut cfg: StakingInitConfig = Default::default();
    general_contract_system_deployment(ref :cfg);
    let attestation_contract = cfg.test_info.attestation_contract;
    let attestation_dispatcher = IAttestationDispatcher { contract_address: attestation_contract };
    let old_attestation_window = attestation_dispatcher.attestation_window();
    assert!(old_attestation_window == MIN_ATTESTATION_WINDOW);
    let mut spy = snforge_std::spy_events();
    cheat_caller_address_once(
        contract_address: attestation_contract, caller_address: cfg.test_info.app_governor,
    );
    let new_attestation_window = MIN_ATTESTATION_WINDOW + 1;
    attestation_dispatcher.set_attestation_window(attestation_window: new_attestation_window);
    assert!(attestation_dispatcher.attestation_window() == MIN_ATTESTATION_WINDOW + 1);
    let events = spy.get_events().emitted_by(contract_address: attestation_contract).events;
    assert_number_of_events(actual: events.len(), expected: 1, message: "set_attestation_window");
    assert_attestation_window_changed_event(
        spied_event: events[0], :old_attestation_window, :new_attestation_window,
    );
}

#[test]
#[should_panic(expected: "ONLY_APP_GOVERNOR")]
fn test_attest_role_assertions() {
    let mut cfg: StakingInitConfig = Default::default();
    general_contract_system_deployment(ref :cfg);
    let attestation_contract = cfg.test_info.attestation_contract;
    let attestation_dispatcher = IAttestationDispatcher { contract_address: attestation_contract };
    // Catch ONLY_APP_GOVERNOR.
    attestation_dispatcher.set_attestation_window(attestation_window: MIN_ATTESTATION_WINDOW);
}

#[test]
fn test_state_bloat_attack() {
    // Summary:
    // This test demonstrates a state bloat attack where an attacker creates many small stakes
    // to increase the contract's storage size and gas costs. It shows that the contract
    // allows minimal stake amounts without proper limits.
    //
    // Testing Approach:
    // 1. Deploy the staking contract system
    // 2. Create multiple attacker addresses
    // 3. Fund each attacker with minimum stake amount
    // 4. Have each attacker stake their minimum amount
    // 5. Track and verify storage growth
    //
    // To run this test:
    // snforge test test_state_bloat_attack

    // Initialize test environment
    let mut cfg: StakingInitConfig = Default::default();
    general_contract_system_deployment(ref :cfg);
    let staking_contract = cfg.test_info.staking_contract;
    let staking_dispatcher = IStakingDispatcher { contract_address: staking_contract };
    let token_address = cfg.staking_contract_info.token_address;

    // Test parameters
    let num_attackers: u32 = 100;
    let min_stake_amount = staking_dispatcher
        .contract_parameters_v1()
        .min_stake; // Use actual minimum stake amount
    let mut total_stake: u128 = 0;

    // Track initial storage
    let initial_storage = staking_dispatcher.get_total_stake();

    // List of attacker addresses
    let attacker_addresses = array![
        contract_address_const::<
            0x03896fb19EaFd5A682386AEFc2D9d027da9615743c004612254B7eC9E6371C1A,
        >(),
        contract_address_const::<
            0x03896fb19EaFd5A682386AEFc2D9d027da9615743c004612264B7eC9E6371C1B,
        >(),
        contract_address_const::<
            0x03896fb19EaFd5A682386AEFc2D9d027da9615743c004612274B7eC9E6371C1C,
        >(),
        contract_address_const::<
            0x03896fb19EaFd5A682386AEFc2D9d027da9615743c004612284B7eC9E6371C1D,
        >(),
        contract_address_const::<
            0x03896fb19EaFd5A682386AEFc2D9d027da9615743c004612294B7eC9E6371C1E,
        >(),
        contract_address_const::<
            0x03896fb19EaFd5A682386AEFc2D9d027da9615743c004612241B7eC9E6371C1F,
        >(),
        contract_address_const::<
            0x03896fb19EaFd5A682386AEFc2D9d027da9615743c004612242B7eC9E6371C0F,
        >(),
        contract_address_const::<
            0x03896fb19EaFd5A682386AEFc2D9d027da9615743c004612243B7eC9E6371C2F,
        >(),
        contract_address_const::<
            0x03896fb19EaFd5A682386AEFc2D9d027da9615743c004612244B7eC9E6371C3F,
        >(),
        contract_address_const::<
            0x03896fb19EaFd5A682386AEFc2D9d027da9615743c004612245B7eC9E6371C4F,
        >(),
        contract_address_const::<
            0x00896fb19EaFd5A682386AEFc2D9d027da9615743c004612245B7eC9E6371C5F,
        >(),
        contract_address_const::<
            0x00096fb19EaFd5A682386AEF92D9d027da9615743c004612245B7eC9E6371C6F,
        >(),
        contract_address_const::<
            0x00006fb19EaFd5A682386AEF82D9d027da9615743c004612245B7eC9E6371C7F,
        >(),
        contract_address_const::<
            0x00006fb19EaFd5A682386AEF72D9d027da9615743c004612245B7eC9E6371C8F,
        >(),
        contract_address_const::<
            0x00002fb19EaFd5A682386AEF62D9d027da9615743c004612245B7eC9E6371C9F,
        >(),
        contract_address_const::<
            0x00001fb19EaFd5A682386AEF52D9d027da9615743c004612245B7eC9E6371CAF,
        >(),
        contract_address_const::<
            0x00007fb19EaFd5A682386AEF42D9d027da9615743c004612245B7eC9E6371CBF,
        >(),
        contract_address_const::<
            0x00008fb19EaFd5A682386AEF32D9d027da9615743c004612245B7eC9E6371CCF,
        >(),
        contract_address_const::<
            0x00009fb19EaFd5A682386AEF22D9d027da9615743c004612245B7eC9E6371CDF,
        >(),
        contract_address_const::<
            0x00011fb19EaFd5A682386AEF12D9d027da9615743c004612245B7eC9E6371CEF,
        >(),
        contract_address_const::<
            0x00017fb19EaFd5A682386AEF02D9d027da9615743c004612245B7eC9E637101F,
        >(),
        contract_address_const::<
            0x00208fb19EaFd5A682386AEFc9D9d027da9615743c004612245B7eC9E637111F,
        >(),
        contract_address_const::<
            0x00309fb19EaFd5A682386AEFc8D9d027da9615743c004612245B7eC9E637121F,
        >(),
        contract_address_const::<
            0x00409fb19EaFd5A682386AEFc7D9d027da9615743c004612245B7eC9E637131F,
        >(),
        contract_address_const::<
            0x03896fb19EaFd5A682386AEFc6D9d027da9615743c004612254B7eC9E6371C1A,
        >(),
        contract_address_const::<
            0x03896fb19EaFd5A682386AEFc5D9d027da9615743c004612264B7eC9E6301C1B,
        >(),
        contract_address_const::<
            0x03896fb19EaFd5A682386AEFc4D9d027da9615743c004612274B7eC9E6311C1C,
        >(),
        contract_address_const::<
            0x03896fb19EaFd5A682386AEFc3D9d027da9615743c004612284B7eC9E6321C1D,
        >(),
        contract_address_const::<
            0x03896fb19EaFd5A682386AEFc1D9d027da9615743c004612294B7eC9E6331C1E,
        >(),
        contract_address_const::<
            0x03896fb19EaFd5A682386AEFc0D9d027da9615743c004612241B7eC9E6341C1F,
        >(),
        contract_address_const::<
            0x03896fb19EaFd5A682386AEFc2C9d027da9615743c004612242B7eC9E6351C0F,
        >(),
        contract_address_const::<
            0x03896fb19EaFd5A682386AEFc2B9d027da9615743c004612243B7eC9E6361C2F,
        >(),
        contract_address_const::<
            0x03896fb19EaFd5A682386AEFc2A9d027da9615743c004612244B7eC9E6381C3F,
        >(),
        contract_address_const::<
            0x03896fb19EaFd5A682386AEFc289d027da9615743c004612245B7eC9E6391C4F,
        >(),
        contract_address_const::<
            0x00896fb19EaFd5A682386AEFc279d027da9615743c004612245B7eC9E63A1C5F,
        >(),
        contract_address_const::<
            0x00096fb19EaFd5A682386AEFc269d027da9615743c004612245B7eC9E63B1C6F,
        >(),
        contract_address_const::<
            0x00006fb19EaFd5A682386AEFc259d027da9615743c004612245B7eC9E63C1C7F,
        >(),
        contract_address_const::<
            0x00006fb19EaFd5A682386AEFc249d027da9615743c004612245B7eC9E63D1C8F,
        >(),
        contract_address_const::<
            0x00002fb19EaFd5A682386AEFc239d027da9615743c004612245B7eC9E63E1C9F,
        >(),
        contract_address_const::<
            0x00001fb19EaFd5A682386AEFc229d027da9615743c004612245B7eC9E63F1CAF,
        >(),
        contract_address_const::<
            0x00007fb19EaFd5A682386AEFc219d027da9615743c004612245B7eC9E6071CBF,
        >(),
        contract_address_const::<
            0x00008fb19EaFd5A682386AEFc209d027da9615743c004612245B7eC9E6171CCF,
        >(),
        contract_address_const::<
            0x00009fb19EaFd5A682386AEFc2DEd027da9615743c004612245B7eC9E6271CDF,
        >(),
        contract_address_const::<
            0x00011fb19EaFd5A682386AEFc2DDd027da9615743c004612245B7eC9E6471CEF,
        >(),
        contract_address_const::<
            0x00017fb19EaFd5A682386AEFc2DCd027da9615743c004612245B7eC9E657101F,
        >(),
        contract_address_const::<
            0x00208fb19EaFd5A682386AEFc2DBd027da9615743c004612245B7eC9E667111F,
        >(),
        contract_address_const::<
            0x00309fb19EaFd5A682386AEFc2DAd027da9615743c004612245B7eC9E677121F,
        >(),
        contract_address_const::<
            0x00409fb19EaFd5A682386AEFc2D8d027da9615743c004612245B7eC9E687131F,
        >(),
        contract_address_const::<
            0x03896fb19EaFd5A682386AEFc2D7d027da9615743c004612254B7e09E6371C1A,
        >(),
        contract_address_const::<
            0x03896fb19EaFd5A682386AEFc2D6d027da9615743c004612264B7e19E6371C1B,
        >(),
        contract_address_const::<
            0x03896fb19EaFd5A682386AEFc2D5d027da9615743c004612274B7e29E6371C1C,
        >(),
        contract_address_const::<
            0x03896fb19EaFd5A682386AEFc2D4d027da9615743c004612284B7e39E6371C1D,
        >(),
        contract_address_const::<
            0x03896fb19EaFd5A682386AEFc2D3d027da9615743c004612294B7e49E6371C1E,
        >(),
        contract_address_const::<
            0x03896fb19EaFd5A682386AEFc2D2d027da9615743c004612241B7e59E6371C1F,
        >(),
        contract_address_const::<
            0x03896fb19EaFd5A682386AEFc2D1d027da9615743c004612242B7e69E6371C0F,
        >(),
        contract_address_const::<
            0x03896fb19EaFd5A682386AEFc2D0d027da9615743c004612243B7e79E6371C2F,
        >(),
        contract_address_const::<
            0x03896fb19EaFd5A682386AEFc2D9F027da9615743c004612244B7e89E6371C3F,
        >(),
        contract_address_const::<
            0x03896fb19EaFd5A682386AEFc2D9E027da9615743c004612245B7e99E6371C4F,
        >(),
        contract_address_const::<
            0x00896fb19EaFd5A682386AEFc2DDd027da9615743c004612245B7eA9E6371C5F,
        >(),
        contract_address_const::<
            0x00096fb19EaFd5A682386AEFc2DCd027da9615743c004612245B7eB9E6371C6F,
        >(),
        contract_address_const::<
            0x00006fb19EaFd5A682386AEFc2DBd027da9615743c004612245B7eD9E6371C7F,
        >(),
        contract_address_const::<
            0x00006fb19EaFd5A682386AEFc2DAd027da9615743c004612245B7eE9E6371C8F,
        >(),
        contract_address_const::<
            0x00002fb19EaFd5A682386AEFc2D8d027da9615743c004612245B7eF9E6371C9F,
        >(),
        contract_address_const::<
            0x00001fb19EaFd5A682386AEFc2D7d027da9615743c004612245B70C9E6371CAF,
        >(),
        contract_address_const::<
            0x00007fb19EaFd5A682386AEFc2D6d027da9615743c004612245B71C9E6371CBF,
        >(),
        contract_address_const::<
            0x00008fb19EaFd5A682386AEFc2D5d027da9615743c004612245B72C9E6371CCF,
        >(),
        contract_address_const::<
            0x00009fb19EaFd5A682386AEFc2D4d027da9615743c004612245B73C9E6371CDF,
        >(),
        contract_address_const::<
            0x00011fb19EaFd5A682386AEFc2D3d027da9615743c004612245B74C9E6371CEF,
        >(),
        contract_address_const::<
            0x00017fb19EaFd5A682386AEFc2D2d027da9615743c004612245B75C9E637101F,
        >(),
        contract_address_const::<
            0x00208fb19EaFd5A682386AEFc2D1d027da9615743c004612245B76C9E637111F,
        >(),
        contract_address_const::<
            0x00309fb19EaFd5A682386AEFc2D90d027da9615743c004612245B77C9E637121F,
        >(),
        contract_address_const::<
            0x00409fb19EaFd5A682386AEFc2D99027da9615743c004612245B78C9E637131F,
        >(),
        contract_address_const::<
            0x03896fb19EaFd5A682386AEFc2D98027da9615743c004612254B79C9E6371C1A,
        >(),
        contract_address_const::<
            0x03896fb19EaFd5A682386AEFc2D97027da9615743c004612264B1eC9E6301C1B,
        >(),
        contract_address_const::<
            0x03896fb19EaFd5A682386AEFc2D96027da9615743c004612274B2eC9E6311C1C,
        >(),
        contract_address_const::<
            0x03896fb19EaFd5A682386AEFc2D95027da9615743c004612284B3eC9E6321C1D,
        >(),
        contract_address_const::<
            0x03896fb19EaFd5A682386AEFc2D94027da9615743c004612294B4eC9E6331C1E,
        >(),
        contract_address_const::<
            0x03896fb19EaFd5A682386AEFc2D93027da9615743c004612241B5eC9E6341C1F,
        >(),
        contract_address_const::<
            0x03896fb19EaFd5A682386AEFc2D92027da9615743c004612242B6eC9E6351C0F,
        >(),
        contract_address_const::<
            0x03896fb19EaFd5A682386AEFc2D91027da9615743c004612243B8eC9E6361C2F,
        >(),
        contract_address_const::<
            0x03896fb19EaFd5A682386AEFc2D90027da9615743c004612244B9eC9E6381C3F,
        >(),
        contract_address_const::<
            0x03896fb19EaFd5A682386AEFc2D9dF27da9615743c00461224507eC9E6391C4F,
        >(),
        contract_address_const::<
            0x00896fb19EaFd5A682386AEFc2D9dE27da9615743c00461224517eC9E63A1C5F,
        >(),
        contract_address_const::<
            0x00096fb19EaFd5A682386AEFc2D9dD27da9615743c00461224527eC9E63B1C6F,
        >(),
        contract_address_const::<
            0x00006fb19EaFd5A682386AEFc2D9dC27da9615743c00461224537eC9E63C1C7F,
        >(),
        contract_address_const::<
            0x00006fb19EaFd5A682386AEFc2D9dB27da9615743c00461224547eC9E63D1C8F,
        >(),
        contract_address_const::<
            0x00002fb19EaFd5A682386AEFc2D9dA27da9615743c00461224557eC9E63E1C9F,
        >(),
        contract_address_const::<
            0x00001fb19EaFd5A682386AEFc2D9d927da9615743c00461224567eC9E63F1CAF,
        >(),
        contract_address_const::<
            0x00007fb19EaFd5A682386AEFc2D9d827da9615743c00461224577eC9E6071CBF,
        >(),
        contract_address_const::<
            0x00008fb19EaFd5A682386AEFc2D9d727da9615743c00461224587eC9E6171CCF,
        >(),
        contract_address_const::<
            0x00009fb19EaFd5A682386AEFc2D9d627da9615743c00461224597eC9E6271CDF,
        >(),
        contract_address_const::<
            0x00011fb19EaFd5A682386AEFc2D9d527da9615743c004612245A7eC9E6471CEF,
        >(),
        contract_address_const::<
            0x00017fb19EaFd5A682386AEFc2D9d427da9615743c004612245C7eC9E657101F,
        >(),
        contract_address_const::<
            0x00017fb19EaFd5A682386AEFc1D9d327da9615743c004612245C7eC9E657101F,
        >(),
        contract_address_const::<
            0x00309fb19EaFd5A682386AEFc2D9d227da9615743c004612205E7eC9E677121F,
        >(),
        contract_address_const::<
            0x00409fb19EaFd5A582386AEFc2D9d127da9615743c004612215B7eC9E687131F,
        >(),
        contract_address_const::<
            0x00011fb19EaFd5A482386AEFc2D9d527da9615743c004612245A7eC9E6471CEF,
        >(),
        contract_address_const::<
            0x00017fb19EaFd5A382386AEFc2D9d427da9615743c004612245C7eC9E657101F,
        >(),
        contract_address_const::<
            0x00017fb19EaFd5A282386AEFc1D9d327da9615743c004612245C7eC9E657101F,
        >(),
        contract_address_const::<
            0x00309fb19EaFd5A182386AEFc2D9d227da9615743c004612205E7eC9E677121F,
        >(),
        contract_address_const::<
            0x00409fb19EaFd5A082386AEFc2D9d127da9615743c004612215B7eC9E687131F,
        >(),
    ];

    // Create and fund attacker addresses
    let mut i: u32 = 0;
    loop {
        if i >= num_attackers {
            break;
        }

        // Get attacker address from the list and convert to ContractAddress
        let attacker_address: ContractAddress = *attacker_addresses[i];

        // Update configuration for this attacker
        cfg.test_info.staker_address = attacker_address;
        cfg.test_info.stake_amount = min_stake_amount;
        cfg.test_info.staker_initial_balance = min_stake_amount;
        cfg.staker_info.operational_address = attacker_address;
        cfg.staker_info.reward_address = attacker_address;

        // Fund attacker with minimum stake from owner address
        fund(
            sender: cfg.test_info.owner_address,
            recipient: attacker_address,
            amount: min_stake_amount,
            token_address: token_address,
        );
        approve(
            owner: attacker_address,
            spender: staking_contract,
            amount: min_stake_amount,
            token_address: token_address,
        );

        // Stake minimum amount using the helper function
        stake_for_testing_using_dispatcher(:cfg, :token_address, :staking_contract);

        total_stake += min_stake_amount;
        i += 1;
    }

    // Verify storage growth
    let final_storage = staking_dispatcher.get_total_stake();
    assert!(final_storage > initial_storage, "Storage should increase");
    assert!(final_storage == total_stake, "Total stake mismatch");

    // Print results
    let mut formatter: Formatter = Default::default();
    writeln!(formatter, "[SUCCESS] State bloat attack completed").expect('write failed');
    writeln!(formatter, "Initial storage: {}", initial_storage).expect('write failed');
    writeln!(formatter, "Final storage: {}", final_storage).expect('write failed');
    writeln!(formatter, "Number of attackers: {}", num_attackers).expect('write failed');
    writeln!(formatter, "Minimal stake amount: {}", min_stake_amount).expect('write failed');
    println!("{}", formatter.buffer);
}
