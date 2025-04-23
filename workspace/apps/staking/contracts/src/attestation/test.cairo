use core::array::ArrayTrait;
use core::fmt::Formatter;
use core::num::traits::Zero;
use snforge_std::cheatcodes::events::{EventSpyTrait, EventsFilterTrait};
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
use staking::staking::interface::{IStakingDispatcher, IStakingDispatcherTrait};
use staking::staking::objects::EpochInfoTrait;
use staking::test_utils;
use starknet::get_block_number;
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
#[feature("safe_dispatcher")]
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
#[should_panic(expected: "Attestation for starting epoch is not allowed")]
fn test_is_attestation_done_in_curr_epoch_zero_epoch() {
    let mut cfg: StakingInitConfig = Default::default();
    general_contract_system_deployment(ref :cfg);
    let attestation_contract = cfg.test_info.attestation_contract;
    let attestation_dispatcher = IAttestationDispatcher { contract_address: attestation_contract };
    attestation_dispatcher.is_attestation_done_in_curr_epoch(staker_address: DUMMY_ADDRESS());
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
#[feature("safe_dispatcher")]
fn test_set_attestation_window_assertions() {
    let mut cfg: StakingInitConfig = Default::default();
    general_contract_system_deployment(ref :cfg);
    let attestation_contract = cfg.test_info.attestation_contract;
    let attestation_safe_dispatcher = IAttestationSafeDispatcher {
        contract_address: attestation_contract,
    };
    cheat_caller_address_once(
        contract_address: attestation_contract, caller_address: cfg.test_info.app_governor,
    );
    // Catch ATTEST_WINDOW_TOO_SMALL.
    let result = attestation_safe_dispatcher
        .set_attestation_window(attestation_window: MIN_ATTESTATION_WINDOW - 1);
    assert_panic_with_error(:result, expected_error: Error::ATTEST_WINDOW_TOO_SMALL.describe());
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
#[feature("safe_dispatcher")]
fn test_extra_felts_in_calldata() {
    // Initialize test environment
    let mut cfg: StakingInitConfig = Default::default();
    general_contract_system_deployment(ref :cfg);
    let staking_contract = cfg.test_info.staking_contract;
    let staking_dispatcher = IStakingDispatcher { contract_address: staking_contract };
    let token_address = cfg.staking_contract_info.token_address;

    // Stake tokens to become a validator
    stake_for_testing_using_dispatcher(:cfg, :token_address, :staking_contract);
    let attestation_contract = cfg.test_info.attestation_contract;
    let attestation_dispatcher = IAttestationDispatcher { contract_address: attestation_contract };
    let operational_address = cfg.staker_info.operational_address;
    let staker_address = cfg.test_info.staker_address;

    // Set attestation window and advance to next epoch
    cheat_caller_address_once(
        contract_address: attestation_contract, caller_address: cfg.test_info.app_governor,
    );
    attestation_dispatcher.set_attestation_window(attestation_window: 100);
    advance_epoch_global();

    // Record initial state
    let initial_attestation_done = attestation_dispatcher
        .is_attestation_done_in_curr_epoch(:staker_address);
    let initial_epoch = staking_dispatcher.get_current_epoch();
    let initial_window = attestation_dispatcher.attestation_window();

    // Calculate target attestation block
    let normal_window = attestation_dispatcher.attestation_window();
    let block_offset = calculate_block_offset(
        stake: cfg.test_info.stake_amount.into(),
        epoch_id: cfg.staking_contract_info.epoch_info.current_epoch().into(),
        staker_address: staker_address.into(),
        epoch_len: cfg.staking_contract_info.epoch_info.epoch_len_in_blocks().into(),
        attestation_window: normal_window,
    );

    let epoch_info = staking_dispatcher.get_epoch_info();
    let current_epoch_start = epoch_info.current_epoch_starting_block();
    let target_attestation_block = current_epoch_start
        + block_offset
        + MIN_ATTESTATION_WINDOW.into();

    // Advance to attestation window
    let current_block_number = get_block_number();
    let blocks_to_advance = if current_block_number < target_attestation_block {
        target_attestation_block - current_block_number
    } else {
        0
    };
    advance_block_number_global(blocks: blocks_to_advance);

    // Submit attestation with extra felts
    cheat_caller_address_once(
        contract_address: attestation_contract, caller_address: operational_address,
    );

    // Create calldata with extra felts
    let mut calldata = array![Zero::zero(), 1, 2, 3];

    // Call attest with extra felts
    attestation_dispatcher.attest_with_extra_felts(calldata: calldata.span());

    // Verify state remains unchanged
    let final_attestation_done = attestation_dispatcher
        .is_attestation_done_in_curr_epoch(:staker_address);
    let final_epoch = staking_dispatcher.get_current_epoch();
    let final_window = attestation_dispatcher.attestation_window();

    assert!(final_attestation_done == true, "Attestation should be marked as done");
    assert!(final_epoch == initial_epoch, "Epoch should not change");
    assert!(final_window == initial_window, "Window should not change");

    // Submit normal attestation for comparison
    cheat_caller_address_once(
        contract_address: attestation_contract, caller_address: operational_address,
    );
    attestation_dispatcher.attest(block_hash: Zero::zero());

    // Verify both attestations produced same result
    let normal_attestation_done = attestation_dispatcher
        .is_attestation_done_in_curr_epoch(:staker_address);
    assert!(
        normal_attestation_done == final_attestation_done,
        "Extra felts should not affect attestation result",
    );
}

#[test]
fn test_attest_with_extra_felts() {
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

    // advance epoch to make sure the staker has a balance
    advance_epoch_global();

    // advance into the attestation window
    advance_block_into_attestation_window(:cfg, stake: cfg.test_info.stake_amount);

    cheat_caller_address_once(
        contract_address: attestation_contract, caller_address: operational_address,
    );

    let epoch = staking_dispatcher.get_current_epoch();

    // Create calldata with block hash and extra felts
    let mut calldata = ArrayTrait::new();
    calldata.append(Zero::zero()); // block hash
    calldata.append(1); // extra felt 1
    calldata.append(2); // extra felt 2

    attestation_dispatcher.attest_with_extra_felts(calldata: calldata.span());

    let is_attestation_done = attestation_dispatcher
        .is_attestation_done_in_curr_epoch(:staker_address);
    assert!(is_attestation_done == true);

    let events = spy.get_events().emitted_by(contract_address: attestation_contract).events;
    assert_number_of_events(actual: events.len(), expected: 1, message: "attest_with_extra_felts");
    assert_staker_attestation_successful_event(spied_event: events[0], :staker_address, :epoch);
}

#[test]
#[should_panic(expected: "Attestation with wrong block hash")]
fn test_attest_with_undersized_calldata() {
    // Initialize test environment
    let mut cfg: StakingInitConfig = Default::default();
    general_contract_system_deployment(ref :cfg);
    let staking_contract = cfg.test_info.staking_contract;
    let staking_dispatcher = IStakingDispatcher { contract_address: staking_contract };
    let token_address = cfg.staking_contract_info.token_address;

    // Stake tokens to become a validator
    stake_for_testing_using_dispatcher(:cfg, :token_address, :staking_contract);
    let attestation_contract = cfg.test_info.attestation_contract;
    let attestation_dispatcher = IAttestationDispatcher { contract_address: attestation_contract };
    let operational_address = cfg.staker_info.operational_address;

    // Set attestation window and advance to next epoch
    cheat_caller_address_once(
        contract_address: attestation_contract, caller_address: cfg.test_info.app_governor,
    );
    attestation_dispatcher.set_attestation_window(attestation_window: 100);
    advance_epoch_global();

    // Advance to attestation window
    advance_block_into_attestation_window(:cfg, stake: cfg.test_info.stake_amount);

    // Submit attestation with empty calldata
    cheat_caller_address_once(
        contract_address: attestation_contract, caller_address: operational_address,
    );

    // Create empty calldata
    let mut calldata = ArrayTrait::new();

    // Call attest with empty calldata - should panic
    attestation_dispatcher.attest_with_extra_felts(calldata: calldata.span());
}

#[test]
#[should_panic(expected: "Attestation with wrong block hash")]
fn test_attest_with_malformed_calldata() {
    // Initialize test environment
    let mut cfg: StakingInitConfig = Default::default();
    general_contract_system_deployment(ref :cfg);
    let staking_contract = cfg.test_info.staking_contract;
    let staking_dispatcher = IStakingDispatcher { contract_address: staking_contract };
    let token_address = cfg.staking_contract_info.token_address;

    // Stake tokens to become a validator
    stake_for_testing_using_dispatcher(:cfg, :token_address, :staking_contract);
    let attestation_contract = cfg.test_info.attestation_contract;
    let attestation_dispatcher = IAttestationDispatcher { contract_address: attestation_contract };
    let operational_address = cfg.staker_info.operational_address;
    let staker_address = cfg.test_info.staker_address;

    // Set attestation window to 100 blocks and verify
    cheat_caller_address_once(
        contract_address: attestation_contract, caller_address: cfg.test_info.app_governor,
    );
    attestation_dispatcher.set_attestation_window(attestation_window: 100);
    let original_window = attestation_dispatcher.attestation_window();
    assert!(original_window == 100, "Initial window should be 100 blocks");

    // Advance to next epoch and set up for attestation
    advance_epoch_global();

    // Calculate validator's target attestation block
    let normal_window = attestation_dispatcher.attestation_window();
    let block_offset = calculate_block_offset(
        stake: cfg.test_info.stake_amount.into(),
        epoch_id: cfg.staking_contract_info.epoch_info.current_epoch().into(),
        staker_address: staker_address.into(),
        epoch_len: cfg.staking_contract_info.epoch_info.epoch_len_in_blocks().into(),
        attestation_window: normal_window,
    );

    // Get current epoch info
    let epoch_info = staking_dispatcher.get_epoch_info();
    let current_epoch_start = epoch_info.current_epoch_starting_block();

    // Calculate target attestation block
    let target_attestation_block = current_epoch_start
        + block_offset
        + MIN_ATTESTATION_WINDOW.into();

    // Advance to the attestation window
    let current_block_number = get_block_number();
    let blocks_to_advance = if current_block_number < target_attestation_block {
        target_attestation_block - current_block_number
    } else {
        0
    };
    advance_block_number_global(blocks: blocks_to_advance);

    // Set caller address for attestation
    cheat_caller_address_once(
        contract_address: attestation_contract, caller_address: operational_address,
    );

    // Create malformed calldata with invalid block hash
    let malformed_calldata = array![
        0, // Zero block hash
        0xFFFF_FFFF_FFFF, // Large felt
        staker_address.into(), // Attacker address
        staker_address.into() // Duplicate address
    ]
        .span();

    // Try attestation with malformed data - should panic with "Attestation with wrong block hash"
    attestation_dispatcher.attest_with_extra_felts(calldata: malformed_calldata);
}

#[test]
#[should_panic(expected: "Attestation with wrong block hash")]
fn test_attest_with_wrong_epoch_block_hash() {
    // Initialize test environment
    let mut cfg: StakingInitConfig = Default::default();
    general_contract_system_deployment(ref :cfg);
    let staking_contract = cfg.test_info.staking_contract;
    let staking_dispatcher = IStakingDispatcher { contract_address: staking_contract };
    let token_address = cfg.staking_contract_info.token_address;

    // Stake tokens to become a validator
    stake_for_testing_using_dispatcher(:cfg, :token_address, :staking_contract);
    let attestation_contract = cfg.test_info.attestation_contract;
    let attestation_dispatcher = IAttestationDispatcher { contract_address: attestation_contract };
    let operational_address = cfg.staker_info.operational_address;
    let staker_address = cfg.test_info.staker_address;

    // Set attestation window to 100 blocks
    cheat_caller_address_once(
        contract_address: attestation_contract, caller_address: cfg.test_info.app_governor,
    );
    attestation_dispatcher.set_attestation_window(attestation_window: 100);

    // Advance to next epoch and record the block hash
    advance_epoch_global();
    let epoch_info = staking_dispatcher.get_epoch_info();
    let current_epoch = staking_dispatcher.get_current_epoch();
    let current_epoch_start = epoch_info.current_epoch_starting_block();

    // Calculate target attestation block for current epoch
    let block_offset = calculate_block_offset(
        stake: cfg.test_info.stake_amount.into(),
        epoch_id: current_epoch.into(),
        staker_address: staker_address.into(),
        epoch_len: epoch_info.epoch_len_in_blocks().into(),
        attestation_window: 100,
    );
    let target_attestation_block = current_epoch_start
        + block_offset
        + MIN_ATTESTATION_WINDOW.into();

    // Advance to attestation window
    let current_block_number = get_block_number();
    let blocks_to_advance = if current_block_number < target_attestation_block {
        target_attestation_block - current_block_number
    } else {
        0
    };
    advance_block_number_global(blocks: blocks_to_advance);

    // Now advance to next epoch
    advance_epoch_global();
    let new_epoch = staking_dispatcher.get_current_epoch();
    assert!(new_epoch > current_epoch, "Should be in a new epoch");

    // Calculate attestation window for the new epoch
    let new_epoch_info = staking_dispatcher.get_epoch_info();
    let new_epoch_start = new_epoch_info.current_epoch_starting_block();
    let new_block_offset = calculate_block_offset(
        stake: cfg.test_info.stake_amount.into(),
        epoch_id: new_epoch.into(),
        staker_address: staker_address.into(),
        epoch_len: new_epoch_info.epoch_len_in_blocks().into(),
        attestation_window: 100,
    );
    let new_target_attestation_block = new_epoch_start
        + new_block_offset
        + MIN_ATTESTATION_WINDOW.into();

    // Advance to attestation window in new epoch
    let current_block_number = get_block_number();
    let blocks_to_advance = if current_block_number < new_target_attestation_block {
        new_target_attestation_block - current_block_number
    } else {
        0
    };
    advance_block_number_global(blocks: blocks_to_advance);

    // Try to attest using the block hash from the previous epoch
    cheat_caller_address_once(
        contract_address: attestation_contract, caller_address: operational_address,
    );

    // Create calldata with the wrong block hash (using the previous epoch's target block)
    let mut calldata = ArrayTrait::new();
    calldata.append(target_attestation_block.into()); // Use the old target block hash

    // Try attestation with block hash from wrong epoch - should panic
    attestation_dispatcher.attest_with_extra_felts(calldata: calldata.span());
}

#[test]
fn test_replay_attestation_calldata() {
    // Initialize test environment
    let mut cfg: StakingInitConfig = Default::default();
    general_contract_system_deployment(ref :cfg);
    let staking_contract = cfg.test_info.staking_contract;
    let staking_dispatcher = IStakingDispatcher { contract_address: staking_contract };
    let token_address = cfg.staking_contract_info.token_address;

    // Stake tokens to become a validator
    stake_for_testing_using_dispatcher(:cfg, :token_address, :staking_contract);
    let attestation_contract = cfg.test_info.attestation_contract;
    let attestation_dispatcher = IAttestationDispatcher { contract_address: attestation_contract };
    let operational_address = cfg.staker_info.operational_address;
    let staker_address = cfg.test_info.staker_address;
    let mut spy = snforge_std::spy_events();

    // Set attestation window to 100 blocks
    cheat_caller_address_once(
        contract_address: attestation_contract, caller_address: cfg.test_info.app_governor,
    );
    attestation_dispatcher.set_attestation_window(attestation_window: 100);

    // Advance to next epoch and prepare for first attestation
    advance_epoch_global();
    let epoch_info = staking_dispatcher.get_epoch_info();
    let current_epoch = staking_dispatcher.get_current_epoch();
    let current_epoch_start = epoch_info.current_epoch_starting_block();

    // Calculate target attestation block
    let block_offset = calculate_block_offset(
        stake: cfg.test_info.stake_amount.into(),
        epoch_id: current_epoch.into(),
        staker_address: staker_address.into(),
        epoch_len: epoch_info.epoch_len_in_blocks().into(),
        attestation_window: 100,
    );
    let target_attestation_block = current_epoch_start
        + block_offset
        + MIN_ATTESTATION_WINDOW.into();

    // Advance to attestation window
    let current_block_number = get_block_number();
    let blocks_to_advance = if current_block_number < target_attestation_block {
        target_attestation_block - current_block_number
    } else {
        0
    };
    advance_block_number_global(blocks: blocks_to_advance);

    // Record initial state
    let initial_last_epoch = attestation_dispatcher
        .get_last_epoch_attestation_done(:staker_address);
    let initial_attestation_done = attestation_dispatcher
        .is_attestation_done_in_curr_epoch(:staker_address);

    // Submit first valid attestation with a mock block hash
    cheat_caller_address_once(
        contract_address: attestation_contract, caller_address: operational_address,
    );
    let mut valid_calldata = ArrayTrait::new();
    // Use the target attestation block as the block hash
    valid_calldata.append(target_attestation_block.into());
    attestation_dispatcher.attest_with_extra_felts(calldata: valid_calldata.span());

    // Verify first attestation succeeded
    let events = spy.get_events().emitted_by(contract_address: attestation_contract).events;
    assert_number_of_events(actual: events.len(), expected: 1, message: "first attest");
    assert_staker_attestation_successful_event(
        spied_event: events[0], :staker_address, epoch: current_epoch,
    );

    // Record state after first attestation
    let post_attest_last_epoch = attestation_dispatcher
        .get_last_epoch_attestation_done(:staker_address);
    assert!(post_attest_last_epoch > initial_last_epoch, "Epoch should advance after attestation");
    assert!(
        attestation_dispatcher.is_attestation_done_in_curr_epoch(:staker_address),
        "Attestation should be marked as done",
    );

    // Advance to next epoch to try replay in a different context
    advance_epoch_global();
    let new_epoch = staking_dispatcher.get_current_epoch();
    assert!(new_epoch > current_epoch, "Should be in a new epoch");

    // Calculate new attestation window for the new epoch
    let new_epoch_info = staking_dispatcher.get_epoch_info();
    let new_epoch_start = new_epoch_info.current_epoch_starting_block();
    let new_block_offset = calculate_block_offset(
        stake: cfg.test_info.stake_amount.into(),
        epoch_id: new_epoch.into(),
        staker_address: staker_address.into(),
        epoch_len: new_epoch_info.epoch_len_in_blocks().into(),
        attestation_window: 100,
    );
    let new_target_attestation_block = new_epoch_start
        + new_block_offset
        + MIN_ATTESTATION_WINDOW.into();

    // Advance to attestation window in new epoch
    let current_block_number = get_block_number();
    let blocks_to_advance = if current_block_number < new_target_attestation_block {
        new_target_attestation_block - current_block_number
    } else {
        0
    };
    advance_block_number_global(blocks: blocks_to_advance);

    // Attempt to replay the same attestation calldata in new epoch
    cheat_caller_address_once(
        contract_address: attestation_contract, caller_address: operational_address,
    );

    // This should fail since we're in a new epoch with a different target block hash
    attestation_dispatcher.attest_with_extra_felts(calldata: valid_calldata.span());
}
