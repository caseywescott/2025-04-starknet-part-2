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
fn test_attestation_window_exploitation() {
    // Summary:
    // The attestation window is a critical parameter that determines when validators can submit
    // attestations.
    // This test demonstrates a vulnerability where the app governor can maliciously shrink the
    // attestation window to prevent validators from attesting, potentially disrupting network
    // operations.
    //
    // Impact:
    // - High Severity: The app governor can manipulate the attestation window to:
    //   * Prevent validators from attesting within their designated time slots
    //   * Disrupt network consensus by forcing validators to miss attestations
    //   * Potentially cause validators to lose rewards or face penalties
    //   * Create network instability by reducing the time window for attestations
    //
    // Testing Approach:
    // 1. Set up a normal attestation window (100 blocks)
    // 2. Calculate the validator's expected attestation block
    // 3. Advance to just before the attestation window
    // 4. Have the app governor maliciously shrink the window to minimum size
    // 5. Attempt to attest (should fail)
    // 6. Verify the attestation failed as expected
    //
    // Recommendations:
    // 1. Implement minimum and maximum bounds for attestation window changes
    // 2. Add a cooldown period between window changes
    // 3. Require multi-signature approval for window changes
    // 4. Implement a voting mechanism for significant parameter changes
    // 5. Add logging and monitoring for window changes
    // 6. Consider making the window size immutable after initial setup
    //
    // command to run: snforge test test_attestation_window_exploitation

    // Initialize test environment
    let mut cfg: StakingInitConfig = Default::default();
    general_contract_system_deployment(ref :cfg);
    let staking_contract = cfg.test_info.staking_contract;
    let token_address = cfg.staking_contract_info.token_address;

    // Stake tokens to become a validator
    stake_for_testing_using_dispatcher(:cfg, :token_address, :staking_contract);
    let attestation_contract = cfg.test_info.attestation_contract;
    let attestation_dispatcher = IAttestationDispatcher { contract_address: attestation_contract };
    let attestation_safe_dispatcher = IAttestationSafeDispatcher {
        contract_address: attestation_contract,
    };
    let operational_address = cfg.staker_info.operational_address;
    let staker_address = cfg.test_info.staker_address;

    // Set initial attestation window to 100 blocks and verify
    cheat_caller_address_once(
        contract_address: attestation_contract, caller_address: cfg.test_info.app_governor,
    );
    attestation_dispatcher.set_attestation_window(attestation_window: 100);
    let initial_window = attestation_dispatcher.attestation_window();
    assert!(initial_window == 100, "Initial window should be 100 blocks");

    // Advance to next epoch to ensure validator has stake
    advance_epoch_global();

    // Calculate validator's target attestation block under normal window
    let normal_window = attestation_dispatcher.attestation_window();
    let block_offset = calculate_block_offset(
        stake: cfg.test_info.stake_amount.into(),
        epoch_id: cfg.staking_contract_info.epoch_info.current_epoch().into(),
        staker_address: staker_address.into(),
        epoch_len: cfg.staking_contract_info.epoch_info.epoch_len_in_blocks().into(),
        attestation_window: normal_window,
    );

    // Get current epoch info
    let staking_dispatcher = IStakingDispatcher { contract_address: staking_contract };
    let epoch_info = staking_dispatcher.get_epoch_info();
    let current_epoch_start = epoch_info.current_epoch_starting_block();

    // Calculate expected attestation block
    let expected_attestation_block = current_epoch_start
        + block_offset
        + MIN_ATTESTATION_WINDOW.into();

    // Advance to just before the attestation window
    let current_block = get_block_number();
    let blocks_to_advance = if current_block < expected_attestation_block {
        expected_attestation_block - current_block - 1
    } else {
        0
    };
    advance_block_number_global(blocks: blocks_to_advance);
    let current_block = get_block_number();

    // Print initial timing details
    let mut formatter: Formatter = Default::default();
    writeln!(formatter, "Initial timing:").expect('write failed');
    writeln!(formatter, "Current block: {}", current_block).expect('write failed');
    writeln!(formatter, "Expected attestation block: {}", expected_attestation_block)
        .expect('write failed');
    writeln!(formatter, "Original window size: {} blocks", initial_window).expect('write failed');
    println!("{}", formatter.buffer);

    // App governor maliciously shrinks the window to minimum size
    cheat_caller_address_once(
        contract_address: attestation_contract, caller_address: cfg.test_info.app_governor,
    );
    attestation_dispatcher.set_attestation_window(attestation_window: MIN_ATTESTATION_WINDOW);
    let new_window = attestation_dispatcher.attestation_window();
    assert!(new_window == MIN_ATTESTATION_WINDOW, "Window should be shrunk to minimum");

    // Print window change details
    let mut formatter: Formatter = Default::default();
    writeln!(formatter, "After window change:").expect('write failed');
    writeln!(formatter, "New window size: {} blocks", new_window).expect('write failed');
    println!("{}", formatter.buffer);

    // Try to attest - should fail because window was shrunk
    cheat_caller_address_once(
        contract_address: attestation_contract, caller_address: operational_address,
    );
    let result = attestation_safe_dispatcher.attest(block_hash: Zero::zero());

    // Assert the specific error for attestation being out of window
    assert_panic_with_error(:result, expected_error: Error::ATTEST_OUT_OF_WINDOW.describe());
    println!("Attestation Status: FAILED (as expected)");

    // Verify attestation failed
    let is_attestation_done = attestation_dispatcher
        .is_attestation_done_in_curr_epoch(:staker_address);
    assert!(is_attestation_done == false, "Attestation should have failed");
}
