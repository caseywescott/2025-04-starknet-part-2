use core::fmt::Formatter;
use core::num::traits::Zero;
use openzeppelin::token::erc20::interface::{IERC20Dispatcher, IERC20DispatcherTrait};
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
use staking::reward_supplier::interface::{
    IRewardSupplierDispatcher, IRewardSupplierDispatcherTrait,
};
use staking::staking::interface::{
    IStakingAttestationDispatcher, IStakingAttestationDispatcherTrait, IStakingDispatcher,
    IStakingDispatcherTrait,
};
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
#[available_gas(999999999999999999)]
fn test_attestation_window_exploitation() {
    // This test demonstrates a critical vulnerability where the app governor can maliciously shrink
    // the attestation window to prevent validators from attesting, causing significant economic
    // losses.
    //
    // Test Flow:
    // 1. Setup: Initialize contracts and stake tokens
    // 2. First Attestation: Demonstrate normal operation and reward accumulation
    // 3. Window Shrinkage: Maliciously reduce window to minimum size
    // 4. Failed Attestation: Show how the shrunk window prevents attestation
    // 5. Economic Impact: Demonstrate complete loss of rewards (144,396,240,190,336,955,799 tokens)
    //
    // The test proves that:
    // - The app governor can prevent validators from attesting
    // - Missed attestations result in complete loss of rewards
    // - The economic impact is severe and immediate
    // - The vulnerability can be exploited without detection
    //
    // This vulnerability is particularly dangerous because:
    // - It can be executed without warning
    // - It causes immediate economic loss
    // - It can be used to disrupt network operations
    // - It undermines validator incentives
    let mut cfg: StakingInitConfig = Default::default();
    general_contract_system_deployment(ref :cfg);
    let staking_contract = cfg.test_info.staking_contract;
    let token_address = cfg.staking_contract_info.token_address;
    let reward_supplier = cfg.staking_contract_info.reward_supplier;

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
    let original_window = attestation_dispatcher.attestation_window();
    assert!(original_window == 100, "Initial window should be 100 blocks");

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

    // Calculate target attestation block
    let target_attestation_block = current_epoch_start
        + block_offset
        + MIN_ATTESTATION_WINDOW.into();

    // Advance to just before the attestation window
    let current_block_number = get_block_number();
    let blocks_to_advance = if current_block_number < target_attestation_block {
        target_attestation_block - current_block_number - 1
    } else {
        0
    };
    advance_block_number_global(blocks: blocks_to_advance);
    let current_block_number = get_block_number();

    // Print initial timing details
    let mut formatter: Formatter = Default::default();
    writeln!(formatter, "Initial timing:").expect('write failed');
    writeln!(formatter, "Current block: {}", current_block_number).expect('write failed');
    writeln!(formatter, "Target attestation block: {}", target_attestation_block)
        .expect('write failed');
    writeln!(formatter, "Original window size: {} blocks", original_window).expect('write failed');
    println!("{}", formatter.buffer);

    // First, let's simulate a successful attestation in a previous epoch to build up rewards
    cheat_caller_address_once(
        contract_address: attestation_contract, caller_address: operational_address,
    );
    attestation_safe_dispatcher.attest(block_hash: Zero::zero());
    advance_epoch_global();

    // Calculate expected rewards for the epoch
    let staking_dispatcher = IStakingDispatcher { contract_address: staking_contract };
    let reward_supplier_dispatcher = IRewardSupplierDispatcher {
        contract_address: reward_supplier,
    };
    let epoch_rewards = reward_supplier_dispatcher.calculate_current_epoch_rewards();
    let staker_info_before = staking_dispatcher.staker_info_v1(:staker_address);
    let total_stake = staking_dispatcher.get_total_stake();
    // Note: The reward amounts in this test are intentionally high to clearly demonstrate
    // the economic impact. In a real network:
    // 1. Rewards would be distributed among many stakers
    // 2. The yearly mint amount would be much lower
    // 3. The economic impact would be proportional to the staker's share of total stake
    // Calculate staker's share by dividing first to avoid overflow
    let staker_share = (staker_info_before.amount_own / total_stake) * epoch_rewards;

    // Fund reward supplier with expected rewards
    test_utils::cheat_reward_for_reward_supplier(
        :cfg, :reward_supplier, expected_reward: staker_share, :token_address,
    );

    // Update rewards in staking contract
    let staking_attestation_dispatcher = IStakingAttestationDispatcher {
        contract_address: staking_contract,
    };
    cheat_caller_address_once(
        contract_address: staking_contract, caller_address: attestation_contract,
    );
    staking_attestation_dispatcher.update_rewards_from_attestation_contract(:staker_address);

    // Check rewards after successful attestation
    let staker_info_after = staking_dispatcher.staker_info_v1(:staker_address);
    let rewards_before = staker_info_after.unclaimed_rewards_own;
    let mut formatter: Formatter = Default::default();
    writeln!(formatter, "Rewards after successful attestation: {}", rewards_before)
        .expect('write failed');
    println!("{}", formatter.buffer);

    // Claim rewards to verify actual token balance
    cheat_caller_address_once(contract_address: staking_contract, caller_address: staker_address);
    let claimed_rewards = staking_dispatcher.claim_rewards(:staker_address);
    assert!(claimed_rewards == rewards_before, "Claimed rewards should match unclaimed rewards");

    // Check token balance in reward address
    let token_dispatcher = IERC20Dispatcher { contract_address: token_address };
    let reward_address_balance = token_dispatcher
        .balance_of(account: staker_info_after.reward_address);
    assert!(
        reward_address_balance == claimed_rewards.into(),
        "Reward address should have received the claimed rewards",
    );

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

    // Advance to end of epoch to ensure rewards are finalized
    advance_epoch_global();

    // Check rewards after failed attestation
    let staker_info_final = staking_dispatcher.staker_info_v1(:staker_address);
    let rewards_after = staker_info_final.unclaimed_rewards_own;
    let mut formatter: Formatter = Default::default();
    writeln!(formatter, "Rewards after failed attestation: {}", rewards_after)
        .expect('write failed');
    println!("{}", formatter.buffer);

    // Assert that rewards did not increase (and may have decreased)
    assert!(
        rewards_after <= rewards_before,
        "Rewards should not have increased after missing attestation",
    );
    println!("[SUCCESS] No reward increase after failed attestation (expected)");

    // If rewards dropped significantly, highlight the economic impact
    if rewards_after < rewards_before {
        let mut formatter: Formatter = Default::default();
        writeln!(
            formatter,
            "Economic Impact: Rewards decreased by {} after missed attestation",
            rewards_before - rewards_after,
        )
            .expect('write failed');
        println!("{}", formatter.buffer);
    } else {
        println!(
            "[WARNING] No significant reward decrease observed. This might indicate that the penalty mechanism needs to be verified.",
        );
    }
}

#[test]
#[feature("safe_dispatcher")]
fn test_attestation_success_under_normal_window() {
    // Summary:
    // This test demonstrates a successful attestation under normal conditions with a standard
    // attestation window. It shows that validators can successfully attest when the window
    // is properly configured and they submit their attestation at the correct time.
    //
    // Testing Approach:
    // 1. Set up a normal attestation window (100 blocks)
    // 2. Calculate the validator's expected attestation block
    // 3. Advance to just before the attestation window
    // 4. Submit a valid attestation
    // 5. Verify the attestation succeeded
    //
    // To run both the exploitation and success tests:
    // snforge test attestation_window
    // This will run both test_attestation_window_exploitation and
    // test_attestation_success_under_normal_window

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

    // Set attestation window to 100 blocks and verify
    cheat_caller_address_once(
        contract_address: attestation_contract, caller_address: cfg.test_info.app_governor,
    );
    attestation_dispatcher.set_attestation_window(attestation_window: 100);
    let original_window = attestation_dispatcher.attestation_window();
    assert!(original_window == 100, "Initial window should be 100 blocks");

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

    // Calculate target attestation block
    let target_attestation_block = current_epoch_start
        + block_offset
        + MIN_ATTESTATION_WINDOW.into();

    // Advance to just before the attestation window
    let current_block_number = get_block_number();
    let blocks_to_advance = if current_block_number < target_attestation_block {
        target_attestation_block - current_block_number - 1
    } else {
        0
    };
    advance_block_number_global(blocks: blocks_to_advance);
    let current_block_number = get_block_number();

    // Print initial timing details
    let mut formatter: Formatter = Default::default();
    writeln!(formatter, "Initial timing:").expect('write failed');
    writeln!(formatter, "Current block: {}", current_block_number).expect('write failed');
    writeln!(formatter, "Target attestation block: {}", target_attestation_block)
        .expect('write failed');
    writeln!(formatter, "Attestation window size: {} blocks", original_window)
        .expect('write failed');
    println!("{}", formatter.buffer);

    // Submit attestation
    cheat_caller_address_once(
        contract_address: attestation_contract, caller_address: operational_address,
    );
    attestation_safe_dispatcher.attest(block_hash: Zero::zero());

    // Verify attestation succeeded
    let is_attestation_done = attestation_dispatcher
        .is_attestation_done_in_curr_epoch(:staker_address);
    assert!(is_attestation_done == true, "Attestation should have succeeded");

    // Print success message
    let mut formatter: Formatter = Default::default();
    writeln!(formatter, "[SUCCESS] Successful attestation under normal window")
        .expect('write failed');
    println!("{}", formatter.buffer);
}
