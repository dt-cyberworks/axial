---
title: A published release installs and works from its own instructions - verification
status: ready
risk: R3
owner: platform-engineering
---

# Install Reliability Verification

Verifies [`../requirements/install-reliability.md`](../requirements/install-reliability.md);
design in [`../design/install-reliability-architecture.md`](../design/install-reliability-architecture.md).
R3: the negative tests are the primary evidence. Most run without infrastructure; the
rendered-compose checks skip when Docker is unavailable, and the full path is proven
by `scripts/install_smoke.sh` on a clean virtual machine and by the release workflow.

## TC-INSTALL-001: The documented install is executed end to end

Requirements:

- REQ-INSTALL-001

Automated tests:

- `scripts/tests/test_install_docs.py`
- `scripts/install_smoke.sh`

Objective:

Confirm the guide and the tree agree on every command, and that the smoke script
follows the guide on a copy of the tree, cannot touch a stack it did not create,
and carries its own negative checks.

Expected results:

- `test_negative_every_make_target_the_guides_mention_exists_in_the_public_makefile`,
  `test_negative_every_script_and_path_a_make_recipe_runs_exists`,
  `test_every_relative_link_and_code_path_in_the_install_guide_exists`.
- `test_the_documented_production_start_command_matches_the_smoke_test`,
  `test_the_smoke_scripts_are_valid_and_executable`,
  `test_the_smoke_script_cannot_touch_a_stack_it_did_not_create`,
  `test_the_smoke_script_contains_its_negative_checks`.
- Run on a clean VM (`scripts/install_smoke.sh all`): every step passes; the result
  is recorded in the release evidence.

## TC-INSTALL-002: The object store is obtainable, pinned, authenticated and isolated

Requirements:

- REQ-INSTALL-002

Automated tests:

- `scripts/tests/test_production_exposure.py`
- `scripts/tests/test_multi_env_exposure.py`
- `scripts/tests/test_container_hardening.py`
- `scripts/tests/test_image_pinning.py`
- `control-plane/tests/test_production_config.py`
- `scripts/smoke_object_store.py`

Objective:

Confirm in the rendered compose configuration (development, production, both named
environments) that the store is pinned, publishes nothing, sits only on the
`objstore` network with the control-plane, is hardened, and that production refuses a
public S3 credential; and, against the running stack, that S3 needs credentials and
the unauthenticated interfaces are unreachable.

Expected results:

- `test_object_store_is_isolated_pinned_and_hardened_in_production`,
  `test_control_plane_binds_loopback_and_the_object_store_publishes_nothing`,
  `test_dev_config_keeps_the_local_defaults_and_still_hides_the_object_store`.
- `test_negative_config_fails_closed_when_a_required_prod_var_is_missing[S3_ACCESS_KEY|S3_SECRET_KEY]`.
- `test_negative_each_preexisting_dev_default_fails_closed` for `minioadmin`, `asm-dev-access`,
  `asm-dev-secret-change-me` and empty.
- `test_negative_python_services_drop_every_capability_and_are_read_only` (including `seaweedfs`).
- `scripts/smoke_object_store.py`: anonymous and wrong-secret requests are 403; create, write,
  read, list and delete succeed; filer, master, volume, Iceberg and Lance ports are unreachable;
  the worker cannot resolve the store.

## TC-INSTALL-003: Secrets are generated, never shipped, and complete

Requirements:

- REQ-INSTALL-003

Automated tests:

- `scripts/tests/test_init_dev_env.py`
- `control-plane/tests/test_install_reliability.py`

Objective:

Confirm `make env` fills only empty keys, never changes a set value or a production
file, and that the production generator's output satisfies the real production gate
with every gate-required setting removable only by failing it.

Expected results:

- `test_negative_a_second_run_changes_nothing`, `test_negative_a_value_that_is_already_set_is_never_changed`,
  `test_negative_a_production_env_file_is_never_modified`, `test_the_two_keys_are_different_so_one_leak_does_not_expose_the_other`,
  `test_the_real_env_example_ships_no_key`, `test_an_env_file_from_v0_3_0_with_the_empty_keys_is_repaired`.
- `test_the_generated_production_env_passes_the_real_production_gate`,
  `test_negative_removing_any_gate_required_setting_makes_the_gate_refuse`,
  `test_every_variable_the_production_compose_files_require_is_generated`,
  `test_cli_writes_a_private_file_and_refuses_to_overwrite_without_force`.

## TC-INSTALL-004: A missing encryption key fails clearly, not with a server error

Requirements:

- REQ-INSTALL-004

Automated tests:

- `control-plane/tests/test_install_reliability.py`
- `control-plane/tests/integration/test_mfa_key_unavailable_http.py`

Objective:

Confirm an empty or malformed MFA key yields `503` naming the setting and the fix,
stores nothing, never echoes the key, and recovers once a key is set.

Expected results:

- `test_negative_an_empty_mfa_key_raises_the_dedicated_error_not_a_value_error`,
  `test_negative_a_malformed_mfa_key_raises_the_dedicated_error_without_echoing_it`,
  `test_negative_the_app_turns_the_error_into_a_503_that_names_the_fix_and_leaks_nothing`.
- `test_negative_enrollment_answers_503_not_500_without_a_key_stores_nothing_and_recovers`,
  `test_negative_a_malformed_key_is_a_503_that_does_not_echo_it` (against Postgres).

## TC-INSTALL-005: The first administrator can always log in

Requirements:

- REQ-INSTALL-005

Automated tests:

- `control-plane/tests/test_install_reliability.py`

Objective:

Confirm `bootstrap_admin` refuses, before touching the database, any address the
sign-in form would reject, and that the two validators cannot disagree.

Expected results:

- `test_negative_addresses_the_sign_in_form_rejects_are_refused_with_a_reason`,
  `test_negative_an_unusable_address_exits_1_and_creates_nothing`.
- `test_bootstrap_and_sign_in_agree_on_every_address`, `test_valid_addresses_are_accepted`.

## TC-INSTALL-006: The public tree contains no instruction that cannot work

Requirements:

- REQ-INSTALL-006

Automated tests:

- `scripts/tests/test_install_docs.py`

Objective:

Confirm the public Makefile refers to no private harness, the private targets are
excluded from the export, and `make scope-check` uses only existing files and starts
nothing.

Expected results:

- `test_negative_the_public_makefile_refers_to_no_private_harness`,
  `test_makefile_private_is_excluded_from_the_public_export`,
  `test_makefile_private_exists_only_where_its_harnesses_do`,
  `test_scope_check_runs_only_files_that_exist`.

## TC-INSTALL-007: The guide is complete for a reader who starts from nothing

Requirements:

- REQ-INSTALL-007

Automated tests:

- `scripts/tests/test_install_docs.py`

Objective:

Confirm the prerequisites, clone URL, first-administrator step, manual link,
production generator, bare-IP warning and upgrade notes are present, and that the
removed settings and image are not named outside the upgrade notes.

Expected results:

- `test_the_guide_lists_every_prerequisite_its_commands_need`, `test_the_guide_clones_a_real_url_not_a_placeholder`,
  `test_negative_the_guides_no_longer_copy_the_env_example_by_hand`,
  `test_the_local_section_ends_with_the_first_administrator_and_the_manual`,
  `test_production_uses_the_generator_and_documents_the_ip_address_pitfall`,
  `test_the_guide_documents_the_v0_3_0_upgrade`, `test_negative_the_guides_name_no_removed_or_private_thing`.

## TC-INSTALL-008: Every release is install-tested before it can be merged

Requirements:

- REQ-INSTALL-008

Automated tests:

- `scripts/tests/test_install_docs.py`

Objective:

Confirm the workflow ships, runs both smoke stages on a fresh runner for release pull
requests, `v*` tags and manual dispatch, and holds no write permission.

Expected results:

- `test_the_release_workflow_exists_and_runs_the_smoke_on_every_release_path`,
  `test_the_workflow_is_part_of_the_public_export`.
- The first release pull request that carries the workflow shows the job green.
