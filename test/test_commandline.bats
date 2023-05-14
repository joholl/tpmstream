#!/usr/bin/env bats

load 'test_helper/bats-support/load'
load 'test_helper/bats-assert/load'

create_primary_bin="$(printf '80020000007700000131400000010000003d0200000000145536c0a5ba338e58abfe729f76ccca61ebaf821f01002082fc712f21e4c7e47bbf84dfa0fb15ddfc7013eb61ed3eb2edaf0286e88ba20c000400000000001a0023000b0004007200000010001a000b00000003001000000000000000000000'  | xxd -r -p)"


@test "Run without args." {
  run tpmstream
  assert_failure
  assert_output --partial "usage:"
  assert_output --partial "error: the following arguments are required:"
}

@test "Print help." {
  run tpmstream --help
  assert_success
  assert_output --partial "usage:"
  assert_output --partial "positional arguments:"
  assert_output --partial "optional arguments:"
}

@test "Doc example: convert CreatePrimary via pipe." {
  export create_primary_bin
  run bash -c 'printf "80020000007700000131400000010000003d0200000000145536c0a5ba338e58abfe729f76ccca61ebaf821f01002082fc712f21e4c7e47bbf84dfa0fb15ddfc7013eb61ed3eb2edaf0286e88ba20c000400000000001a0023000b0004007200000010001a000b00000003001000000000000000000000"  | xxd -r -p | tpmstream convert -'
  assert_success
  assert_output --regexp "^Command"
  assert_output --regexp ".pcrSelections\s*$"
}

@test "Examples for CreatePrimary." {
  run tpmstream example CreatePrimary
  assert_success
  assert_output --regexp "^Command"
  assert_output --regexp ".pcrSelections\s*$"
}

#@test "Examples for CreatePrimary." {
#  run printf "0002AABB" | xxd -r -p | tpmstream convert --type TPM2B_IV --in=binary -
#  assert_success
#  assert_output --regexp "^Command"
#  assert_output --regexp ".pcrSelections\s*$"
#}
