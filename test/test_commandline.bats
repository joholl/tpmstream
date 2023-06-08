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
  assert_output --regexp "option(al argument)?s:"
}

@test "Doc example: convert CreatePrimary via pipe." {
  export create_primary_bin
  run bash -c 'printf "80020000007700000131400000010000003d0200000000145536c0a5ba338e58abfe729f76ccca61ebaf821f01002082fc712f21e4c7e47bbf84dfa0fb15ddfc7013eb61ed3eb2edaf0286e88ba20c000400000000001a0023000b0004007200000010001a000b00000003001000000000000000000000"  | xxd -r -p | tpmstream convert -'
  assert_success
  assert_output --regexp "^Command"
  assert_output --regexp ".pcrSelections\s*$"
}

@test "Convert TPM2B_IV." {
  run tpmstream convert --type TPM2B_IV --in=binary - < <(printf "\x00\x03ABC")
  assert_success
  assert_output --regexp "^TPM2B_IV"
  assert_output --regexp ".buffer\s*414243\s*ABC$"
}

@test "Fuzzy match on convert --type." {
  run tpmstream convert --type=i32 - < <(printf "ABC")
  assert_failure
  assert_output --regexp "Did you mean:"
  assert_output --regexp "tpmstream convert --type=INT32 -"
}

@test "Convert command with encrypted param." {
  run tpmstream convert - < <(printf "8002000000890000015380000000000000490200000100206b033b09f16c7fbb8009ad18daacf02eef695adc158e27ba41d1082d33125a2e61002012a2e744fc5da70cc09972a7e5798aebd3631c844d184f3b7983f85044d07b4a000af264d4145f2859e59f29001a0001000b00030072000000060080004300100800000000000000000000000000" | xxd -r -p)
  assert_success
  assert_output --regexp "TPM2B_ENCRYPTED_PARAM.*\.inSensitive"
  assert_output --regexp "list\[TPMS_PCR_SELECTION\].*\.pcrSelections"
}

@test "Convert --type=Response --command=CreatePrimary." {
  run tpmstream co --type=Response --in=binary --command=CreatePrimary - < <( printf "8002000001f80000000080000000000001e101180001000b00040072000000100016000b0800000000000100a443d946ffc24def9bf7507975758499895721b24a7cac5d8a7bf6166a5eab22676c4ba4c946810c894f7571079f4ddd5ba446976ec7e6513438800a53647ecc8c83c8a52016f4212c25818d0d430dfdb345ca357253c57df516274e388170816982b331b00a20af5683082e075e5d64652ff61c6b6307461e7327772fd07935bcff00d1f78bc78ff31b6be71657f4b0253f4f517c532565f077e9a764ec18934b578e75032a6b8926def48a0f597910a03100edbb4e902efa4a842d8ebe21bfc457c6c1a51942a66f8077805b42b4454b179535eeda2704572de75acf8fc0fd48d6988ddf8b87175b254242bd6e4fadf3b89bd0f463412c1aeaf59151a088470037000000000020e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855010010000440000001000440000001000000205da041bac0ee3135aebb0cadfba497c6a1877fae832dd3d1f8f7a871b825e854802140000001004058bc151a36b419a7f51cc595d3bc5676f32a01608f1bca1feadf245d202c81f9ca228176e0cebeccb7c6400eb9c332f396bfce3d773c6876f889251c510fc3f40022000b8e1d6e2d998644c4c6f0cc68f2b325d879f5791d698581d6338e6a05134fd3730000010000" | xxd -p -r)
  assert_success
  assert_output --regexp "TPMA_SESSION.*sessionAttributes.*01"
}

@test "Convert --type=Response, missing --command." {
  run tpmstream co --type=Response --in=binary - < <( printf "ABC")
  assert_failure
  assert_output --regexp "Error: --type=Response requires --command=<command>."
}

@test "Example TPM2B_PUBLIC." {
  run tpmstream ex TPM2B_PUBLIC
  assert_success
  assert_output --regexp "TPM2B_PUBLIC:"
}
