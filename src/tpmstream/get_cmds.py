import glob
import re

from tpmstream.spec.structures.constants import TPM_CC

tpm_handles = {
    TPM_CC.NV_UndefineSpaceSpecial: (2, 0),
    TPM_CC.EvictControl: (2, 0),
    TPM_CC.HierarchyControl: (1, 0),
    TPM_CC.NV_UndefineSpace: (2, 0),
    TPM_CC.ChangeEPS: (1, 0),
    TPM_CC.ChangePPS: (1, 0),
    TPM_CC.Clear: (1, 0),
    TPM_CC.ClearControl: (1, 0),
    TPM_CC.ClockSet: (1, 0),
    TPM_CC.HierarchyChangeAuth: (1, 0),
    TPM_CC.NV_DefineSpace: (1, 0),
    TPM_CC.PCR_Allocate: (1, 0),
    TPM_CC.PCR_SetAuthPolicy: (1, 0),
    TPM_CC.PP_Commands: (1, 0),
    TPM_CC.SetPrimaryPolicy: (1, 0),
    TPM_CC.FieldUpgradeStart: (2, 0),
    TPM_CC.ClockRateAdjust: (1, 0),
    TPM_CC.CreatePrimary: (1, 1),
    TPM_CC.NV_GlobalWriteLock: (1, 0),
    TPM_CC.GetCommandAuditDigest: (2, 0),
    TPM_CC.NV_Increment: (2, 0),
    TPM_CC.NV_SetBits: (2, 0),
    TPM_CC.NV_Extend: (2, 0),
    TPM_CC.NV_Write: (2, 0),
    TPM_CC.NV_WriteLock: (2, 0),
    TPM_CC.DictionaryAttackLockReset: (1, 0),
    TPM_CC.DictionaryAttackParameters: (1, 0),
    TPM_CC.NV_ChangeAuth: (1, 0),
    TPM_CC.PCR_Event: (1, 0),
    TPM_CC.PCR_Reset: (1, 0),
    TPM_CC.SequenceComplete: (1, 0),
    TPM_CC.SetAlgorithmSet: (1, 0),
    TPM_CC.SetCommandCodeAuditStatus: (1, 0),
    TPM_CC.FieldUpgradeData: (0, 0),
    TPM_CC.IncrementalSelfTest: (0, 0),
    TPM_CC.SelfTest: (0, 0),
    TPM_CC.Startup: (0, 0),
    TPM_CC.Shutdown: (0, 0),
    TPM_CC.StirRandom: (0, 0),
    TPM_CC.ActivateCredential: (2, 0),
    TPM_CC.Certify: (2, 0),
    TPM_CC.PolicyNV: (3, 0),
    TPM_CC.CertifyCreation: (2, 0),
    TPM_CC.Duplicate: (2, 0),
    TPM_CC.GetTime: (2, 0),
    TPM_CC.GetSessionAuditDigest: (3, 0),
    TPM_CC.NV_Read: (1, 0),
    TPM_CC.NV_ReadLock: (2, 0),
    TPM_CC.ObjectChangeAuth: (2, 0),
    TPM_CC.PolicySecret: (2, 0),
    TPM_CC.Rewrap: (2, 0),
    TPM_CC.Create: (1, 0),
    TPM_CC.ECDH_ZGen: (1, 0),
    TPM_CC.HMAC: (1, 0),
    TPM_CC.Import: (1, 0),
    TPM_CC.Load: (1, 1),
    TPM_CC.Quote: (1, 0),
    TPM_CC.RSA_Decrypt: (1, 0),
    TPM_CC.HMAC_Start: (1, 1),
    TPM_CC.SequenceUpdate: (1, 0),
    TPM_CC.Sign: (1, 0),
    TPM_CC.Unseal: (1, 0),
    TPM_CC.PolicySigned: (2, 0),
    TPM_CC.ContextLoad: (0, 1),
    TPM_CC.ContextSave: (1, 0),
    TPM_CC.ECDH_KeyGen: (1, 0),
    TPM_CC.EncryptDecrypt: (1, 0),
    TPM_CC.FlushContext: (1, 0),
    TPM_CC.LoadExternal: (0, 1),
    TPM_CC.MakeCredential: (1, 0),
    TPM_CC.NV_ReadPublic: (1, 0),
    TPM_CC.PolicyAuthorize: (1, 0),
    TPM_CC.PolicyAuthValue: (1, 0),
    TPM_CC.PolicyCommandCode: (1, 0),
    TPM_CC.PolicyCounterTimer: (1, 0),
    TPM_CC.PolicyCpHash: (1, 0),
    TPM_CC.PolicyLocality: (1, 0),
    TPM_CC.PolicyNameHash: (1, 0),
    TPM_CC.PolicyOR: (1, 0),
    TPM_CC.PolicyTicket: (1, 0),
    TPM_CC.ReadPublic: (1, 0),
    TPM_CC.RSA_Encrypt: (1, 0),
    TPM_CC.StartAuthSession: (2, 1),
    TPM_CC.VerifySignature: (1, 0),
    TPM_CC.ECC_Parameters: (0, 0),
    TPM_CC.FirmwareRead: (0, 0),
    TPM_CC.GetCapability: (0, 0),
    TPM_CC.GetRandom: (0, 0),
    TPM_CC.GetTestResult: (0, 0),
    TPM_CC.Hash: (0, 0),
    TPM_CC.PCR_Read: (0, 0),
    TPM_CC.PolicyPCR: (1, 0),
    TPM_CC.PolicyRestart: (1, 0),
    TPM_CC.ReadClock: (0, 0),
    TPM_CC.PCR_Extend: (1, 0),
    TPM_CC.PCR_SetAuthValue: (1, 0),
    TPM_CC.NV_Certify: (3, 0),
    TPM_CC.EventSequenceComplete: (2, 0),
    TPM_CC.HashSequenceStart: (0, 1),
    TPM_CC.PolicyPhysicalPresence: (1, 0),
    TPM_CC.PolicyDuplicationSelect: (1, 0),
    TPM_CC.PolicyGetDigest: (1, 0),
    TPM_CC.TestParms: (0, 0),
    TPM_CC.Commit: (1, 0),
    TPM_CC.PolicyPassword: (1, 0),
    TPM_CC.ZGen_2Phase: (1, 0),
    TPM_CC.EC_Ephemeral: (0, 0),
    TPM_CC.PolicyNvWritten: (1, 0),
    TPM_CC.PolicyTemplate: (1, 0),
    TPM_CC.CreateLoaded: (1, 1),
    TPM_CC.PolicyAuthorizeNV: (3, 0),
    TPM_CC.EncryptDecrypt2: (1, 0),
    TPM_CC.AC_GetCapability: (1, 0),
    TPM_CC.AC_Send: (3, 0),
    TPM_CC.Policy_AC_SendSelect: (1, 0),
    TPM_CC.CertifyX509: (2, 0),
    TPM_CC.ACT_SetTimeout: (1, 0),
}


is_cmd = 1  # 0 for cmd, 1 for rsp
is_params = 0  # 0 for params, 1 for handles
is_def = 0  # 0 for class definition, 1 for dict (TPMCC to class mapping)

paths = glob.glob("/home/johannes/persistent/dev-projects/tpm/ibmtpm1563/src/*_fp.h")


def cc_name_from_path(path):
    return path.split("/")[-1][:-5]


paths = [p for p in paths if hasattr(TPM_CC, cc_name_from_path(p))]
paths = sorted(paths, key=lambda p: getattr(TPM_CC, cc_name_from_path(p))._value)


skipped = []
done = []

for path in paths:
    name = cc_name_from_path(path)
    indent = " " * 4
    try:
        cc = getattr(TPM_CC, name)
    except AttributeError:
        continue
    try:
        num_handles = tpm_handles[cc]
    except KeyError:
        continue

    with open(path) as file:
        lines = "".join(file.readlines())

    postfix = "_In;" if is_cmd == 0 else "_Out"
    m = re.search(
        "typedef struct \{((\s+[A-Z0-9_]+\s+\S+;)+)\n\} [A-Za-z0-9_]+" + postfix,
        lines,
        flags=re.DOTALL,
    )
    if m is None:
        if is_cmd == 0:
            skipped.append(cc)
            continue
        else:
            fields = []
    else:
        fields = [f.strip() for f in m.group(1).strip().split(";") if f]
        fields = [[e for e in re.split("\t| ", f) if e] for f in fields]

    done.append(cc)

    if is_params == 0:
        fields = fields[num_handles[is_cmd] :]
    else:
        fields = fields[: num_handles[is_cmd]]

    # print(name)
    # print()
    # print(fields)

    if len(fields) == 0:
        fields_str = f"{indent}pass"
    else:
        fields_str = "\n".join(
            f"{indent}{f_name}: {f_type}" for f_type, f_name in fields
        )

    def camel_to_snake(name):
        name = re.sub("(.)([A-Z][a-z]+)", r"\1_\2", name)
        return re.sub("([a-z0-9])([A-Z])", r"\1_\2", name).upper()

    name = camel_to_snake(name)
    name = re.sub("__", "_", name)

    if is_cmd == 0:
        if is_params == 0:
            name = f"TPMS_COMMAND_PARAMS_{name}"
        else:
            name = f"TPMS_COMMAND_HANDLES_{name}"
    else:
        if is_params == 0:
            name = f"TPMS_RESPONSE_PARAMS_{name}"
        else:
            name = f"TPMS_RESPONSE_HANDLES_{name}"

    if is_def == 0:
        print(f"@tpm_dataclass\nclass {camel_to_snake(name)}:\n{fields_str}\n")
    else:
        print(f"TPM_CC.{cc_name_from_path(path)}: {camel_to_snake(name)},")


skipped = skipped
todo = list(set(TPM_CC) - set(done))
todo = sorted(todo, key=lambda e: e._value)
# TODO a lot of skipped responses
print("foo")
