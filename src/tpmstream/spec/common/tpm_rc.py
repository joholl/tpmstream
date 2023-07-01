from collections import defaultdict

from tpmstream.spec.common.values import tpm_bitfield
from tpmstream.spec.structures.base_types import UINT32

TPM_RC_FMT0_ERROR_MAP = defaultdict(
    lambda: ("None", "Unknown TPM_RC"),
    {
        0x000: (
            "INITIALIZE",
            "TPM not initialized by TPM2_Startup or already initialized",
        ),
        0x001: (
            "FAILURE",
            "commands not being accepted because of a TPM failure NOTE This may be returned by TPM2_GetTestResult() as the testResult parameter.",
        ),
        0x003: ("SEQUENCE", "improper use of a sequence handle"),
        0x00B: ("PRIVATE", "not currently used"),
        0x019: ("HMAC", "not currently used"),
        0x020: ("DISABLED", "the command is disabled"),
        0x021: (
            "EXCLUSIVE",
            "command failed because audit sequence required exclusivity",
        ),
        0x024: ("AUTH_TYPE", "authorization handle is not correct for command"),
        0x025: (
            "AUTH_MISSING",
            "command requires an authorization session for handle and it is not present.",
        ),
        0x026: (
            "POLICY",
            "policy failure in math operation or an invalid authPolicy value",
        ),
        0x027: ("PCR", "PCR check fail"),
        0x028: ("PCR_CHANGED", "PCR have changed since checked."),
        0x02D: (
            "UPGRADE",
            "for all commands other than TPM2_FieldUpgradeData(), this code indicates that the TPM is in field upgrade mode; for TPM2_FieldUpgradeData(), this code indicates that the TPM is not in field upgrade mode",
        ),
        0x02E: ("TOO_MANY_CONTEXTS", "context ID counter is at maximum."),
        0x02F: (
            "AUTH_UNAVAILABLE",
            "authValue or authPolicy is not available for selected entity.",
        ),
        0x030: (
            "REBOOT",
            "a _TPM_Init and Startup(CLEAR) is required before the TPM can resume operation.",
        ),
        0x031: (
            "UNBALANCED",
            "the protection algorithms (hash and symmetric) are not reasonably balanced. The digest size of the hash must be larger than the key size of the symmetric algorithm.",
        ),
        0x042: (
            "COMMAND_SIZE",
            "command commandSize value is inconsistent with contents of the command buffer; either the size is not the same as the octets loaded by the hardware interface layer or the value is not large enough to hold a command header",
        ),
        0x043: ("COMMAND_CODE", "command code not supported"),
        0x044: (
            "AUTHSIZE",
            "the value of authorizationSize is out of range or the number of octets in the Authorization Area is greater than required",
        ),
        0x045: (
            "AUTH_CONTEXT",
            "use of an authorization session with a context command or another command that cannot have an authorization session.",
        ),
        0x046: ("NV_RANGE", "NV offset+size is out of range."),
        0x047: ("NV_SIZE", "Requested allocation size is larger than allowed."),
        0x048: ("NV_LOCKED", "NV access locked."),
        0x049: (
            "NV_AUTHORIZATION",
            "NV access authorization fails in command actions (this failure does not affect lockout.action)",
        ),
        0x04A: (
            "NV_UNINITIALIZED",
            "an NV Index is used before being initialized or the state saved by TPM2_Shutdown(STATE) could not be restored",
        ),
        0x04B: ("NV_SPACE", "insufficient space for NV allocation"),
        0x04C: ("NV_DEFINED", "NV Index or persistent object already defined"),
        0x050: ("BAD_CONTEXT", "context in TPM2_ContextLoad() is not valid"),
        0x051: ("CPHASH", "cpHash value already set or not correct for use"),
        0x052: ("PARENT", "handle for parent is not a valid parent"),
        0x053: ("NEEDS_TEST", "some function needs testing."),
        0x054: (
            "NO_RESULT",
            "returned when an internal function cannot process a request due to an unspecified problem. This code is usually related to invalid parameters that are not properly filtered by the input unmarshaling code.",
        ),
        0x055: (
            "SENSITIVE",
            "the sensitive area did not unmarshal correctly after decryption – this code is used in lieu of the other unmarshaling errors so that an attacker cannot determine where the unmarshaling error occurred",
        ),
    },
)


TPM_RC_FMT1_MAP = defaultdict(
    lambda: ("None", "Unknown TPM_RC"),
    {
        0x001: ("ASYMMETRIC", "asymmetric algorithm not supported or not correct"),
        0x002: ("ATTRIBUTES", "inconsistent attributes"),
        0x003: ("HASH", "hash algorithm not supported or not appropriate"),
        0x004: ("VALUE", "value is out of range or is not correct for the context"),
        0x005: ("HIERARCHY", "hierarchy is not enabled or is not correct for the use"),
        0x007: ("KEY_SIZE", "key size is not supported"),
        0x008: ("MGF", "mask generation function not supported"),
        0x009: ("MODE", "mode of operation not supported"),
        0x00A: ("TYPE", "the type of the value is not appropriate for the use"),
        0x00B: ("HANDLE", "the handle is not correct for the use"),
        0x00C: (
            "KDF",
            "unsupported key derivation function or function not appropriate for use",
        ),
        0x00D: ("RANGE", "value was out of allowed range."),
        0x00E: (
            "AUTH_FAIL",
            "the authorization HMAC check failed and DA counter incremented",
        ),
        0x00F: ("NONCE", "invalid nonce size or nonce value mismatch"),
        0x010: ("PP", "authorization requires assertion of PP"),
        0x012: ("SCHEME", "unsupported or incompatible scheme"),
        0x015: ("SIZE", "structure is the wrong size"),
        0x016: (
            "SYMMETRIC",
            "unsupported symmetric algorithm or key size, or not appropriate for instance",
        ),
        0x017: ("TAG", "incorrect structure tag"),
        0x018: ("SELECTOR", "union selector is incorrect"),
        0x01A: (
            "INSUFFICIENT",
            "the TPM was unable to unmarshal a value because there were not enough octets in the input buffer",
        ),
        0x01B: ("SIGNATURE", "the signature is not valid"),
        0x01C: ("KEY", "key fields are not compatible with the selected use"),
        0x01D: ("POLICY_FAIL", "a policy check failed"),
        0x01F: ("INTEGRITY", "integrity check failed"),
        0x020: ("TICKET", "invalid ticket"),
        0x021: ("RESERVED_BITS", "reserved bits not set to zero as required"),
        0x022: ("BAD_AUTH", "authorization failure without DA implications"),
        0x023: ("EXPIRED", "the policy has expired"),
        0x024: (
            "POLICY_CC",
            "the commandCode in the policy is not the commandCode of the command or the command code in a policy command references a command that is not implemented",
        ),
        0x025: (
            "BINDING",
            "public and sensitive portions of an object are not cryptographically bound",
        ),
        0x026: ("CURVE", "curve not supported"),
        0x027: ("ECC_POINT", "point is not on the required curve. New Subsection"),
    },
)


TPM_RC_FMT0_WARN_MAP = defaultdict(
    lambda: ("None", "Unknown TPM_RC"),
    {
        0x001: ("CONTEXT_GAP", "gap for context ID is too large"),
        0x002: ("OBJECT_MEMORY", "out of memory for object contexts"),
        0x003: ("SESSION_MEMORY", "out of memory for session contexts"),
        0x004: (
            "MEMORY",
            "out of shared object/session memory or need space for internal operations",
        ),
        0x005: (
            "SESSION_HANDLES",
            "out of session handles – a session must be flushed before a new session may be created",
        ),
        0x006: (
            "OBJECT_HANDLES",
            "out of object handles – the handle space for objects is depleted and a reboot is required NOTE 1 This cannot occur on the reference implementation. NOTE 2 There is no reason why an implementation would implement a design that would deplete handle space. Platform specifications are encouraged to forbid it.",
        ),
        0x007: ("LOCALITY", "bad locality"),
        0x008: (
            "YIELDED",
            "the TPM has suspended operation on the command; forward progress was made and the command may be retried See TPM 2.0 Part 1, “Multi-tasking.” NOTE This cannot occur on the reference implementation.",
        ),
        0x009: ("CANCELED", "the command was canceled"),
        0x00A: ("TESTING", "TPM is performing self-tests"),
        0x010: (
            "REFERENCE_H0",
            "the 1st handle in the handle area references a transient object or session that is not loaded",
        ),
        0x011: (
            "REFERENCE_H1",
            "the 2nd handle in the handle area references a transient object or session that is not loaded",
        ),
        0x012: (
            "REFERENCE_H2",
            "the 3rd handle in the handle area references a transient object or session that is not loaded",
        ),
        0x013: (
            "REFERENCE_H3",
            "the 4th handle in the handle area references a transient object or session that is not loaded",
        ),
        0x014: (
            "REFERENCE_H4",
            "the 5th handle in the handle area references a transient object or session that is not loaded",
        ),
        0x015: (
            "REFERENCE_H5",
            "the 6th handle in the handle area references a transient object or session that is not loaded",
        ),
        0x016: (
            "REFERENCE_H6",
            "the 7th handle in the handle area references a transient object or session that is not loaded",
        ),
        0x018: (
            "REFERENCE_S0",
            "the 1st authorization session handle references a session that is not loaded",
        ),
        0x019: (
            "REFERENCE_S1",
            "the 2nd authorization session handle references a session that is not loaded",
        ),
        0x01A: (
            "REFERENCE_S2",
            "the 3rd authorization session handle references a session that is not loaded",
        ),
        0x01B: (
            "REFERENCE_S3",
            "the 4th authorization session handle references a session that is not loaded",
        ),
        0x01C: (
            "REFERENCE_S4",
            "the 5th session handle references a session that is not loaded",
        ),
        0x01D: (
            "REFERENCE_S5",
            "the 6th session handle references a session that is not loaded",
        ),
        0x01E: (
            "REFERENCE_S6",
            "the 7th authorization session handle references a session that is not loaded",
        ),
        0x020: (
            "NV_RATE",
            "the TPM is rate-limiting accesses to prevent wearout of NV",
        ),
        0x021: (
            "LOCKOUT",
            "authorizations for objects subject to DA protection are not allowed at this time because the TPM is in DA lockout mode",
        ),
        0x022: ("RETRY", "the TPM was not able to start the command"),
        0x023: (
            "NV_UNAVAILABLE",
            "the command may require writing of NV and NV is not current accessible",
        ),
        0x07F: (
            "NOT_USED",
            "this value is reserved and shall not be returned by the TP",
        ),
    },
)


mask_reserved = 0xFFFFF000
mask_tpm12 = 0x180
mask_tpm12_non_fatal = 0x800
mask_tpm12_vendor_specific = 0x400
mask_tpm12_code = 0x7F
mask_fmt1 = 0x80
mask_fmt1_code = 0x7F
mask_fmt1_version = 0x100
mask_fmt1_reserved = 0x200
mask_fmt1_vendor = 0x400
mask_fmt1_spec_warning = 0x800
mask_fmt0_param = 0x40
mask_fmt0_session = 0x800
mask_fmt0_code = 0x3F
mask_fmt0_param_num = 0xF00
mask_fmt0_handle_num = 0x700
mask_fmt0_session_num = 0x700
shift_fmt0_param_num = 8
shift_fmt0_handle_num = 8
shift_fmt0_session_num = 8


@tpm_bitfield(replace_format=False)
class TPM_RC(UINT32):
    SUCCESS = 0x00000000
    # TODO add all errors above?
    # TODO value constraints?

    def are_bits_set(self, mask):
        return bool(self._value & mask == mask)

    def are_bits_unset(self, mask):
        return bool(self._value & mask == 0)

    def __format__(self, *args, **kwargs):
        if self._value == 0:
            return f"{type(self).__name__}.SUCCESS"

        if self.are_bits_unset(mask_tpm12):
            # TPM 1.2 Response Code
            return f"{type(self).__name__}.UNKNOWN (TPM1.2)"

        if not self.are_bits_set(mask_fmt1):
            # Format 0 (command errors)
            if self.are_bits_set(mask_fmt1_vendor):
                return f"{type(self).__name__}.UNKNOWN (Vendor-defined)"

            if self.are_bits_set(mask_fmt1_spec_warning):
                # Warning Code in Bits[06:00]
                name, _description = TPM_RC_FMT0_WARN_MAP[self._value & mask_fmt1_code]
            else:
                # Error Code in Bits[06:00]
                name, _description = TPM_RC_FMT0_ERROR_MAP[self._value & mask_fmt1_code]
            return f"{type(self).__name__}.{name}"

        # Format 1 (unmarshalling errors)
        if self.are_bits_set(mask_fmt0_param):
            param_num = (self._value & mask_fmt0_param_num) >> shift_fmt0_param_num
            details = f"Parameter No. {param_num}"
        else:
            if self.are_bits_set(mask_fmt0_session):
                session_num = (
                    self._value & mask_fmt0_session_num
                ) >> shift_fmt0_session_num
                details = f"Session No. {session_num}"
            else:
                handle_num = (
                    self._value & mask_fmt0_handle_num
                ) >> shift_fmt0_handle_num
                details = f"Handle No. {handle_num}"

        name, _description = TPM_RC_FMT1_MAP[self._value & mask_fmt0_code]
        return f"{type(self).__name__}.{name} ({details})"

    def __str__(self):
        return self.__format__(None)

    def attributes(self):
        def sort(bits):
            return sorted(bits, key=lambda b: b._value, reverse=True)

        bits = []

        if self._value == 0:
            # success
            return []

        bits.append(TPM_RC(mask_reserved, name="reserved0"))
        if self.are_bits_unset(mask_tpm12):
            # TPM 1.2 Response Code
            bits.append(TPM_RC(0x00000800, name="nonFatal"))
            bits.append(TPM_RC(0x00000400, name="vendorSpecific"))

            bits.append(TPM_RC(mask_tpm12, name="tpm12_signifier", details="TPM 1.2"))
            bits.append(TPM_RC(mask_tpm12_code, name="code"))
            return sort(bits)

        bits.append(TPM_RC(mask_fmt1, name="format"))
        if not self.are_bits_set(mask_fmt1):
            # Format 0 (command errors)
            bits.append(TPM_RC(0x100, name="version", details="TPM 2.0"))
            bits.append(TPM_RC(mask_fmt1_vendor, name="vendorDefined"))
            severity_str = (
                "Warning" if self.are_bits_set(mask_fmt1_spec_warning) else "Error"
            )
            bits.append(
                TPM_RC(mask_fmt1_spec_warning, name="severity", details=severity_str)
            )
            bits.append(TPM_RC(mask_fmt1_reserved, name="reserved1"))

            details = None
            if self.are_bits_unset(mask_fmt1_vendor):
                if self.are_bits_set(mask_fmt1_spec_warning):
                    # Warning Code in Bits[06:00]
                    name, description = TPM_RC_FMT0_WARN_MAP[
                        self._value & mask_fmt1_code
                    ]
                else:
                    # Error Code in Bits[06:00]
                    name, description = TPM_RC_FMT0_ERROR_MAP[
                        self._value & mask_fmt1_code
                    ]
                details = f"{name}: {description}"

            bits.append(TPM_RC(mask_fmt1_code, name="code", details=details))
            return sort(bits)

        # Format 1 (unmarshalling errors)
        bits.append(TPM_RC(mask_fmt0_param, name="parameterError"))
        if self.are_bits_set(mask_fmt0_param):
            param_num = (self._value & mask_fmt0_param_num) >> shift_fmt0_param_num
            bits.append(
                TPM_RC(
                    mask_fmt0_param_num,
                    name="parameterNumber",
                    details=f"Parameter No. {param_num}",
                )
            )
        else:
            bits.append(TPM_RC(mask_fmt0_session, name="sessionError"))
            if self.are_bits_set(mask_fmt0_session):
                session_num = (
                    self._value & mask_fmt0_session_num
                ) >> shift_fmt0_session_num
                bits.append(
                    TPM_RC(
                        mask_fmt0_session_num,
                        name="sessionNumber",
                        details=f"Session No. {session_num}",
                    )
                )
            else:
                handle_num = (
                    self._value & mask_fmt0_handle_num
                ) >> shift_fmt0_handle_num
                bits.append(
                    TPM_RC(
                        mask_fmt0_handle_num,
                        name="handleNumber",
                        details=f"Handle No. {handle_num}",
                    )
                )

        name, description = TPM_RC_FMT1_MAP[self._value & mask_fmt0_code]
        bits.append(
            TPM_RC(mask_fmt0_code, name="code", details=f"{name}: {description}")
        )
        return sort(bits)
