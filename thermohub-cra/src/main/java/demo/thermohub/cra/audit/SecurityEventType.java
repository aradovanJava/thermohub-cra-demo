package demo.thermohub.cra.audit;

/** Security-relevant activity recorded under CRA Annex I Part I (2)(l). */
public enum SecurityEventType {
    LOGIN_FAILED,
    LOGIN_BLOCKED,
    ACCESS_DENIED,
    COMMAND_DENIED,
    PAIRING_FAILED,
    PAIRING_THROTTLED,
    DEVICE_PAIRED,
    INPUT_REJECTED,
    FIRMWARE_REJECTED,
    FIRMWARE_RELEASED
}
