package demo.thermohub.cra.security;

public enum Role {

    USER,
    ADMIN;

    /** ADMIN satisfies every requirement; USER satisfies only USER. */
    public boolean satisfies(Role required) {
        return this == ADMIN || this == required;
    }
}
