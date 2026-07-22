package dev.sdkey;

/** User object returned by register / login / upgrade. */
public final class ClientAuthUser {
  private final String id;
  private final String username;
  private final String email;
  private final String applicationId;

  public ClientAuthUser(String id, String username, String email, String applicationId) {
    this.id = id;
    this.username = username;
    this.email = email;
    this.applicationId = applicationId;
  }

  public String getId() {
    return id;
  }

  public String getUsername() {
    return username;
  }

  public String getEmail() {
    return email;
  }

  public String getApplicationId() {
    return applicationId;
  }
}
