package dev.sdkey;

/** Session metadata returned by register / login / upgrade. */
public final class ClientAuthSession {
  private final String ip;
  private final String hwid;

  public ClientAuthSession(String ip, String hwid) {
    this.ip = ip;
    this.hwid = hwid;
  }

  public String getIp() {
    return ip;
  }

  public String getHwid() {
    return hwid;
  }
}
