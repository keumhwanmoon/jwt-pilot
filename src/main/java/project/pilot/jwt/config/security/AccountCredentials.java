package project.pilot.jwt.config.security;

import lombok.Getter;
import lombok.Setter;

@Getter
@Setter
public class AccountCredentials {

    private String username;
    private String password;
}
