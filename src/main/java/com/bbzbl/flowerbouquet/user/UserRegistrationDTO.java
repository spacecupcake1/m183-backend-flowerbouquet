package com.bbzbl.flowerbouquet.user;

import com.bbzbl.flowerbouquet.validation.NoSqlInjection;
import com.bbzbl.flowerbouquet.validation.NoXSS;
import com.bbzbl.flowerbouquet.validation.StrongPassword;

import jakarta.validation.constraints.Email;
import jakarta.validation.constraints.NotBlank;
import jakarta.validation.constraints.Pattern;
import jakarta.validation.constraints.Size;

public class UserRegistrationDTO {

    @NotBlank(message = "Username is required")
    @Size(min = 3, max = 50, message = "Username must be between 3 and 50 characters")
    @Pattern(regexp = "^[a-zA-Z0-9_-]+$", message = "Username can only contain letters, numbers, hyphens and underscores")
    @NoSqlInjection
    @NoXSS
    private String username;

    @NotBlank(message = "First name is required")
    @Size(min = 2, max = 50, message = "First name must be between 2 and 50 characters")
    @Pattern(regexp = "^[a-zA-ZÀ-ÿ\\s'-]+$", message = "First name can only contain letters, spaces, hyphens and apostrophes")
    @NoSqlInjection
    @NoXSS
    private String firstname;

    @NotBlank(message = "Last name is required")
    @Size(min = 2, max = 50, message = "Last name must be between 2 and 50 characters")
    @Pattern(regexp = "^[a-zA-ZÀ-ÿ\\s'-]+$", message = "Last name can only contain letters, spaces, hyphens and apostrophes")
    @NoSqlInjection
    @NoXSS
    private String lastname;

    @NotBlank(message = "Email is required")
    @Email(message = "Please provide a valid email address")
    @Size(max = 100, message = "Email cannot exceed 100 characters")
    @NoSqlInjection
    @NoXSS
    private String email;

    @NotBlank(message = "Password is required")
    @StrongPassword
    @NoSqlInjection
    @NoXSS
    private String password;

    // Constructors, getters, and setters
    public UserRegistrationDTO() {}

    public UserRegistrationDTO(String username, String firstname, String lastname, String email, String password) {
        this.username = username;
        this.firstname = firstname;
        this.lastname = lastname;
        this.email = email;
        this.password = password;
    }

    // Getters and setters
    public String getUsername() { return username; }
    public void setUsername(String username) { this.username = username; }

    public String getFirstname() { return firstname; }
    public void setFirstname(String firstname) { this.firstname = firstname; }

    public String getLastname() { return lastname; }
    public void setLastname(String lastname) { this.lastname = lastname; }

    public String getEmail() { return email; }
    public void setEmail(String email) { this.email = email; }

    public String getPassword() { return password; }
    public void setPassword(String password) { this.password = password; }
}
