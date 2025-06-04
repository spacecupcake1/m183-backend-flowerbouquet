package com.bbzbl.flowerbouquet.user;

import java.util.List;

import lombok.Data;

@Data
public class UserResponseDTO {
    private Long id;
    private String username;
    private String firstname;
    private String lastname;
    private String email;
    private List<String> roles;
}
