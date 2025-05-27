package com.bbzbl.flowerbouquet.user;

import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.mockito.InjectMocks;
import org.mockito.Mock;
import org.mockito.MockitoAnnotations;

import java.util.Arrays;
import java.util.List;
import java.util.Optional;

import static org.assertj.core.api.Assertions.assertThat;
import static org.mockito.Mockito.*;

public class UserServiceTest {

    @Mock
    private UserRepository userRepo;

    @InjectMocks
    private UserService userService;

    private User user1;
    private User user2;

    @BeforeEach
    public void setUp() {
        MockitoAnnotations.openMocks(this);
        
        user1 = new User();
        user1.setId(1L);
        user1.setUsername("user1");
        user1.setFirstname("First1");
        user1.setLastname("Last1");
        user1.setEmail("user1@example.com");
        user1.setPassword("password1");

        user2 = new User();
        user2.setId(2L);
        user2.setUsername("user2");
        user2.setFirstname("First2");
        user2.setLastname("Last2");
        user2.setEmail("user2@example.com");
        user2.setPassword("password2");
    }

    @Test
    public void testGetAllUsers() {
        when(userRepo.findAll()).thenReturn(Arrays.asList(user1, user2));

        List<User> users = userService.getAllUsers();

        assertThat(users).hasSize(2);
        assertThat(users).contains(user1, user2);

        verify(userRepo, times(1)).findAll();
    }

    @Test
    public void testGetUserById() {
        when(userRepo.findById(1L)).thenReturn(Optional.of(user1));

        Optional<User> foundUser = userService.getUserById(1L);

        assertThat(foundUser).isPresent();
        assertThat(foundUser.get()).isEqualTo(user1);

        verify(userRepo, times(1)).findById(1L);
    }

    @Test
    public void testCreateUser() {
        when(userRepo.save(user1)).thenReturn(user1);

        User createdUser = userService.createUser(user1);

        assertThat(createdUser).isEqualTo(user1);

        verify(userRepo, times(1)).save(user1);
    }
}
