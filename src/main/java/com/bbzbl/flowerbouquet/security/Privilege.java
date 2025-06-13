package com.bbzbl.flowerbouquet.security;

import java.util.Collection;

import com.fasterxml.jackson.annotation.JsonIgnore;

import jakarta.persistence.Column;
import jakarta.persistence.Entity;
import jakarta.persistence.GeneratedValue;
import jakarta.persistence.GenerationType;
import jakarta.persistence.Id;
import jakarta.persistence.ManyToMany;
import jakarta.persistence.Table;
import lombok.Data;
import lombok.NoArgsConstructor;

/**
 * Entity class representing a Privilege in the system.
 * Privileges provide fine-grained permissions that can be assigned to roles.
 * This allows for more detailed access control beyond basic role-based security.
 */
@Data
@NoArgsConstructor
@Entity
@Table(name = "privileges")
public class Privilege {

    @Id
    @GeneratedValue(strategy = GenerationType.IDENTITY)
    private Long id;

    /**
     * The name of the privilege (e.g., "READ_USERS", "WRITE_ORDERS", "DELETE_PRODUCTS").
     * Should follow a consistent naming convention for clarity.
     */
    @Column(nullable = false, unique = true, length = 50)
    private String name;

    /**
     * Optional description of what this privilege allows.
     */
    @Column(length = 255)
    private String description;

    /**
     * Roles that have this privilege.
     * Uses @JsonIgnore to prevent circular reference during serialization.
     */
    @ManyToMany(mappedBy = "privileges")
    @JsonIgnore
    private Collection<Role> roles;

    /**
     * Constructor with name only.
     * 
     * @param name the privilege name
     */
    public Privilege(String name) {
        this.name = name;
    }

    /**
     * Constructor with name and description.
     * 
     * @param name the privilege name
     * @param description the privilege description
     */
    public Privilege(String name, String description) {
        this.name = name;
        this.description = description;
    }

    @Override
    public String toString() {
        return "Privilege{" +
                "id=" + id +
                ", name='" + name + '\'' +
                ", description='" + description + '\'' +
                '}';
    }

    @Override
    public boolean equals(Object o) {
        if (this == o) return true;
        if (!(o instanceof Privilege)) return false;
        Privilege privilege = (Privilege) o;
        return name != null && name.equals(privilege.name);
    }

    @Override
    public int hashCode() {
        return name != null ? name.hashCode() : 0;
    }
}