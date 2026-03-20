package com.passmanager.util;

import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;

import static org.junit.jupiter.api.Assertions.*;

class PasswordGeneratorTest {
    private PasswordGeneratorUtil util;

    @BeforeEach
    void setUp() {
        util = new PasswordGeneratorUtil();
    }

    @Test
    void generatesRequestedLength() {
        String password = util.generate(24, true, true, true, true, false);
        assertEquals(24, password.length());
    }

    @Test
    void excludesSimilarCharactersWhenRequested() {
        String password = util.generate(64, true, true, true, false, true);
        assertFalse(password.matches(".*[0O1Il].*"));
    }

    @Test
    void fallsBackToLowercaseWhenNoOptionsSelected() {
        String password = util.generate(12, false, false, false, false, false);
        assertEquals(12, password.length());
        assertTrue(password.matches("[a-z]+"));
    }

    @Test
    void includesOnlyDigitsWhenDigitsSelected() {
        String password = util.generate(16, false, false, true, false, false);
        assertTrue(password.matches("[0-9]+"));
    }
}
