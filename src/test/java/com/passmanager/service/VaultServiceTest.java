package com.passmanager.service;

import com.passmanager.entity.PasswordEntry;
import com.passmanager.entity.User;
import com.passmanager.repository.PasswordEntryRepository;
import com.passmanager.util.EncryptionUtil;
import com.passmanager.util.PasswordStrengthUtil;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.extension.ExtendWith;
import org.mockito.ArgumentCaptor;
import org.mockito.Mock;
import org.mockito.junit.jupiter.MockitoExtension;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertNotNull;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.mockito.ArgumentMatchers.any;
import static org.mockito.ArgumentMatchers.eq;
import static org.mockito.Mockito.never;
import static org.mockito.Mockito.verify;
import static org.mockito.Mockito.when;

@ExtendWith(MockitoExtension.class)
class VaultServiceTest {

    @Mock
    private PasswordEntryRepository passwordEntryRepository;

    @Mock
    private EncryptionUtil encryptionUtil;

    private VaultService vaultService;
    private final PasswordStrengthUtil strengthUtil = new PasswordStrengthUtil();

    @BeforeEach
    void setUp() {
        vaultService = new VaultService(passwordEntryRepository, encryptionUtil, strengthUtil);
    }

    @Test
    void importsValidBackupRows() {
        when(passwordEntryRepository.save(any(PasswordEntry.class)))
                .thenAnswer(invocation -> invocation.getArgument(0));

        when(encryptionUtil.encrypt(any(String.class), eq("master123")))
                .thenAnswer(invocation -> "enc:" + invocation.getArgument(0));

        String decrypted = "ACCOUNT_NAME,WEBSITE,USERNAME,PASSWORD,CATEGORY,NOTES\n" +
                "\"GitHub\",\"https://github.com\",\"ojas\",\"Secret123!\",\"WORK\",\"dev\"\n";

        when(encryptionUtil.decrypt("backup-data", "master123")).thenReturn(decrypted);

        User user = new User();
        user.setUsername("ojas");

        int imported = vaultService.importVault(user, "master123", "backup-data");

        assertEquals(1, imported);

        ArgumentCaptor<PasswordEntry> captor = ArgumentCaptor.forClass(PasswordEntry.class);
        verify(passwordEntryRepository).save(captor.capture());

        PasswordEntry saved = captor.getValue();
        assertEquals("GitHub", saved.getAccountName());
        assertEquals(PasswordEntry.Category.WORK, saved.getCategory());
        assertNotNull(saved.getPasswordStrengthScore());
    }

    @Test
    void rejectsInvalidBackupHeader() {
        when(encryptionUtil.decrypt("backup-data", "master123"))
                .thenReturn("BAD_HEADER\n");

        User user = new User();

        assertThrows(IllegalArgumentException.class,
                () -> vaultService.importVault(user, "master123", "backup-data"));

        verify(passwordEntryRepository, never()).save(any());
    }
}