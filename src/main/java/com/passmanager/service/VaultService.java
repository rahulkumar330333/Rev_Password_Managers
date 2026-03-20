package com.passmanager.service;

import com.passmanager.dto.AccountAuditDto;
import com.passmanager.dto.PasswordEntryDto;
import com.passmanager.dto.SecurityAuditDto;
import com.passmanager.entity.PasswordEntry;
import com.passmanager.entity.User;
import com.passmanager.repository.PasswordEntryRepository;
import com.passmanager.util.EncryptionUtil;
import com.passmanager.util.PasswordStrengthUtil;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.stereotype.Service;
import org.springframework.transaction.annotation.Transactional;
import java.util.*;
import java.util.stream.Collectors;

/**
 * VaultService — manages all password vault operations.
 *
 * Key features:
 *  - passwordStrengthScore calculated and stored on every add/update
 *  - reEncryptEntriesForMasterPasswordChange: re-encrypts all vault data when master password changes
 *  - importVault: imports an encrypted CSV backup, deduplicates entries
 *  - exportVault: exports encrypted CSV backup
 *  - generateAudit / generateDetailedAudit: security scoring and grading
 */
@Service
public class VaultService {

    private static final Logger log = LoggerFactory.getLogger(VaultService.class);

    private final PasswordEntryRepository passwordEntryRepository;
    private final EncryptionUtil encryptionUtil;
    private final PasswordStrengthUtil strengthUtil;

    public VaultService(PasswordEntryRepository passwordEntryRepository,
                        EncryptionUtil encryptionUtil,
                        PasswordStrengthUtil strengthUtil) {
        this.passwordEntryRepository = passwordEntryRepository;
        this.encryptionUtil = encryptionUtil;
        this.strengthUtil = strengthUtil;
    }

    @Transactional
    public PasswordEntry addEntry(User user, PasswordEntryDto dto, String masterPassword) {
        int strengthScore = strengthUtil.calculateScore(dto.getPassword());
        String encryptedPassword = encryptionUtil.encrypt(dto.getPassword(), masterPassword);
        String encryptedNotes = (dto.getNotes() != null && !dto.getNotes().isEmpty())
                ? encryptionUtil.encrypt(dto.getNotes(), masterPassword)
                : null;

        PasswordEntry entry = PasswordEntry.builder()
                .user(user)
                .accountName(dto.getAccountName())
                .websiteUrl(dto.getWebsiteUrl())
                .usernameOrEmail(dto.getUsernameOrEmail())
                .encryptedPassword(encryptedPassword)
                .encryptedNotes(encryptedNotes)
                .category(dto.getCategory() != null ? dto.getCategory() : PasswordEntry.Category.OTHER)
                .favorite(dto.isFavorite())
                .passwordStrengthScore(strengthScore)
                .build();

        entry = passwordEntryRepository.save(entry);
        log.info("Password entry added: {} for user: {}", dto.getAccountName(), user.getUsername());
        return entry;
    }

    @Transactional
    public PasswordEntry updateEntry(Long entryId, User user, PasswordEntryDto dto, String masterPassword) {
        PasswordEntry entry = passwordEntryRepository.findById(entryId)
                .orElseThrow(() -> new RuntimeException("Entry not found"));
        if (!entry.getUser().getId().equals(user.getId())) {
            throw new SecurityException("Unauthorized access");
        }
        entry.setAccountName(dto.getAccountName());
        entry.setWebsiteUrl(dto.getWebsiteUrl());
        entry.setUsernameOrEmail(dto.getUsernameOrEmail());
        entry.setPasswordStrengthScore(strengthUtil.calculateScore(dto.getPassword()));
        entry.setEncryptedPassword(encryptionUtil.encrypt(dto.getPassword(), masterPassword));
        entry.setCategory(dto.getCategory() != null ? dto.getCategory() : PasswordEntry.Category.OTHER);
        entry.setFavorite(dto.isFavorite());
        if (dto.getNotes() != null && !dto.getNotes().isEmpty()) {
            entry.setEncryptedNotes(encryptionUtil.encrypt(dto.getNotes(), masterPassword));
        } else {
            entry.setEncryptedNotes(null);
        }
        return passwordEntryRepository.save(entry);
    }

    @Transactional
    public void deleteEntry(Long entryId, User user) {
        PasswordEntry entry = passwordEntryRepository.findById(entryId)
                .orElseThrow(() -> new RuntimeException("Entry not found"));
        if (!entry.getUser().getId().equals(user.getId())) {
            throw new SecurityException("Unauthorized access");
        }
        passwordEntryRepository.delete(entry);
        log.info("Password entry deleted: {} for user: {}", entryId, user.getUsername());
    }

    public List<PasswordEntry> getAllEntries(User user) {
        return passwordEntryRepository.findByUserOrderByCreatedAtDesc(user);
    }

    public List<PasswordEntry> getFavorites(User user) {
        return passwordEntryRepository.findByUserAndFavoriteTrueOrderByAccountNameAsc(user);
    }

    public List<PasswordEntry> searchEntries(User user, String query) {
        return passwordEntryRepository.searchByUser(user, query);
    }

    public List<PasswordEntry> filterByCategory(User user, PasswordEntry.Category category) {
        return passwordEntryRepository.findByUserAndCategoryOrderByAccountNameAsc(user, category);
    }

    public Optional<PasswordEntry> findById(Long id, User user) {
        return passwordEntryRepository.findById(id)
                .filter(e -> e.getUser().getId().equals(user.getId()));
    }

    public String decryptPassword(PasswordEntry entry, String masterPassword) {
        return encryptionUtil.decrypt(entry.getEncryptedPassword(), masterPassword);
    }

    public String decryptNotes(PasswordEntry entry, String masterPassword) {
        if (entry.getEncryptedNotes() == null) return null;
        return encryptionUtil.decrypt(entry.getEncryptedNotes(), masterPassword);
    }

    @Transactional
    public void toggleFavorite(Long entryId, User user) {
        PasswordEntry entry = passwordEntryRepository.findById(entryId)
                .orElseThrow(() -> new RuntimeException("Entry not found"));
        if (!entry.getUser().getId().equals(user.getId())) {
            throw new SecurityException("Unauthorized");
        }
        entry.setFavorite(!entry.isFavorite());
        passwordEntryRepository.save(entry);
    }

    // ---- Security Audit ----

    @Transactional(readOnly = true)
    public SecurityAuditDto generateAudit(User user, String masterPassword) {
        List<PasswordEntry> entries = getAllEntries(user);
        List<String> weakAccounts = new ArrayList<>();
        List<String> reusedAccounts = new ArrayList<>();
        Map<String, List<String>> passwordToAccounts = new HashMap<>();

        for (PasswordEntry entry : entries) {
            try {
                String pwd = decryptPassword(entry, masterPassword);
                if (strengthUtil.isWeak(pwd)) {
                    weakAccounts.add(entry.getAccountName());
                }
                passwordToAccounts.computeIfAbsent(pwd, k -> new ArrayList<>()).add(entry.getAccountName());
            } catch (Exception e) {
                log.warn("Could not decrypt entry: {}", entry.getId());
            }
        }

        for (Map.Entry<String, List<String>> e : passwordToAccounts.entrySet()) {
            if (e.getValue().size() > 1) {
                reusedAccounts.addAll(e.getValue());
            }
        }

        long strong = entries.size() - weakAccounts.size();
        int score = entries.isEmpty() ? 100
                : (int) (((double) strong / entries.size()) * 100 - (reusedAccounts.size() * 5));
        score = Math.max(0, Math.min(100, score));
        String grade = score >= 90 ? "A" : score >= 75 ? "B" : score >= 60 ? "C" : score >= 40 ? "D" : "F";

        SecurityAuditDto audit = new SecurityAuditDto();
        audit.setTotalPasswords(entries.size());
        audit.setWeakPasswords(weakAccounts.size());
        audit.setReusedPasswords(reusedAccounts.size());
        audit.setStrongPasswords(strong);
        audit.setWeakPasswordAccounts(weakAccounts);
        audit.setReusedPasswordAccounts(reusedAccounts.stream().distinct().collect(Collectors.toList()));
        audit.setOverallScore(score);
        audit.setOverallGrade(grade);
        return audit;
    }

    @Transactional(readOnly = true)
    public List<AccountAuditDto> generateDetailedAudit(User user, String masterPassword) {
        List<PasswordEntry> entries = getAllEntries(user);
        List<AccountAuditDto> detailedAudits = new ArrayList<>();
        Map<String, List<PasswordEntry>> pwdMap = new HashMap<>();

        for (PasswordEntry entry : entries) {
            try {
                String pwd = decryptPassword(entry, masterPassword);
                pwdMap.computeIfAbsent(pwd, k -> new ArrayList<>()).add(entry);

                AccountAuditDto dto = new AccountAuditDto();
                dto.setId(entry.getId());
                dto.setAccountName(entry.getAccountName());
                dto.setWebsiteUrl(entry.getWebsiteUrl());
                dto.setUsernameOrEmail(entry.getUsernameOrEmail());
                dto.setCategory(entry.getCategory() != null ? entry.getCategory().name() : "OTHER");
                dto.setFavorite(entry.isFavorite());
                dto.setWeak(strengthUtil.isWeak(pwd));
                detailedAudits.add(dto);
            } catch (Exception e) {
                log.warn("Could not decrypt entry: {}", entry.getId());
            }
        }

        // Mark reused passwords
        for (List<PasswordEntry> group : pwdMap.values()) {
            if (group.size() > 1) {
                Set<Long> reusedIds = group.stream().map(PasswordEntry::getId).collect(Collectors.toSet());
                for (AccountAuditDto audit : detailedAudits) {
                    if (reusedIds.contains(audit.getId())) {
                        audit.setReused(true);
                    }
                }
            }
        }

        return detailedAudits;
    }

    // ---- Export / Import ----

    public String exportVault(User user, String masterPassword) {
        List<PasswordEntry> entries = getAllEntries(user);
        StringBuilder sb = new StringBuilder();
        sb.append("ACCOUNT_NAME,WEBSITE,USERNAME,PASSWORD,CATEGORY,NOTES\n");
        for (PasswordEntry entry : entries) {
            try {
                String pwd = decryptPassword(entry, masterPassword);
                String notes = entry.getEncryptedNotes() != null ? decryptNotes(entry, masterPassword) : "";
                sb.append(String.format("\"%s\",\"%s\",\"%s\",\"%s\",\"%s\",\"%s\"\n",
                        entry.getAccountName(), nullSafe(entry.getWebsiteUrl()),
                        nullSafe(entry.getUsernameOrEmail()), pwd,
                        entry.getCategory(), nullSafe(notes)));
            } catch (Exception e) {
                log.warn("Could not export entry: {}", entry.getId());
            }
        }
        return encryptionUtil.encrypt(sb.toString(), masterPassword);
    }

    @Transactional
    public int importVault(User user, String masterPassword, String encryptedBackup) {
        String decrypted = encryptionUtil.decrypt(encryptedBackup, masterPassword);
        List<String> lines = decrypted.lines()
                .filter(line -> line != null && !line.isBlank())
                .toList();
        if (lines.isEmpty()) {
            throw new IllegalArgumentException("Backup file is empty");
        }

        String header = lines.get(0).trim();
        if (!"ACCOUNT_NAME,WEBSITE,USERNAME,PASSWORD,CATEGORY,NOTES".equalsIgnoreCase(header)) {
            throw new IllegalArgumentException("Backup file format is invalid");
        }

        Set<String> existingKeys = getAllEntries(user).stream()
                .map(this::entryIdentityKey)
                .collect(Collectors.toCollection(HashSet::new));

        int importedCount = 0;
        for (int i = 1; i < lines.size(); i++) {
            List<String> columns = parseCsvLine(lines.get(i));
            if (columns.size() < 6) {
                throw new IllegalArgumentException("Backup row " + (i + 1) + " is invalid");
            }

            PasswordEntryDto dto = new PasswordEntryDto();
            dto.setAccountName(columns.get(0).trim());
            dto.setWebsiteUrl(blankToNull(columns.get(1)));
            dto.setUsernameOrEmail(blankToNull(columns.get(2)));
            dto.setPassword(columns.get(3));
            dto.setCategory(parseCategory(columns.get(4)));
            dto.setNotes(blankToNull(columns.get(5)));

            if (dto.getAccountName().isBlank() || dto.getPassword() == null || dto.getPassword().isBlank()) {
                throw new IllegalArgumentException("Backup row " + (i + 1) + " is missing required fields");
            }

            String importKey = identityKey(dto.getAccountName(), dto.getWebsiteUrl(), dto.getUsernameOrEmail());
            if (existingKeys.contains(importKey)) {
                continue; // skip duplicates
            }
            addEntry(user, dto, masterPassword);
            existingKeys.add(importKey);
            importedCount++;
        }
        return importedCount;
    }

    /**
     * Re-encrypts all vault entries when a user changes their master password.
     * Critical: ensures the vault key stays in sync with the master password.
     */
    @Transactional
    public void reEncryptEntriesForMasterPasswordChange(User user, String oldMasterPassword, String newMasterPassword) {
        List<PasswordEntry> entries = getAllEntries(user);
        for (PasswordEntry entry : entries) {
            try {
                String decryptedPassword = decryptPassword(entry, oldMasterPassword);
                entry.setEncryptedPassword(encryptionUtil.encrypt(decryptedPassword, newMasterPassword));

                if (entry.getEncryptedNotes() != null) {
                    String decryptedNotes = decryptNotes(entry, oldMasterPassword);
                    entry.setEncryptedNotes(encryptionUtil.encrypt(decryptedNotes, newMasterPassword));
                }
            } catch (Exception e) {
                log.error("Failed to re-encrypt entry {} during master password change", entry.getId(), e);
                throw new RuntimeException("Vault re-encryption failed. Password not changed.", e);
            }
        }
        passwordEntryRepository.saveAll(entries);
        log.info("Re-encrypted {} vault entries for user: {}", entries.size(), user.getUsername());
    }

    public long countEntries(User user) {
        return passwordEntryRepository.countByUser(user);
    }

    // ---- Private helpers ----

    private PasswordEntry.Category parseCategory(String categoryValue) {
        if (categoryValue == null || categoryValue.isBlank()) return PasswordEntry.Category.OTHER;
        try {
            return PasswordEntry.Category.valueOf(categoryValue.trim());
        } catch (IllegalArgumentException ex) {
            return PasswordEntry.Category.OTHER;
        }
    }

    private String blankToNull(String value) {
        if (value == null) return null;
        String trimmed = value.trim();
        return trimmed.isEmpty() ? null : trimmed;
    }

    private List<String> parseCsvLine(String line) {
        List<String> columns = new ArrayList<>();
        StringBuilder current = new StringBuilder();
        boolean inQuotes = false;

        for (int i = 0; i < line.length(); i++) {
            char ch = line.charAt(i);
            if (ch == '"') {
                if (inQuotes && i + 1 < line.length() && line.charAt(i + 1) == '"') {
                    current.append('"');
                    i++;
                } else {
                    inQuotes = !inQuotes;
                }
            } else if (ch == ',' && !inQuotes) {
                columns.add(current.toString());
                current.setLength(0);
            } else {
                current.append(ch);
            }
        }
        columns.add(current.toString());
        return columns;
    }

    private String nullSafe(String s) { return s != null ? s : ""; }

    private String entryIdentityKey(PasswordEntry entry) {
        return identityKey(entry.getAccountName(), entry.getWebsiteUrl(), entry.getUsernameOrEmail());
    }

    private String identityKey(String accountName, String websiteUrl, String usernameOrEmail) {
        return normalize(accountName) + "|" + normalize(websiteUrl) + "|" + normalize(usernameOrEmail);
    }

    private String normalize(String value) {
        return value == null ? "" : value.trim().toLowerCase(Locale.ROOT);
    }
}
