/*
 * Copyright (C) 2025 Evandro Giachetto <evandro@hey-dba.com>
 *
 * This program is free software: you can redistribute it and/or modify
 * it under the terms of the GNU General Public License as published by
 * the Free Software Foundation, either version 3 of the License, or
 * (at your option) any later version.
 *
 * This program is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU General Public License for more details.
 *
 * You should have received a copy of the GNU General Public License
 * along with this program.  If not, see <https://www.gnu.org/licenses/>.
 */

-- pci_password_check_rules Extension Description
--
-- Name: pci_password_check_rules
-- Purpose: This pg_tle extension provides a comprehensive set of functions, tables, and hooks
--          designed to enforce stringent password and account management policies within PostgreSQL,
--          specifically aligning with PCI DSS v4.0.1 requirements. It acts as a robust security layer
--          to protect sensitive data environments.
--
-- Version 0.6 Update Path (from 0.5 to 0.6)
-- This update significantly enhances the extension's capabilities by introducing mandatory
-- first-time password changes and implementing a "bad passwords" list to prevent the use
-- of common or compromised credentials.
--
-- PCI DSS Requirements Addressed in Version 0.6:
--   - Requirement 8.3.5: Require all users to change their password upon first login after account creation or password reset.
--   - Requirement 8.3.8 (Good Practice): Implement processes to confirm passwords meet policy,
--     e.g., by comparing password choices to a list of unacceptable passwords.
--
-- Changes Introduced in Version 0.6:
--
--   1.  Enhanced User Activity Tracking (`password_check.user_login_activity`):
--       - **New Columns:**
--         - `password_reset_required` (BOOLEAN): Flag indicating if the user's password must be changed on their next login.
--         - `password_first_login` (BOOLEAN): Flag used to manage the grace period for first-time password changes.
--
--   2.  **NEW Table: `password_check.bad_passwords`:**
--       - Purpose: Stores cryptographic hashes of commonly known weak, compromised, or vendor-default passwords.
--       - Columns: `password_hash` (TEXT, PRIMARY KEY), `source` (TEXT).
--       - Initial Population: Includes a pre-compiled list of such passwords, hashed with a fixed salt (`$2a$06$uDrK/2blP99mE1qXATTJce`).
--
--   3.  Enhanced Hook Functions:
--       - **`clientauth_hook`:**
--         - **First-Time Login Enforcement:** On a user's *first successful login* when `password_reset_required` is TRUE, it issues a warning and immediately sets `password_first_login` to FALSE.
--         - **Subsequent Login Enforcement:** If `password_reset_required` is TRUE and `password_first_login` is FALSE, it raises a hard EXCEPTION, preventing login until the password is changed.
--       - **`passcheck_hook`:**
--         - **Bad Password Check:** Integrates a new check using `password_check.is_bad_password()` to reject passwords found in the `bad_passwords` list (PCI DSS 8.3.8 Good Practice).
--         - **New User Initialization:** For newly created users, it sets `password_reset_required` and `password_first_login` to TRUE, initiating the forced change flow.
--         - **Flag Clearance:** Upon a successful password change, it now explicitly clears both `password_reset_required` and `password_first_login` flags.
--         - **Clarity Improvement:** Incorporates `#variable_conflict use_column` for improved readability and to resolve naming ambiguities between function parameters and table columns.
--
--   4.  **NEW Helper Functions for Bad Passwords Management:**
--       - **`password_check.is_bad_password(TEXT)`:** Checks if a given plaintext password is in the `bad_passwords` list.
--       - **`password_check.add_bad_password(TEXT)`:** Adds a new plaintext password (hashed internally) to the `bad_passwords` list.
--       - **`password_check.remove_bad_password(TEXT)`:** Removes a password (by hashing its plaintext) from the `bad_passwords` list.
--
-- Compatibility: This script is compatible with PostgreSQL 16 and later.
--
-- IMPORTANT: Before running this script, ensure you have:
--   1. pci_password_check_rules version 0.5 installed.
--   2. A clear understanding of the new first-time login flow and the implications of the bad passwords list.

-- To uninstall this update path, if needed:
-- SELECT pgtle.uninstall_update_path('pci_password_check_rules', '0.5','0.6');

SELECT
	pgtle.install_update_path (
		'pci_password_check_rules', -- Name of your custom pg_tle extension
		'0.5',                      -- The version this update path is from
		'0.6',                      -- The version this update path goes to (new version)
		$_pgtle_$

  -- password_check.user_login_activity Table
  -- Purpose: This table serves as the central repository for tracking user login attempts and activity.
  -- It stores information essential for implementing both account lockout and inactive account management.
  --
  -- Columns:
  --   username (TEXT): The name of the PostgreSQL user/role. Primary key.
  --   last_successful_login (TIMESTAMPTZ): Timestamp of the user's last successful authentication.
  --                                        Used for tracking inactivity (PCI DSS 8.2.6).
  --   failed_attempts (INTEGER): Counter for consecutive failed login attempts. Resets on successful login.
  --                               Used for account lockout logic (PCI DSS 8.3.4).
  --   last_activity (TIMESTAMPTZ): Timestamp of the last known activity. Can be updated more broadly
  --                                than just login if granular activity tracking is desired.
  --   password_reset_required (BOOLEAN): NEW! Flag indicating if the user must change their password on next login (PCI DSS 8.3.6).
  --   password_first_login (BOOLEAN): NEW! Flag indicating if this is the user's first login after a pwd change.
  ALTER TABLE password_check.user_login_activity
    ADD COLUMN IF NOT EXISTS password_reset_required BOOLEAN DEFAULT FALSE NOT NULL, --NEW! Flag indicating if the user must change their password on next login (PCI DSS 8.3.6).
    ADD COLUMN IF NOT EXISTS password_first_login BOOLEAN DEFAULT FALSE NOT NULL; --NEW! Flag indicating if this is the user's first login after a pwd change. (PCI DSS 8.3.6).
-- NOTE: ADD 1 MORE COLUMN TO CONTROL IF ITS THE FIRST LOGIN.
-- IF FIRST_LOGIN = TRUE AND PASSWORD_RESET_REQUIRED = TRUE -> ALLOW THE USER TO CONNECT SO IT CAN CHANGE THE PASSWORD.
-- UPDATE FIRST_LOGIN TO FALSE AFTER.
-- IF ON THE NEXT CONNECTION FIRST_LOGIN IS FALSE AND PASSWORD_RESET_REQUIRED IS TRUE, RAISE EXCEPTION.


  -- password_check.bad_passwords Table
  -- Purpose: This table stores cryptographic hashes of commonly known weak, compromised,
  -- or vendor-default passwords. It is used by the passcheck_hook to prevent users
  -- from setting passwords that are easily guessable or have been exposed in data breaches,
  -- directly supporting PCI DSS Requirement 8.3.8 (Good Practice).
  --
  -- Columns:
  --   password_hash (TEXT): The cryptographic hash of a known bad password. This is the primary key.
  --                         It MUST be hashed using the same algorithm (e.g., Blowfish via crypt())
  --                         and salt generation method as user passwords for direct comparison.
  --                         Salt used: $2a$06$uDrK/2blP99mE1qXATTJce
  --   source (TEXT): An optional field indicating where the bad password entry originated
  --                  (e.g., 'common_weak', 'vendor_default', 'breached_list', 'manual').
  CREATE TABLE IF NOT EXISTS password_check.bad_passwords (
    password_hash TEXT PRIMARY KEY, -- Stores the hash of the bad password
    source TEXT DEFAULT 'manual'
  );


-- Initial Population of password_check.bad_passwords Table
-- Purpose: This INSERT statement populates the `password_check.bad_passwords` table
--          with a pre-compiled list of cryptographic hashes for commonly known weak,
--          default, or easily guessable passwords. This data is essential for the
--          `passcheck_hook` to prevent users from setting insecure passwords,
--          thereby directly supporting the "Good Practice" outlined in PCI DSS Requirement 8.3.8.
--
-- Details:
--   - The passwords included in this list are derived from common default credentials
--     and frequently used weak passwords found in various security advisories and
--     breached password compilations.
--   - https://datarecovery.com/rd/default-passwords/
--   - Each plaintext password has been securely hashed using PostgreSQL's `crypt()`
--     function with the specific Blowfish salt: `$2a$06$uDrK/2blP99mE1qXATTJce`.
--     This ensures that the stored hashes are directly comparable with passwords
--     checked by the `password_check.is_bad_password` function.
--   - The `source` column is set to 'common_default' for all entries in this initial population,
--     indicating their origin as broadly recognized insecure defaults.
--   - The `ON CONFLICT (password_hash) DO NOTHING` clause is included to prevent errors
--     if this statement is executed multiple times, ensuring only unique hashes are added.
--
-- Usage:
--   This provides a foundational set of disallowed passwords for your security policy.
--   The list can be expanded later using the `password_check.add_bad_password()` function.
insert into password_check.bad_passwords
select * from (values
 ('$2a$06$uDrK/2blP99mE1qXATTJcefCUe3vYLWF.pLoDBDLuXUCUJkBOg3/i', 'common_default'),
 ('$2a$06$uDrK/2blP99mE1qXATTJcecOQVkt5AN8zYvpg7xFvKcrbrSXW7f.e', 'common_default'),
 ('$2a$06$uDrK/2blP99mE1qXATTJceZmEOHr0K/A7j5p4u9mHhgRu70.WixkK', 'common_default'),
 ('$2a$06$uDrK/2blP99mE1qXATTJce8dOgDeegkt.NJ.rlmtNbkDfqFZMJJui', 'common_default'),
 ('$2a$06$uDrK/2blP99mE1qXATTJceBgE8zpglb40mPrV97/c9z3hW4Rx2CL.', 'common_default'),
 ('$2a$06$uDrK/2blP99mE1qXATTJcez44CO2jCYuf1CDXSYmln8OBNZ4ECVkC', 'common_default'),
 ('$2a$06$uDrK/2blP99mE1qXATTJceSmMXnGJeTq9TY6VanjrM7GfMI6qEwAO', 'common_default'),
 ('$2a$06$uDrK/2blP99mE1qXATTJcerUrWGNn1DXx.gnF.d59hxLOQnqOo5AO', 'common_default'),
 ('$2a$06$uDrK/2blP99mE1qXATTJcesc2Q/FRds/w.pIrUND2lmfOimm5AGt6', 'common_default'),
 ('$2a$06$uDrK/2blP99mE1qXATTJcek2VEwIRS72D6.xzHGb6zWSCdnRBT6AC', 'common_default'),
 ('$2a$06$uDrK/2blP99mE1qXATTJcemwTaAU2mO9EzqmZKoH84iyq3GNQes9C', 'common_default'),
 ('$2a$06$uDrK/2blP99mE1qXATTJceQzPKf1wk5RiAnwA8VK60elvWCmDU4ga', 'common_default'),
 ('$2a$06$uDrK/2blP99mE1qXATTJce/QhnfDLqzckYucMz3AiN4fUcntpQuLW', 'common_default'),
 ('$2a$06$uDrK/2blP99mE1qXATTJce8nErzHem7ZGrFFLHlGhXhuAjXfBnnZO', 'common_default'),
 ('$2a$06$uDrK/2blP99mE1qXATTJce.4bHJWpqU0SIrE1feH5DpW9lp.9UuT6', 'common_default'),
 ('$2a$06$uDrK/2blP99mE1qXATTJceJPsvAvKmlLdXyWWn/CVY9sZMfidC8MW', 'common_default'),
 ('$2a$06$uDrK/2blP99mE1qXATTJcecyc6Xeq8ZpIeYj4qgploerw1TM2win.', 'common_default'),
 ('$2a$06$uDrK/2blP99mE1qXATTJceu8G7WGsRlr0hnH3M.KaRxRzn.oWUyIa', 'common_default'),
 ('$2a$06$uDrK/2blP99mE1qXATTJceBsQ.jN0MlNC5PSy3i9BnllbU0VCcnQe', 'common_default'),
 ('$2a$06$uDrK/2blP99mE1qXATTJce9APofbmq3a1985FBrzxe8VTnF7xLHKq', 'common_default'),
 ('$2a$06$uDrK/2blP99mE1qXATTJce//XhVCoOBf9nufGIEQnWzdVGZYhJlMi', 'common_default'),
 ('$2a$06$uDrK/2blP99mE1qXATTJceLNxVssmF0M4Jc0669zSpK2MjP9QlaLq', 'common_default'),
 ('$2a$06$uDrK/2blP99mE1qXATTJceitTXB6FrigUjJPjIHJqZMEToWqjnaUa', 'common_default'),
 ('$2a$06$uDrK/2blP99mE1qXATTJcev1DfHztPbZHrj6dmh82BQp9nrZIalTa', 'common_default'),
 ('$2a$06$uDrK/2blP99mE1qXATTJceFJxva./sM8R9bX9p4e2Svo52tAehJI.', 'common_default'),
 ('$2a$06$uDrK/2blP99mE1qXATTJceFl4Xtkeeph72/XKEncA2oL82KO.ARjm', 'common_default'),
 ('$2a$06$uDrK/2blP99mE1qXATTJceapoXJbCH6uvjpxVxZ3gNIrYx6JT8yb6', 'common_default'),
 ('$2a$06$uDrK/2blP99mE1qXATTJcerZ40sk2VkLMMATa3AWdxnDaC.QTjHGa', 'common_default'),
 ('$2a$06$uDrK/2blP99mE1qXATTJcefZZUMaqcVkirSCMF6v6AHrq9hQ4hEqa', 'common_default'),
 ('$2a$06$uDrK/2blP99mE1qXATTJceoSIvcb4UyBaYErBesRwwSzadE2QU7W6', 'common_default'),
 ('$2a$06$uDrK/2blP99mE1qXATTJceO.dRapbG.sf35USYuefkxYJGWZIJVSi', 'common_default'),
 ('$2a$06$uDrK/2blP99mE1qXATTJceNCW2UQ6Bndb0EVAY8tDAcu2knThNhx6', 'common_default'),
 ('$2a$06$uDrK/2blP99mE1qXATTJceFf9J1FbfTMwMcKsCPqHPscY/CsQLI.m', 'common_default'),
 ('$2a$06$uDrK/2blP99mE1qXATTJce0doI9Ttlc/6MNRQgo6lZVxP6FWyNrQi', 'common_default'),
 ('$2a$06$uDrK/2blP99mE1qXATTJce42jnTDJ5Ca2huskoz5xnmi/1b17LnmS', 'common_default'),
 ('$2a$06$uDrK/2blP99mE1qXATTJcesokKMofdgzAay2BbifP5wRB5wh3r6/e', 'common_default'),
 ('$2a$06$uDrK/2blP99mE1qXATTJce7dd0zjQ59K0HZUB4t2NMbez4y45XCsS', 'common_default'),
 ('$2a$06$uDrK/2blP99mE1qXATTJceLnt/PhUsrZ4UdaFOkp.OxZc78jve56C', 'common_default'),
 ('$2a$06$uDrK/2blP99mE1qXATTJceegrTeOgJgydd2kY0ldFrqjXSy45HFZq', 'common_default'),
 ('$2a$06$uDrK/2blP99mE1qXATTJceM.lRj5JxklEZkG6rJiSHRWCLXDMizxS', 'common_default'),
 ('$2a$06$uDrK/2blP99mE1qXATTJcefqeSiQke0Vbq.4rPsspYeYkfkfqhM.6', 'common_default'),
 ('$2a$06$uDrK/2blP99mE1qXATTJceOkBn8Mp8zkOj1ZzlTXnr8e8yzXjEgLK', 'common_default'),
 ('$2a$06$uDrK/2blP99mE1qXATTJcet12eytl..Uhs6lGT4dPg/VninBNWb6.', 'common_default'),
 ('$2a$06$uDrK/2blP99mE1qXATTJceNT9bOZY9ckJNp.y9PmIUThnqnXrYW7C', 'common_default'),
 ('$2a$06$uDrK/2blP99mE1qXATTJcecYh1CXGeEtkKqymPmQvccw3ybalrzV2', 'common_default'),
 ('$2a$06$uDrK/2blP99mE1qXATTJceZ1/jjF2RukplVdr93qbdMbK9NPkCISu', 'common_default'),
 ('$2a$06$uDrK/2blP99mE1qXATTJcemL2k6YXEdptNzXO7u0QBpjv44lcmPcq', 'common_default'),
 ('$2a$06$uDrK/2blP99mE1qXATTJceGzQQxFBnCUyJUfphA4tAN8m2MJz.5Fq', 'common_default'),
 ('$2a$06$uDrK/2blP99mE1qXATTJce8/aoX5D8DAPNfKz/Kxse8wO4UIF72cy', 'common_default'),
 ('$2a$06$uDrK/2blP99mE1qXATTJceqy6M7NZ4zxirPIOPlTtDZqS2x2Yebny', 'common_default'),
 ('$2a$06$uDrK/2blP99mE1qXATTJceU84xqI3r.igWQp9Fcf.u58.o6809W0K', 'common_default'),
 ('$2a$06$uDrK/2blP99mE1qXATTJceDkdSFyXJiuOwGT8RsLOXtE2fuAsfc4S', 'common_default'),
 ('$2a$06$uDrK/2blP99mE1qXATTJce37L5/GwM1ONEVKQ0gp5NlgZwfE5Fc5G', 'common_default'),
 ('$2a$06$uDrK/2blP99mE1qXATTJce6Wtsl2lgjjNJT2UbfWruADljrsrJ42i', 'common_default'),
 ('$2a$06$uDrK/2blP99mE1qXATTJcecDSEYr89G4/mhXDcagwo25KWybi.LjW', 'common_default'),
 ('$2a$06$uDrK/2blP99mE1qXATTJce242VFEhUC9Sz6GM/Ifrdid6wDUKa5/i', 'common_default'),
 ('$2a$06$uDrK/2blP99mE1qXATTJcelDH0xSPAVQaEtzDK9E0VtWGG8/KQadq', 'common_default'),
 ('$2a$06$uDrK/2blP99mE1qXATTJcevD8dOTQSX18C4ajx2jnapv6DZ75KHvu', 'common_default'),
 ('$2a$06$uDrK/2blP99mE1qXATTJceVXk2GJyB51C1EWfoxLt2Gm0AiG70zQ6', 'common_default'),
 ('$2a$06$uDrK/2blP99mE1qXATTJce5ePLjeGQXQRE00WlvkVnGccVmc.RtDK', 'common_default'),
 ('$2a$06$uDrK/2blP99mE1qXATTJceJd34kIlTlCFAD2iPMD5xe8t6imbxDO6', 'common_default'),
 ('$2a$06$uDrK/2blP99mE1qXATTJceYtWy6EltlJEc6oz7B2P7TezuRb7D/cG', 'common_default'),
 ('$2a$06$uDrK/2blP99mE1qXATTJce5wPQmlfKxQISfQhmScgC09teDOqVF4e', 'common_default'),
 ('$2a$06$uDrK/2blP99mE1qXATTJcejyvh1NQAu8heAZ4Ec1J9x7GSidxEFM.', 'common_default'),
 ('$2a$06$uDrK/2blP99mE1qXATTJcegnweMfkvs/VfZ6rIYfJU7JPlx8KdC9W', 'common_default'),
 ('$2a$06$uDrK/2blP99mE1qXATTJceQePh4wk7KdM8coisLXGqn2szZPQfeQ2', 'common_default'),
 ('$2a$06$uDrK/2blP99mE1qXATTJceZulqd7q4ynIWGsu/Lp8tQ/lPT5AhvpO', 'common_default'),
 ('$2a$06$uDrK/2blP99mE1qXATTJcegx4edQk.nXEoM/NDbUaX0W7Q4Ex0efO', 'common_default'),
 ('$2a$06$uDrK/2blP99mE1qXATTJceP18z9FVJb6qoIFMMYxWhWCShJW1OkVe', 'common_default'),
 ('$2a$06$uDrK/2blP99mE1qXATTJcezq1kOQeGQh6MdHAHO9.t19jm3SNGn8e', 'common_default'),
 ('$2a$06$uDrK/2blP99mE1qXATTJcemV2z/0/9xHIDZp5nLB8snxG8Hksi5fO', 'common_default'),
 ('$2a$06$uDrK/2blP99mE1qXATTJceLvet6KmqgfntB54wKC5ARdRZ8cLS87.', 'common_default'),
 ('$2a$06$uDrK/2blP99mE1qXATTJce0mV/Kgc6e7dQbz8aJ/ogZDxL5160ATC', 'common_default'),
 ('$2a$06$uDrK/2blP99mE1qXATTJceIczL1X/ltI7N8XHlxgY2BgeBuHXYhOS', 'common_default'),
 ('$2a$06$uDrK/2blP99mE1qXATTJceD9oEzIL4ONbDUqTYLc3XavQ5Pz8Lw/y', 'common_default'),
 ('$2a$06$uDrK/2blP99mE1qXATTJceKK7pfl4gk1sPnjemWiu1fZKmpTXfsD2', 'common_default'),
 ('$2a$06$uDrK/2blP99mE1qXATTJce6Eh0.thcICanwjBwRKOe8w4cVradAa6', 'common_default'),
 ('$2a$06$uDrK/2blP99mE1qXATTJceFcUZ5CCrBWrd3n2vpAY9QBK75Rq.WPa', 'common_default'),
 ('$2a$06$uDrK/2blP99mE1qXATTJcejx.fxP2C/hhqMca8W.dTK0/NsJcXK8y', 'common_default'),
 ('$2a$06$uDrK/2blP99mE1qXATTJceNaNKa64HSlCTR8/mKSguxRlw4NkzXQi', 'common_default'),
 ('$2a$06$uDrK/2blP99mE1qXATTJceFPKBD1bSh4hnKBKO98z06OFXXArTkHS', 'common_default'),
 ('$2a$06$uDrK/2blP99mE1qXATTJceIHZVx2skA8GgLbLEkmga39JSXMHAL6q', 'common_default'),
 ('$2a$06$uDrK/2blP99mE1qXATTJcePu1WtceKGOtaLNJveRCsol/F..j5yQK', 'common_default'),
 ('$2a$06$uDrK/2blP99mE1qXATTJceSUxgeO0S5lsJ3fEk7I9J2BmuQ.i/mm.', 'common_default'),
 ('$2a$06$uDrK/2blP99mE1qXATTJceSmM.apeqnw02lT7eAgI2q26wZQMgkMS', 'common_default'),
 ('$2a$06$uDrK/2blP99mE1qXATTJceg4DCT7NnmRtHwQ0LTCSloy.a5GD.lIO', 'common_default'),
 ('$2a$06$uDrK/2blP99mE1qXATTJceBqKXgN4oxg3iOhJFAtjLXo6C7fd5at.', 'common_default'),
 ('$2a$06$uDrK/2blP99mE1qXATTJcewDM/hYoXdb5K4bKi/2IsoykzVFhdACm', 'common_default'),
 ('$2a$06$uDrK/2blP99mE1qXATTJceYpjI2FblcmNBDuG5RZ3h4k8B4e89pE6', 'common_default'),
 ('$2a$06$uDrK/2blP99mE1qXATTJcejJDxd75w6TFmOdBJ671unFtgw1uml2.', 'common_default'),
 ('$2a$06$uDrK/2blP99mE1qXATTJcevUm0XIFEe9onExbNCxH2ih9pxU4U49O', 'common_default'),
 ('$2a$06$uDrK/2blP99mE1qXATTJce2w4bGGyVcq2hOnxLLMn3Y.BIBViKAwu', 'common_default'),
 ('$2a$06$uDrK/2blP99mE1qXATTJcenNcnuFLXJXZyZU1QisNGhRuDD5htzWy', 'common_default'),
 ('$2a$06$uDrK/2blP99mE1qXATTJce95p16UT2TVjiMZ2TdNtMH5.wDWYZ7dG', 'common_default'),
 ('$2a$06$uDrK/2blP99mE1qXATTJceVd5iyCwaLy9/qlTTNOmhjBZcrRB5TZK', 'common_default'),
 ('$2a$06$uDrK/2blP99mE1qXATTJceUIKhO.EWWhCjBBddu93aDyllHE4jQ6u', 'common_default'),
 ('$2a$06$uDrK/2blP99mE1qXATTJcexYnVKuOxgNcC39XZQn0NvyiL0JsdkAq', 'common_default'),
 ('$2a$06$uDrK/2blP99mE1qXATTJceu4M3FRGInsCzioLUN/hd/Kn/wLtAmkW', 'common_default'),
 ('$2a$06$uDrK/2blP99mE1qXATTJceSYqABPZ7OtRCLt.DDJVqsE1mKIzaSeK', 'common_default'),
 ('$2a$06$uDrK/2blP99mE1qXATTJceWNTg1iEmvEktdNZKCqJWRjIx.ybe5Vu', 'common_default'),
 ('$2a$06$uDrK/2blP99mE1qXATTJcePljFUpDH2khVuY4DL7iveeFIRVsUuH6', 'common_default'),
 ('$2a$06$uDrK/2blP99mE1qXATTJcePo70G2cFWOsiBqkJGV05yirntmJTouG', 'common_default'),
 ('$2a$06$uDrK/2blP99mE1qXATTJceOWghfv3EQeiVcAxWyMm3QBgj2KQjiJK', 'common_default'),
 ('$2a$06$uDrK/2blP99mE1qXATTJceo.dpX5/s/vN0kAfltHaC/BFA5rm1LtC', 'common_default'),
 ('$2a$06$uDrK/2blP99mE1qXATTJceBwRe0kLqMyXVE3c9sSVLr0WZ9FlYsFW', 'common_default'),
 ('$2a$06$uDrK/2blP99mE1qXATTJce6Xe2XGwrRlvi1JF9pRza16GBOYLfqJu', 'common_default'),
 ('$2a$06$uDrK/2blP99mE1qXATTJcebrcqf5DNnd2dwSCdCD9m8KnoFOY0wgO', 'common_default'),
 ('$2a$06$uDrK/2blP99mE1qXATTJceZYqQMbEkUHubHZ01LT4NfevTJ5mjDEu', 'common_default'),
 ('$2a$06$uDrK/2blP99mE1qXATTJcec7ifEOWH6NNCF1yshvDl892qLZDSl2a', 'common_default'),
 ('$2a$06$uDrK/2blP99mE1qXATTJcehBffD904UdfPkGLMNi7D6bgjYy8V8/W', 'common_default'),
 ('$2a$06$uDrK/2blP99mE1qXATTJceB95hoE1qrpxN15FVeE07wuAaYFc0nM6', 'common_default'),
 ('$2a$06$uDrK/2blP99mE1qXATTJce9hbV2gyZnlU5c9iOFkV/JqrF0hQxkmi', 'common_default'),
 ('$2a$06$uDrK/2blP99mE1qXATTJcejsGe9ALFBMYEXx5MqzApev/rMhJ7oZS', 'common_default'),
 ('$2a$06$uDrK/2blP99mE1qXATTJcezCoHwxldcwLumjx51a1RHpwthou1/ty', 'common_default'),
 ('$2a$06$uDrK/2blP99mE1qXATTJceFNvneKSJjul51H4R6zTt668X6XE81m6', 'common_default'),
 ('$2a$06$uDrK/2blP99mE1qXATTJce6GR9LGNFNdNNaMBACnQGWSAWYrqjslq', 'common_default'),
 ('$2a$06$uDrK/2blP99mE1qXATTJceCfrxW/7Z6BVaY6f/in/CT58DCxI.ESK', 'common_default'),
 ('$2a$06$uDrK/2blP99mE1qXATTJceWf5Vm18zHt4EPQCdXTp5YjYqbeILp8y', 'common_default'),
 ('$2a$06$uDrK/2blP99mE1qXATTJceSg55og4whelrl921UYHhiNDPlgCLrRu', 'common_default'),
 ('$2a$06$uDrK/2blP99mE1qXATTJceOVdfqU//ARv31LOk/Lm/1OEGbTVjIBm', 'common_default'),
 ('$2a$06$uDrK/2blP99mE1qXATTJcegxt/S9uFLFv9vvVpSN4Pc/bLgDEnJ2C', 'common_default'),
 ('$2a$06$uDrK/2blP99mE1qXATTJce8uCu2zbAHhpgCjGLjRlGN9nh1Fr055C', 'common_default'),
 ('$2a$06$uDrK/2blP99mE1qXATTJcehbonXMs6fXZuaoP7LSXR6Vv5ncNhg12', 'common_default'),
 ('$2a$06$uDrK/2blP99mE1qXATTJceRh9wLppBgxUDhuV2RWegKRFTMOFcJwa', 'common_default'),
 ('$2a$06$uDrK/2blP99mE1qXATTJceOvAHsI6f62/dQhN8xasAjOJT2ewO3VS', 'common_default'),
 ('$2a$06$uDrK/2blP99mE1qXATTJcelMj1pBmLsLTzQtVFcGGtz7Fuz2.TRwa', 'common_default'),
 ('$2a$06$uDrK/2blP99mE1qXATTJceaKXsx.Oq7sBAD//G1CEepVKfe0p3SpW', 'common_default'),
 ('$2a$06$uDrK/2blP99mE1qXATTJcex4RycKdF7pAIi.AYOCMu67BD67MHUqC', 'common_default'),
 ('$2a$06$uDrK/2blP99mE1qXATTJced2uS4L.vStVS4joG6s/W3sbfw5wAad6', 'common_default'),
 ('$2a$06$uDrK/2blP99mE1qXATTJceFucGqEZZQ6hHSHJZGgLYw7K0P.w336C', 'common_default'),
 ('$2a$06$uDrK/2blP99mE1qXATTJceO47DhivrTikNIZLT0zl./ZoPdH6B8be', 'common_default'),
 ('$2a$06$uDrK/2blP99mE1qXATTJceWfAxxVtLGUYt1Ffq9jsFmnAtZgDBsqy', 'common_default'),
 ('$2a$06$uDrK/2blP99mE1qXATTJcevyaMl1JPRf4lVU6kkNe31UW5y2S4eAK', 'common_default'),
 ('$2a$06$uDrK/2blP99mE1qXATTJcem95lEJci6h5FT6PGQIZ55J5LEhh9JUy', 'common_default'),
 ('$2a$06$uDrK/2blP99mE1qXATTJceNV/Mqye6EcJOrzd8UzvPhVolWjajokm', 'common_default'),
 ('$2a$06$uDrK/2blP99mE1qXATTJcejpAuMpxrZmZ20DHX4PcSj5X033Jhqfi', 'common_default'),
 ('$2a$06$uDrK/2blP99mE1qXATTJceQR3XDqhwkkEA3p1xhwUPLpD6r//dhra', 'common_default'),
 ('$2a$06$uDrK/2blP99mE1qXATTJceyNGZnicSTi0iCm66rqO8jzAnq3G3Y1O', 'common_default'),
 ('$2a$06$uDrK/2blP99mE1qXATTJcexrW.Foxx2.iiT9NoDyApS.6A/XolTEG', 'common_default'),
 ('$2a$06$uDrK/2blP99mE1qXATTJce.LHMMan0wB56OwK0BSPztOHMmvnn0D.', 'common_default'),
 ('$2a$06$uDrK/2blP99mE1qXATTJce9u9sKsdyVGKDY7rpwi1eJ/xkBooPIc.', 'common_default'),
 ('$2a$06$uDrK/2blP99mE1qXATTJceOFmAXkXbRrkjFDFYdNC3OVDu0CaCjSS', 'common_default'),
 ('$2a$06$uDrK/2blP99mE1qXATTJceHeQP8KnT93WoQeWh8rMHrStsl42lPZO', 'common_default'),
 ('$2a$06$uDrK/2blP99mE1qXATTJcenz7/HcsqaAurjuXlV57/6/Sv/KOh.da', 'common_default'),
 ('$2a$06$uDrK/2blP99mE1qXATTJceSZwi3NmDI.VRiBTXTLfFBzrEASqEVvy', 'common_default'),
 ('$2a$06$uDrK/2blP99mE1qXATTJceAKC5bWPCAhV8L48b0fxlXadsm/G4TBi', 'common_default'),
 ('$2a$06$uDrK/2blP99mE1qXATTJceiiYaAZiQof8TMbD.ypQ.a.8ev4itVEu', 'common_default'),
 ('$2a$06$uDrK/2blP99mE1qXATTJcefnCtYkXzsArOaC/qCyMygqcb2WmwClG', 'common_default'),
 ('$2a$06$uDrK/2blP99mE1qXATTJcejJyEclRJtYXKp5EMX1M92OsD.2OyPrq', 'common_default'),
 ('$2a$06$uDrK/2blP99mE1qXATTJce/UEJADtkxvqerXwMA4xeqtRVoVcwWNi', 'common_default'),
 ('$2a$06$uDrK/2blP99mE1qXATTJceAGs2YSJNy.sNWcyMhsgndESZlVNfUqe', 'common_default'),
 ('$2a$06$uDrK/2blP99mE1qXATTJceTEFlDs76ucpTuU25g6IbaY5tXzk7jnC', 'common_default'),
 ('$2a$06$uDrK/2blP99mE1qXATTJceL/.P2RLWz2ozq1hmzh2fPc7mbGGXclO', 'common_default'),
 ('$2a$06$uDrK/2blP99mE1qXATTJceGSjINfOEYpmdSdLogz3WaleZklBGb5y', 'common_default'),
 ('$2a$06$uDrK/2blP99mE1qXATTJceO6m.MU.aEqXZdElLUj3ElkisKj.qv6y', 'common_default'),
 ('$2a$06$uDrK/2blP99mE1qXATTJceXBw15y1BUxbXqYYeJjtOKl2J8Cbj3V2', 'common_default'),
 ('$2a$06$uDrK/2blP99mE1qXATTJceyyOayVYo1nPIVa0cN61Cz61fJLDzKzW', 'common_default'),
 ('$2a$06$uDrK/2blP99mE1qXATTJceGzVReXN66h447Uo6CGFAkjpG12qHsai', 'common_default'),
 ('$2a$06$uDrK/2blP99mE1qXATTJceGL3Dh8mtMyrClF9hI0oYnEc1INOOZgy', 'common_default'),
 ('$2a$06$uDrK/2blP99mE1qXATTJceXj6VUCaiHigZ4MISQPs3WduNAwkMowi', 'common_default'),
 ('$2a$06$uDrK/2blP99mE1qXATTJcen0SJCDqjBWGj6E37eZxoXUA.zzeFubi', 'common_default'),
 ('$2a$06$uDrK/2blP99mE1qXATTJcezGpMqI8EG79BWaUGGJvuLFfRgez4DcG', 'common_default'),
 ('$2a$06$uDrK/2blP99mE1qXATTJcetuMXDQVphyZISrM77YnJftZfTXT0ctW', 'common_default'),
 ('$2a$06$uDrK/2blP99mE1qXATTJce54rRR7o5p6zEzEqyoV5o.1MEJ6.7Gza', 'common_default'),
 ('$2a$06$uDrK/2blP99mE1qXATTJce7D83xYxM7mkdrkXNhKUXNsvrgBwXQZy', 'common_default'),
 ('$2a$06$uDrK/2blP99mE1qXATTJce4Q5OV9HwLEl.5RKzWj7c94l2SE4ZzBq', 'common_default'),
 ('$2a$06$uDrK/2blP99mE1qXATTJcekawUq9anSJBYyGdlEQV7FBfusXQzUXm', 'common_default'),
 ('$2a$06$uDrK/2blP99mE1qXATTJce58Rgo.k0N3SvxrwM6r7TfHOV.hkAyPy', 'common_default'),
 ('$2a$06$uDrK/2blP99mE1qXATTJceo0zEZUoTWnO5o56XALpD2.7qIqBf6.S', 'common_default'),
 ('$2a$06$uDrK/2blP99mE1qXATTJce2atmMX2/jN1hEiSIbT12epgmC.Qt8ey', 'common_default'),
 ('$2a$06$uDrK/2blP99mE1qXATTJcec9S01TDZyTIPlDyF8BW3L25h1E3yfNW', 'common_default'),
 ('$2a$06$uDrK/2blP99mE1qXATTJcednG2CFj2GsnAOUqSAyepXslanXairsq', 'common_default'),
 ('$2a$06$uDrK/2blP99mE1qXATTJceiJNb1fhZfkxcQuVY6RWsUp2yUex5dEm', 'common_default'),
 ('$2a$06$uDrK/2blP99mE1qXATTJceXT0S.XUPd4VXqmoaNNXDRTR5psaPS9W', 'common_default'),
 ('$2a$06$uDrK/2blP99mE1qXATTJce6MCrNpc8j1phbDR8b.qtR4Hldyoc3BS', 'common_default'),
 ('$2a$06$uDrK/2blP99mE1qXATTJceQ21IODg7453JuIOfqp023154S/TSLdm', 'common_default'),
 ('$2a$06$uDrK/2blP99mE1qXATTJceO4gA9T42iJGw2PBGQYDcgP4FFboC/sm', 'common_default'),
 ('$2a$06$uDrK/2blP99mE1qXATTJce5jcEPXveahBqVzwxbBUa0nWlb8ECbG6', 'common_default'),
 ('$2a$06$uDrK/2blP99mE1qXATTJceDGa59pQNYxlWxATH1SiW8avwSX5Wqzy', 'common_default'),
 ('$2a$06$uDrK/2blP99mE1qXATTJcegNriW93iQmhattQdaok4oqKr15n461a', 'common_default'),
 ('$2a$06$uDrK/2blP99mE1qXATTJceml544GV0zxViPfMzwFwy.5.0wW94Q06', 'common_default'),
 ('$2a$06$uDrK/2blP99mE1qXATTJceDFGdd8135d/qDNN3Nu2nyuYAuz5m/HW', 'common_default'),
 ('$2a$06$uDrK/2blP99mE1qXATTJceYVxIbyed1Kowq9Blw.wgZsf4/GLq7g6', 'common_default'),
 ('$2a$06$uDrK/2blP99mE1qXATTJcectK.u0iGBQkC8ZkToNlf8A.gm.tVP/G', 'common_default'),
 ('$2a$06$uDrK/2blP99mE1qXATTJceFZBAs4zFGGu9iVwXOrW9BcAHAWgDodi', 'common_default'),
 ('$2a$06$uDrK/2blP99mE1qXATTJcexEexmt5ki2Tm5LYb6CvtmFKPS7AIc4K', 'common_default'),
 ('$2a$06$uDrK/2blP99mE1qXATTJceslk6lkHN8LgDqeoL1ZOUYV9kgGkR48u', 'common_default'),
 ('$2a$06$uDrK/2blP99mE1qXATTJceO37hsIy7ftZA0HLGu2DSlEDiPJDUEU6', 'common_default'),
 ('$2a$06$uDrK/2blP99mE1qXATTJcewIcEJvSNhZfuoyQ9iKbS1FNtXRycIgC', 'common_default'),
 ('$2a$06$uDrK/2blP99mE1qXATTJcevajvFaFFsJEjSaq2GGO8U24hn2QLUoa', 'common_default'),
 ('$2a$06$uDrK/2blP99mE1qXATTJceYXUkQ3na8mW4ftBzoTz2RN9bmgjGNX2', 'common_default'),
 ('$2a$06$uDrK/2blP99mE1qXATTJceB/wqX3d.IkmRzR2tnN.j/IuzULh7/MW', 'common_default'),
 ('$2a$06$uDrK/2blP99mE1qXATTJcebs/AzEBN2PJAgf.0Wm8ZjXwUWkFLo96', 'common_default'),
 ('$2a$06$uDrK/2blP99mE1qXATTJcerE7CM5uetrYsJDSz.D/fMfKXTXRmasi', 'common_default'),
 ('$2a$06$uDrK/2blP99mE1qXATTJceSBST9aq72VmT2NLYiz4K8gbl6gOZq4G', 'common_default'),
 ('$2a$06$uDrK/2blP99mE1qXATTJceU8nD4Z8boSEjlUD2i98/hUEXTJuvU3O', 'common_default'),
 ('$2a$06$uDrK/2blP99mE1qXATTJceBcZyw1IXOhr9vg8lj5SfEdD1MwG6lyC', 'common_default'),
 ('$2a$06$uDrK/2blP99mE1qXATTJceZdonc6WmdquEWErBDcUE/abr1ADhTya', 'common_default'),
 ('$2a$06$uDrK/2blP99mE1qXATTJcetTRW5e/AamMrEJB7q/QH7FOozZSUi4C', 'common_default'),
 ('$2a$06$uDrK/2blP99mE1qXATTJceBN8e7LnH5J0RcrA1NXtKkWKNFirXvvC', 'common_default'),
 ('$2a$06$uDrK/2blP99mE1qXATTJceB6EXnsx39OSMl4pMUFRN8hHOsxa3uj6', 'common_default'),
 ('$2a$06$uDrK/2blP99mE1qXATTJce1KEGfPEwaAJfV8r4LJJcsn0SoF09VbK', 'common_default'),
 ('$2a$06$uDrK/2blP99mE1qXATTJcejjqvaBcw33w1xD8a5upufSIE9oVfYW6', 'common_default'),
 ('$2a$06$uDrK/2blP99mE1qXATTJcetqplSakDCNw4Gkn4RZDDBNhcz5PHDMC', 'common_default'),
 ('$2a$06$uDrK/2blP99mE1qXATTJceTffo.AehYPm5E3.mXYcIJx7UXPuTqze', 'common_default'),
 ('$2a$06$uDrK/2blP99mE1qXATTJceCkPso979YbsowR9idENOlZ3WG.YfhM.', 'common_default'),
 ('$2a$06$uDrK/2blP99mE1qXATTJceWLYGc4k5VdDtlUDyhEeacEd7T.UF8PS', 'common_default'),
 ('$2a$06$uDrK/2blP99mE1qXATTJceWeGCkM3unTrdFTaJMzLGxFmdcpLvDyO', 'common_default'),
 ('$2a$06$uDrK/2blP99mE1qXATTJce2IDMlQb3xGhHNqiR2ucdzylHRuNhYQC', 'common_default'),
 ('$2a$06$uDrK/2blP99mE1qXATTJceE9LxWRKFmuxoLNrdF1a0HbIAv6NlyPa', 'common_default'),
 ('$2a$06$uDrK/2blP99mE1qXATTJceTjt7o09mzhKpqUlyijf8VVBEW8oxIsW', 'common_default'),
 ('$2a$06$uDrK/2blP99mE1qXATTJceUwex/udOrYsn/v/HHZXTt6l/btZnr.2', 'common_default'),
 ('$2a$06$uDrK/2blP99mE1qXATTJceM13P0AudDiL3bY2.mc82/f8naSq073a', 'common_default'),
 ('$2a$06$uDrK/2blP99mE1qXATTJceZEF7PRgIojLS0LIA6Q1KPWRvZxdqTiO', 'common_default'),
 ('$2a$06$uDrK/2blP99mE1qXATTJce9Sgljua1yFaJRsDoS.yB3DYK927VZqa', 'common_default'),
 ('$2a$06$uDrK/2blP99mE1qXATTJceLtJOBJfx0eD6pi9p5GxEjPqePSPWhTO', 'common_default'),
 ('$2a$06$uDrK/2blP99mE1qXATTJcebCP0SWOTpo5bpAZa9XLYeVed6xtk1Fe', 'common_default'),
 ('$2a$06$uDrK/2blP99mE1qXATTJceYiDzy20OVAaojeYOG6m2unQGhhexeBS', 'common_default'),
 ('$2a$06$uDrK/2blP99mE1qXATTJcejFifLSrjQJ/kN84oxbyd4kAKTPZcQc2', 'common_default'),
 ('$2a$06$uDrK/2blP99mE1qXATTJceyzY2xWCfFWXgLNI3LyJw2Yw4gFUDaFW', 'common_default'),
 ('$2a$06$uDrK/2blP99mE1qXATTJceTqbbDp8p0siw8fdQXrPJHHZ662PErf6', 'common_default'),
 ('$2a$06$uDrK/2blP99mE1qXATTJcePTCMZQREfFrK1rLZ4QwZuDy4XeUWG0q', 'common_default'),
 ('$2a$06$uDrK/2blP99mE1qXATTJceoRC825BBoWa3DJKrPfySypM2TuTI2We', 'common_default'),
 ('$2a$06$uDrK/2blP99mE1qXATTJceLm/p6VxZvAphFEXbCsYJOGTUUquHjvm', 'common_default'),
 ('$2a$06$uDrK/2blP99mE1qXATTJceYacIoqbTxY9lnt3Egg54jIcdVZ4UQIq', 'common_default'),
 ('$2a$06$uDrK/2blP99mE1qXATTJceo0len6Le90B5tL4c53g2zRzF7b4Wzue', 'common_default'),
 ('$2a$06$uDrK/2blP99mE1qXATTJce9DqOf9asHVcdfAFuiLZGEJihRoxOTHa', 'common_default'),
 ('$2a$06$uDrK/2blP99mE1qXATTJceHWQCLS6JyZx82y03nwcvcCDeTYMZcaq', 'common_default'),
 ('$2a$06$uDrK/2blP99mE1qXATTJcevryCD5.L8gj0vpk4/vLrVVgWg3/FVdm', 'common_default'),
 ('$2a$06$uDrK/2blP99mE1qXATTJcek3bTX090AdrxaELLY4pcg79iG.c0iiG', 'common_default'),
 ('$2a$06$uDrK/2blP99mE1qXATTJce6se/mcd8EUh6DiSkBzPmILqrVr.AAj.', 'common_default'),
 ('$2a$06$uDrK/2blP99mE1qXATTJcex3R5KWcB7LVaBgEuQq8BuUC4w9kQ4QG', 'common_default'),
 ('$2a$06$uDrK/2blP99mE1qXATTJce5g6BdiDhK3mrdqlXZmW3OfbWHJRzc9y', 'common_default'),
 ('$2a$06$uDrK/2blP99mE1qXATTJceDP19ANq0UeluG4jqJLtXaeJcruZdL5q', 'common_default'),
 ('$2a$06$uDrK/2blP99mE1qXATTJcegZSATAFnLMs5FX7ew6pOKeGe733iXHW', 'common_default'),
 ('$2a$06$uDrK/2blP99mE1qXATTJceW64ntmNG6vkCYlDoehIP8c8MI66s/QC', 'common_default'),
 ('$2a$06$uDrK/2blP99mE1qXATTJcesTqEbC/VqV8od/F9ktqU6OHlSckpTOy', 'common_default'),
 ('$2a$06$uDrK/2blP99mE1qXATTJceszgm/tMiGlEf4d6dRZKYhLtQDK8vLsS', 'common_default'),
 ('$2a$06$uDrK/2blP99mE1qXATTJcewd1PWwBK/R4f1xXMSAVGvaQAIGU.xia', 'common_default'),
 ('$2a$06$uDrK/2blP99mE1qXATTJceJvGAnYBd8nr9MLx9G/1RCvtYlkfUbv.', 'common_default'),
 ('$2a$06$uDrK/2blP99mE1qXATTJceRGqkax4jLMoXBjTDEqQoys3J.RiZw.u', 'common_default'),
 ('$2a$06$uDrK/2blP99mE1qXATTJce8JbDvzcaflKmzz6GgOPGXeouESXNJrm', 'common_default'),
 ('$2a$06$uDrK/2blP99mE1qXATTJce0qxpJpbstG.59GSxLGpS1X4vU3sR3S6', 'common_default'),
 ('$2a$06$uDrK/2blP99mE1qXATTJceePOclaqDBNwlYZ2dDYu0AM297FpdhIS', 'common_default'),
 ('$2a$06$uDrK/2blP99mE1qXATTJceNfhYkmu7B2ZjdFSxop9OlQUMa71ZQ8i', 'common_default'),
 ('$2a$06$uDrK/2blP99mE1qXATTJce4yA0y/XflfmbGhUlpQljTrd1AzMLTki', 'common_default'),
 ('$2a$06$uDrK/2blP99mE1qXATTJce.Ib.D9PdRL1fe0eZEbE1Q7dwLfePVJa', 'common_default'),
 ('$2a$06$uDrK/2blP99mE1qXATTJceh6FBE.BURdUQmaOFvff.M.rJCAWgI96', 'common_default'),
 ('$2a$06$uDrK/2blP99mE1qXATTJce0D/DDzkvbAX9r.4QRbcF8w0R3Ar51ri', 'common_default'),
 ('$2a$06$uDrK/2blP99mE1qXATTJceZMJWevzg6zaRE04GQkpl7QZ6tbXrjAe', 'common_default'),
 ('$2a$06$uDrK/2blP99mE1qXATTJceWSFk/JbfbQ4LvnGx6yJJX2.86f0ZaZW', 'common_default'),
 ('$2a$06$uDrK/2blP99mE1qXATTJce3YJxRwNz4mANW7LGY.lVjHs5osYQEXC', 'common_default'),
 ('$2a$06$uDrK/2blP99mE1qXATTJce0/pr.xpCTZDnCvJaqThOwHrHqkYUDTS', 'common_default'),
 ('$2a$06$uDrK/2blP99mE1qXATTJceAjefGxupCMlWwdhzZXHHSJdfmW0BGre', 'common_default'),
 ('$2a$06$uDrK/2blP99mE1qXATTJce2FW7yl9XF73jQ8Qs.9VQHYr/mu56UmO', 'common_default'),
 ('$2a$06$uDrK/2blP99mE1qXATTJcevYe0GNQrmy6IRJLD6tB2/u5gCvH.LYK', 'common_default'),
 ('$2a$06$uDrK/2blP99mE1qXATTJceHgo0DBShI6IkXaRJt.lEBgdaXl1qGoq', 'common_default'),
 ('$2a$06$uDrK/2blP99mE1qXATTJceFjZhAGFAZDAxgE2LFMrOCJTI4t4tWbq', 'common_default'),
 ('$2a$06$uDrK/2blP99mE1qXATTJceQuIsx4f/oRpQxTWJg0VH4JZOH4axk3e', 'common_default'),
 ('$2a$06$uDrK/2blP99mE1qXATTJcer0MkCvcdp5BOwFhpQOhAeQi.bdiYqa6', 'common_default'),
 ('$2a$06$uDrK/2blP99mE1qXATTJcegY9pB8.CSLVooRaIa.pa.uTIJi1uvGK', 'common_default'),
 ('$2a$06$uDrK/2blP99mE1qXATTJce2bHSqyTjUwjgI7hdPwRxcHzsTT/J5ju', 'common_default'),
 ('$2a$06$uDrK/2blP99mE1qXATTJcet3kM3ZPMl9MczsWX0xqsZisjVkQE5o2', 'common_default'),
 ('$2a$06$uDrK/2blP99mE1qXATTJce3BrxehVCV1o4AmBt0nlsEICEw955GXW', 'common_default'),
 ('$2a$06$uDrK/2blP99mE1qXATTJcezQwkGIFG1vtb55NtkfSdEHbJDVxLNIy', 'common_default'),
 ('$2a$06$uDrK/2blP99mE1qXATTJceTJaTdHBUPQoRiqXg3qX2Gs/EyUGEGBC', 'common_default'),
 ('$2a$06$uDrK/2blP99mE1qXATTJce1SFrv47iA1DWW3AFlUBHWWRDC4bVytO', 'common_default'),
 ('$2a$06$uDrK/2blP99mE1qXATTJcee3hdEyV4ioF1H/f7iQoud9hb1ULVb6C', 'common_default'),
 ('$2a$06$uDrK/2blP99mE1qXATTJceJ3h4R5JTVM0SEQ5ekQ/ys2W4aYAzn.W', 'common_default'),
 ('$2a$06$uDrK/2blP99mE1qXATTJceZqCoM1tanPXWFBJCgbnjE8h37Glbfme', 'common_default'),
 ('$2a$06$uDrK/2blP99mE1qXATTJcekxC.WUOmMIBWMoWWGkuxqOMMfBTWyqS', 'common_default'),
 ('$2a$06$uDrK/2blP99mE1qXATTJceNETSCfkI3Wjm1ALaIuN/xanFWUNWmc2', 'common_default'),
 ('$2a$06$uDrK/2blP99mE1qXATTJceTq5xpdJIxQFtD0zahkKRw1shfiBT/dW', 'common_default'),
 ('$2a$06$uDrK/2blP99mE1qXATTJcenn8MFd.1tHk2I/bssVFamsWhzUKMEnu', 'common_default'),
 ('$2a$06$uDrK/2blP99mE1qXATTJceiZd6CRivfZY3Nz.jt/a4a/HjgBvfgba', 'common_default'),
 ('$2a$06$uDrK/2blP99mE1qXATTJceRrmlVEtbjRaF3Rf5hbhuzzKyG5wlXtO', 'common_default'),
 ('$2a$06$uDrK/2blP99mE1qXATTJce331/hP6pOsbBpFtHQ4Grb8FhF5b5xT2', 'common_default'),
 ('$2a$06$uDrK/2blP99mE1qXATTJce4Ov9X8DVzTYPsolFsfrnH/MsDUodHQ6', 'common_default'),
 ('$2a$06$uDrK/2blP99mE1qXATTJcezFdY3njpI4/8aM9SSIfSdvObxwgqHn.', 'common_default'),
 ('$2a$06$uDrK/2blP99mE1qXATTJcei3dIM3BFv07gH2oFeMVcZd05n4fcUxC', 'common_default'),
 ('$2a$06$uDrK/2blP99mE1qXATTJceCHbHCC55uZ6zF5.ri2wtzqTGOxs4lGu', 'common_default'),
 ('$2a$06$uDrK/2blP99mE1qXATTJceya2BdmaDtO3YeYzuzZcBIaZUP8w8oJS', 'common_default'),
 ('$2a$06$uDrK/2blP99mE1qXATTJceWGbw1kQnr91DK2SvgpjR6m03f5iJsJK', 'common_default'),
 ('$2a$06$uDrK/2blP99mE1qXATTJceGGFtjOd0TD.F.cOF8ZxDEpex59FZx5a', 'common_default'),
 ('$2a$06$uDrK/2blP99mE1qXATTJce1pwLP9y/XlKZbn/DU0JSFjNdRpgrl5u', 'common_default'),
 ('$2a$06$uDrK/2blP99mE1qXATTJcezAEMrBqc3wlpMo1dIgQRYxUobnVbw6y', 'common_default'),
 ('$2a$06$uDrK/2blP99mE1qXATTJcegRvp2MKpePO1eI6X1LGnYmOvr6BfFzm', 'common_default'),
 ('$2a$06$uDrK/2blP99mE1qXATTJceerq8zXfO5k7A/GbnWffkvxd2QJxFFAK', 'common_default'),
 ('$2a$06$uDrK/2blP99mE1qXATTJce5wr9bAszm7yDAi1bANscrN11yKJ8uCG', 'common_default'),
 ('$2a$06$uDrK/2blP99mE1qXATTJce051RpoBxwpo9q6f./EZDYtHVxRs4mXm', 'common_default'),
 ('$2a$06$uDrK/2blP99mE1qXATTJcelDuU5f4Cl4QFfJ.T92NYT8UVRkL/ArO', 'common_default'),
 ('$2a$06$uDrK/2blP99mE1qXATTJceEO/9/79tGnznu8gIdAJ/TwR/8EZWcZS', 'common_default'),
 ('$2a$06$uDrK/2blP99mE1qXATTJceRQ8c5h8tx35Qz0R8sWK4rFCMskdSCVG', 'common_default'),
 ('$2a$06$uDrK/2blP99mE1qXATTJceVqAunMAhuFcp9W3gKuw7WocR9xyx26S', 'common_default'),
 ('$2a$06$uDrK/2blP99mE1qXATTJceh0T2g3efXL7Ml5y0M0KGaZd0UtaJnyW', 'common_default'),
 ('$2a$06$uDrK/2blP99mE1qXATTJceZ9SL2nQWMy1WG.tAtNz36SXw01A0W5G', 'common_default'),
 ('$2a$06$uDrK/2blP99mE1qXATTJcenZIkZCO/2PanxEIGd38f9Fa5iFFn1Gi', 'common_default'),
 ('$2a$06$uDrK/2blP99mE1qXATTJce/PaCT6AybvMOOGVWhECC6nRkM7N4zcS', 'common_default'),
 ('$2a$06$uDrK/2blP99mE1qXATTJceD5yQFqV.AD9MMVlmCEvwE4Mfq.Tzsfa', 'common_default'),
 ('$2a$06$uDrK/2blP99mE1qXATTJcenH0IOYxCvK3RRIoB3LjQdKSE8irWfwe', 'common_default'),
 ('$2a$06$uDrK/2blP99mE1qXATTJcexUw3XO.1kbgXDJk8HB8gChBi8ds.xbG', 'common_default'),
 ('$2a$06$uDrK/2blP99mE1qXATTJceHI2mbOik1H/JQUb0CK32zdLaMczIdW6', 'common_default'),
 ('$2a$06$uDrK/2blP99mE1qXATTJceatFZ6xoqLOsiW3h7e.pJJ1kZ3.kbd22', 'common_default'),
 ('$2a$06$uDrK/2blP99mE1qXATTJce3RYUvJeQd8jq606H9MT9MceVoupKwxS', 'common_default'),
 ('$2a$06$uDrK/2blP99mE1qXATTJce4OTTLRwQDLlBM3wsNJYQJYUg/RjmL4K', 'common_default'),
 ('$2a$06$uDrK/2blP99mE1qXATTJcelbBv3lL.s/A5snpYtKdYXIIbihqKVi6', 'common_default'),
 ('$2a$06$uDrK/2blP99mE1qXATTJceRrX4K2KAW1toDehomwLUGtYTGaD8c/a', 'common_default'),
 ('$2a$06$uDrK/2blP99mE1qXATTJcebopjDr0AyYMWs0aEHXWxHMDxUqmJygW', 'common_default'),
 ('$2a$06$uDrK/2blP99mE1qXATTJceuXpzO8u1LfDNowJmHFHY1e5FtNqZOTm', 'common_default'),
 ('$2a$06$uDrK/2blP99mE1qXATTJcewPE05cqiJyR4Mlo3DimhQKX4jy2Sezm', 'common_default'),
 ('$2a$06$uDrK/2blP99mE1qXATTJceMsz2KZgJ9uXkks1DCJHk7WCuF7D9c5G', 'common_default'),
 ('$2a$06$uDrK/2blP99mE1qXATTJce8LtTFhNw1yDVbEXo4.47S/Nn8ONbA3y', 'common_default'),
 ('$2a$06$uDrK/2blP99mE1qXATTJcet4xGtOgvBWUGG42IXin5L.U77k3oB82', 'common_default'),
 ('$2a$06$uDrK/2blP99mE1qXATTJceM9elG5PVFZjuoS1u/sY.Upk6LNcZqt2', 'common_default'),
 ('$2a$06$uDrK/2blP99mE1qXATTJcep87AkXgtU2OG82VI5EbK5rfRiqQ4y.i', 'common_default'),
 ('$2a$06$uDrK/2blP99mE1qXATTJcee97uPaHcPcr1T5ANbFrPjLBiazKtbjK', 'common_default'),
 ('$2a$06$uDrK/2blP99mE1qXATTJceNT0hbIcA.gYA5Ee9IyYFi0tBl368KWe', 'common_default'),
 ('$2a$06$uDrK/2blP99mE1qXATTJceIrv3XfIrviQZtR/9tomaTdbRA3KwObW', 'common_default'),
 ('$2a$06$uDrK/2blP99mE1qXATTJcepvdFSkerv03X.1u5rdeyHY7AddkEWH.', 'common_default'),
 ('$2a$06$uDrK/2blP99mE1qXATTJcexcTFq04dXWvevSRO7rJmAw7we0ocC3K', 'common_default'),
 ('$2a$06$uDrK/2blP99mE1qXATTJceO0pUIwz9bobSEd6.iBeLSeY3CAtzeZq', 'common_default'),
 ('$2a$06$uDrK/2blP99mE1qXATTJce3yxK/MgUGux2XzeQNxqv2mVsQcjUJGa', 'common_default'),
 ('$2a$06$uDrK/2blP99mE1qXATTJcerDZERsv06TwZpCdfeWACe2AjmgjmPdq', 'common_default'),
 ('$2a$06$uDrK/2blP99mE1qXATTJceX816V0FQBH86KNnEga6g7pe3br.X7xu', 'common_default'),
 ('$2a$06$uDrK/2blP99mE1qXATTJceO6BL8yfy.1I4H207dv4fHN9.VfhejcK', 'common_default'),
 ('$2a$06$uDrK/2blP99mE1qXATTJceSveBdG.H6i8liUlklKUZffyOSuM1nNS', 'common_default'),
 ('$2a$06$uDrK/2blP99mE1qXATTJceLdrpDLsR.2qQunHXdj0qdTgHxkQqq4G', 'common_default'),
 ('$2a$06$uDrK/2blP99mE1qXATTJceYVRF2EKjP1slYx2XbS4bDuoc60JIn.m', 'common_default'),
 ('$2a$06$uDrK/2blP99mE1qXATTJcew6eey/oP6XhotPvnb50mT7YBTEe8mNS', 'common_default'),
 ('$2a$06$uDrK/2blP99mE1qXATTJce/msW576pIGism5bax2n8vzr480Mx/mu', 'common_default'),
 ('$2a$06$uDrK/2blP99mE1qXATTJceMzgQ.yh4P0y2RxBTsMm7VR3Ce2oqvra', 'common_default'),
 ('$2a$06$uDrK/2blP99mE1qXATTJcey0Oeqw2a0lrWBhXcj1313UPjjgkKKlq', 'common_default'),
 ('$2a$06$uDrK/2blP99mE1qXATTJce8AGkMPat5ou3u6BLaCQWF17xYYxeGxa', 'common_default'),
 ('$2a$06$uDrK/2blP99mE1qXATTJceZWndAcrOrDzPLP0cV.JPk2qtkgG0JhS', 'common_default'),
 ('$2a$06$uDrK/2blP99mE1qXATTJcelKBVmpnNylpX/RmStAV1s9GQuIGSvOi', 'common_default'),
 ('$2a$06$uDrK/2blP99mE1qXATTJcecIJcuOmTM8fwe8dHF5Ka.UMnkqHkZGG', 'common_default'),
 ('$2a$06$uDrK/2blP99mE1qXATTJceR0glOzrp9Irf2P3PrapN7aj7Q/wfUw2', 'common_default'),
 ('$2a$06$uDrK/2blP99mE1qXATTJce7o17GpoVJSpWqlngOpVyX1SJLn27/pe', 'common_default'),
 ('$2a$06$uDrK/2blP99mE1qXATTJceg0sweGQPONn4rvFBr.S9D9fy5t7ZMhC', 'common_default'),
 ('$2a$06$uDrK/2blP99mE1qXATTJceCel1yTWfZo5cooHmVguHvNXKjriWh8K', 'common_default'),
 ('$2a$06$uDrK/2blP99mE1qXATTJceT95RuJfQ2j/PFhXjMdY.WES5aXOyxmO', 'common_default'),
 ('$2a$06$uDrK/2blP99mE1qXATTJce2Bj3FMEAd2WUGVAUmp/fFmRv525Plba', 'common_default'),
 ('$2a$06$uDrK/2blP99mE1qXATTJceQ0ziueUIQPPKySBTApxl4yRcMpYjUx6', 'common_default'),
 ('$2a$06$uDrK/2blP99mE1qXATTJce6jT.B36c/th0zidxlrGvZDL6EqZ3Fyi', 'common_default'),
 ('$2a$06$uDrK/2blP99mE1qXATTJcelWWHycDEN3.tgcml.6Rr8g8qVVQocU.', 'common_default'),
 ('$2a$06$uDrK/2blP99mE1qXATTJcecQGhtYVZhN4qbn0EFAuvgFJMK48xT/S', 'common_default'),
 ('$2a$06$uDrK/2blP99mE1qXATTJcelFNIu5BSA6PtU4Wu5B3NAlkzLOrv76O', 'common_default'),
 ('$2a$06$uDrK/2blP99mE1qXATTJce0iYvTlIsZ/iyt8oc1oM0GH4jx.7SIjm', 'common_default'),
 ('$2a$06$uDrK/2blP99mE1qXATTJce6sKfsDC1QYMlbloWWQOsvbNw3slZ26y', 'common_default'),
 ('$2a$06$uDrK/2blP99mE1qXATTJceok5.M77VYwoVFeSwjQ7v0B4qi4ky0i.', 'common_default'),
 ('$2a$06$uDrK/2blP99mE1qXATTJce7h9zaDmoFTiSZuwPG6Dg2lW7yZW2/Qa', 'common_default'),
 ('$2a$06$uDrK/2blP99mE1qXATTJceFuFcssHUnvSrA0d7aPyf9oiirR441MS', 'common_default'),
 ('$2a$06$uDrK/2blP99mE1qXATTJcevWTDlYA2CXBdSqvSgjBWcpbq57dazke', 'common_default'),
 ('$2a$06$uDrK/2blP99mE1qXATTJcetsBcj/lVe71gfBGQKD/jcWuneBtuvmi', 'common_default'),
 ('$2a$06$uDrK/2blP99mE1qXATTJcenfnh00WbEVOSeYP/mzlGflHRxCkshuC', 'common_default'),
 ('$2a$06$uDrK/2blP99mE1qXATTJcex199vpLNMVCDHnpwpSIv5YJJwu6Lrty', 'common_default'),
 ('$2a$06$uDrK/2blP99mE1qXATTJceOzDDxBF7v.P6J0ma5mY1AzgNpV7JjYa', 'common_default'),
 ('$2a$06$uDrK/2blP99mE1qXATTJceQpme6kcuOgwP1FnIzBSh2/iYrVkYMly', 'common_default'),
 ('$2a$06$uDrK/2blP99mE1qXATTJceT.EMzOQiVb8hZ9ADrmM/GAQUTWQM4iC', 'common_default'),
 ('$2a$06$uDrK/2blP99mE1qXATTJcee1oqcNbaMgGQ/7aID93ujDKS.xw.e3a', 'common_default'),
 ('$2a$06$uDrK/2blP99mE1qXATTJcenfvoMS61YrjxDQ1VWmL5kTm5X0EgBKe', 'common_default'),
 ('$2a$06$uDrK/2blP99mE1qXATTJceZnH0vN1x8atpSkQvyfXwoVJzpbPL/4O', 'common_default'),
 ('$2a$06$uDrK/2blP99mE1qXATTJceZTZR/K5mssqnjsxCjjLK2iG23HWtwpS', 'common_default'),
 ('$2a$06$uDrK/2blP99mE1qXATTJceTtg1P0LHd.HeeEoAx4mr/6uJkMO2Uoq', 'common_default'),
 ('$2a$06$uDrK/2blP99mE1qXATTJceDHLp.1sW2E8PXiErObDazgQbTXtSu/y', 'common_default'),
 ('$2a$06$uDrK/2blP99mE1qXATTJceU6ZJ5K0TeqRJ8zGlvQ7f6RG72oMOy8y', 'common_default'),
 ('$2a$06$uDrK/2blP99mE1qXATTJce2m1SJ1UXWNwyb50LpEL2zzb.HLlFuvK', 'common_default'),
 ('$2a$06$uDrK/2blP99mE1qXATTJceMdk/p1gG7HG.BPtOC8cm5lVKRMFYAfS', 'common_default'),
 ('$2a$06$uDrK/2blP99mE1qXATTJceBBw9DNDFPuRJi9iGTeXSIQcUy8tB5qS', 'common_default'),
 ('$2a$06$uDrK/2blP99mE1qXATTJceCKqIt.DRHiKKMfMMmqNrKWFvpkKlPbW', 'common_default'),
 ('$2a$06$uDrK/2blP99mE1qXATTJceoiYoytXz3gM95cuLNWechouj860ZJC6', 'common_default'),
 ('$2a$06$uDrK/2blP99mE1qXATTJceky4pFfzw7T8khDITuPHEoWLvaCpKmbe', 'common_default'),
 ('$2a$06$uDrK/2blP99mE1qXATTJceDjUIebOl9pTWWzfWsNJgE3MIZgi9TNq', 'common_default'),
 ('$2a$06$uDrK/2blP99mE1qXATTJcew413RuhdNZ6ZT9jJGZwN.v.b8fWZqwS', 'common_default'),
 ('$2a$06$uDrK/2blP99mE1qXATTJceymkT88JTiEMK1sQt1gCOS3sy3AhjdJK', 'common_default'),
 ('$2a$06$uDrK/2blP99mE1qXATTJce0h8rr/u/XK0siAHphokZ/cvbuCE9FcW', 'common_default'),
 ('$2a$06$uDrK/2blP99mE1qXATTJceMuMJgQHKV09nOfMwm6wz1FJGl52GLai', 'common_default'),
 ('$2a$06$uDrK/2blP99mE1qXATTJcebX1XSaN11WAFO6BWVYTk1sDJsEedQFe', 'common_default'),
 ('$2a$06$uDrK/2blP99mE1qXATTJceB9cbeVeSly4qy6fU9vNY6PvYXm1jU72', 'common_default'),
 ('$2a$06$uDrK/2blP99mE1qXATTJcefQRNuL8x6h4FTM2.03dTByR8GuLZr.K', 'common_default'),
 ('$2a$06$uDrK/2blP99mE1qXATTJceKMJKaUr5bSAC4GzF4eGHiQ4ImWslPIK', 'common_default'),
 ('$2a$06$uDrK/2blP99mE1qXATTJcek62U5MwV9rbqxfoMMSQ28FTLLtes08W', 'common_default'),
 ('$2a$06$uDrK/2blP99mE1qXATTJceqtCOUHVW2/mWuxCvNzjKutGAU96fW26', 'common_default'),
 ('$2a$06$uDrK/2blP99mE1qXATTJce0Wu6zk3wl/6s/1cWp1Uzz47IzT344Wq', 'common_default'),
 ('$2a$06$uDrK/2blP99mE1qXATTJce6ikM3BBZAvGXoAygpatKgnNav6IJRi.', 'common_default'),
 ('$2a$06$uDrK/2blP99mE1qXATTJcezrLWxNAPNX9aUnHBnhnw9qw3RJqSV.i', 'common_default'),
 ('$2a$06$uDrK/2blP99mE1qXATTJce46Oeb4T7vWZxKVOmVwE5X5i.jPuabXG', 'common_default'),
 ('$2a$06$uDrK/2blP99mE1qXATTJce6N4vOH.9T/fr71X2/2hno9jdFwhphoG', 'common_default'),
 ('$2a$06$uDrK/2blP99mE1qXATTJceVsznal/7zQMYzvsLI6d4SB03jLscNdW', 'common_default'),
 ('$2a$06$uDrK/2blP99mE1qXATTJceNMzCAUTltPp/JEQ8y2H.lWdZA5pdN4C', 'common_default'),
 ('$2a$06$uDrK/2blP99mE1qXATTJceLT1ERgQmlwdG991OANr2GgL.KumB2Iy', 'common_default'),
 ('$2a$06$uDrK/2blP99mE1qXATTJcewXLL4FEjbi9M7MsKgRopK5.F2EsCGiq', 'common_default'),
 ('$2a$06$uDrK/2blP99mE1qXATTJceyo3NZvUuqqnx/shPaTE4s5ybyOwdDTy', 'common_default'),
 ('$2a$06$uDrK/2blP99mE1qXATTJce3PCxuXOeBLKTMsV53XSCwdIRo2C6dMG', 'common_default'),
 ('$2a$06$uDrK/2blP99mE1qXATTJceT/EvzD91Q9VUCYaILqd6zxnGhNYHtxu', 'common_default'),
 ('$2a$06$uDrK/2blP99mE1qXATTJceTLTB5awK6MIfa6Wg2nL1jmmsFPwYoFu', 'common_default'),
 ('$2a$06$uDrK/2blP99mE1qXATTJcekwnq4yJYZVpYpAym5jtGiiWtThxYk6q', 'common_default'),
 ('$2a$06$uDrK/2blP99mE1qXATTJceUMn8EjK/J8mgYU.yHUseAC9WvWuH5f6', 'common_default'),
 ('$2a$06$uDrK/2blP99mE1qXATTJceio0j.w5RWVox2KW5DHruxNcIhe09sg2', 'common_default'),
 ('$2a$06$uDrK/2blP99mE1qXATTJceHu/FTO/GYv0Ob7G.zKfO7FtnCoL0gcC', 'common_default'),
 ('$2a$06$uDrK/2blP99mE1qXATTJcemLz4Z8IhU7uYrcx9EtRIMKDschyKh0u', 'common_default'),
 ('$2a$06$uDrK/2blP99mE1qXATTJceBJNzpqiSM19FL920Yp2idRdsV09rg8q', 'common_default'),
 ('$2a$06$uDrK/2blP99mE1qXATTJce0rDbLz61w8hMfte/W1MePtk/TTGT/vu', 'common_default'),
 ('$2a$06$uDrK/2blP99mE1qXATTJcePaXik2EMRRMhYsPis.ZBD4B4xEq7TgS', 'common_default'),
 ('$2a$06$uDrK/2blP99mE1qXATTJceNR1/l6UKsegxColMk4Vk2WDgmMaEMzq', 'common_default'),
 ('$2a$06$uDrK/2blP99mE1qXATTJce82undD8nkhPmaB3jMxf4YcOMYgfqT2G', 'common_default'),
 ('$2a$06$uDrK/2blP99mE1qXATTJceWv6E.NsL485kzJ0GQs7LOfB2rQ5UVii', 'common_default'),
 ('$2a$06$uDrK/2blP99mE1qXATTJcefU4WFZC2ajC.pePAjK/XHx4Vg09HB4K', 'common_default'),
 ('$2a$06$uDrK/2blP99mE1qXATTJce9Zq6o8Mks6zd1qFYBzEp.04iCC0J54K', 'common_default'),
 ('$2a$06$uDrK/2blP99mE1qXATTJce4uwWkYUOmgtzmExdM.0OMA/3VBHubxa', 'common_default'),
 ('$2a$06$uDrK/2blP99mE1qXATTJce374XvySFMJ1ScYrCb2cEm/NIGrrabWy', 'common_default'),
 ('$2a$06$uDrK/2blP99mE1qXATTJceo1SN5ieDj50nAXh6xFQK1NYZSzWsbgG', 'common_default'),
 ('$2a$06$uDrK/2blP99mE1qXATTJceI69CKCXOGWQWao06QbUdGHc793TTPSu', 'common_default'),
 ('$2a$06$uDrK/2blP99mE1qXATTJceIdYPlvF1bbWBh5o/PEPekUL3cUzG1Xy', 'common_default'),
 ('$2a$06$uDrK/2blP99mE1qXATTJcemId.N7iS0R7kmS2vUGF6BP22kHbvTMC', 'common_default'),
 ('$2a$06$uDrK/2blP99mE1qXATTJcecbpVcFTWHcK.NQ.F/GoSPFbEsu8Ue8G', 'common_default'),
 ('$2a$06$uDrK/2blP99mE1qXATTJceFevVoOHigAA4OTHjQ8jP6sd2eEr9BmS', 'common_default'),
 ('$2a$06$uDrK/2blP99mE1qXATTJceOxWXGayquNUfjBhGnZeaSN090XbyFEu', 'common_default'),
 ('$2a$06$uDrK/2blP99mE1qXATTJcevd58ApgevJMjEujjZgInioVTKjPb.dK', 'common_default'),
 ('$2a$06$uDrK/2blP99mE1qXATTJce/oztR5ImHwmpqlivcMnz0dfwqf/P3b.', 'common_default'),
 ('$2a$06$uDrK/2blP99mE1qXATTJce1G4ggvxfzNTOitZf3ltCoYsWxZ/lo.K', 'common_default'),
 ('$2a$06$uDrK/2blP99mE1qXATTJcevS9roLug3eOacBnHK0PmUbANE7q7hf6', 'common_default'),
 ('$2a$06$uDrK/2blP99mE1qXATTJce8Wb2nlPrG7Mwbg5MrnkEmfMUGyUXtsq', 'common_default'),
 ('$2a$06$uDrK/2blP99mE1qXATTJceO/PGZjmwOTJBHNFmxT54dP96KE9/vLS', 'common_default'),
 ('$2a$06$uDrK/2blP99mE1qXATTJce5OtRglw8nJ1yxRTP3GLueuIenZA9KVy', 'common_default'),
 ('$2a$06$uDrK/2blP99mE1qXATTJce9ndhulKNwzZje1KkekijwR8To/5.6O.', 'common_default'),
 ('$2a$06$uDrK/2blP99mE1qXATTJceL4FNsaNOsBBkSCe4Z8427y1aYdaaP5C', 'common_default'),
 ('$2a$06$uDrK/2blP99mE1qXATTJcelw20UySCE7qnbqDCEfZQY9tFpPQ1UsW', 'common_default'),
 ('$2a$06$uDrK/2blP99mE1qXATTJcewY5JskUDsxqIBATJMMUL2wGC012WGvy', 'common_default'),
 ('$2a$06$uDrK/2blP99mE1qXATTJceoUofn/gO97ka0WFprRhTNNVTf/qYUnS', 'common_default'),
 ('$2a$06$uDrK/2blP99mE1qXATTJceLxbL9F73HEeV0RG9DthaNOVacF4VOeS', 'common_default'),
 ('$2a$06$uDrK/2blP99mE1qXATTJcew/xezrmjM.BaQmOKslMqTahlUgies02', 'common_default'),
 ('$2a$06$uDrK/2blP99mE1qXATTJcehrCuQxRQoh8yjPgtrRAf4Uc3LXgB3Q.', 'common_default'),
 ('$2a$06$uDrK/2blP99mE1qXATTJcem2aYSiMo393qRURALcJ6oSpA2.fzkJy', 'common_default'),
 ('$2a$06$uDrK/2blP99mE1qXATTJceA0S8jsUEPUt/3iZ.9V4L.WPh3lnS1Ey', 'common_default'),
 ('$2a$06$uDrK/2blP99mE1qXATTJce8bRnpYFghfGDBapdY8/2EhGzBWPdUuK', 'common_default'),
 ('$2a$06$uDrK/2blP99mE1qXATTJceC6CY/OBf4ZWBD7wgKop/qPph175hPPm', 'common_default'),
 ('$2a$06$uDrK/2blP99mE1qXATTJce1M59LJZmSdWSUHt15ud52vXyqePap5K', 'common_default'),
 ('$2a$06$uDrK/2blP99mE1qXATTJceXVwOTOsfgqZoC2Yk.351bJalHwOw7Qe', 'common_default'),
 ('$2a$06$uDrK/2blP99mE1qXATTJcexJxvZ3WTHPU0nkuV7wZ8OdHhae1x6Ry', 'common_default'),
 ('$2a$06$uDrK/2blP99mE1qXATTJce6RirucCFG9jrHhWqSLV099aczQi.aWG', 'common_default'),
 ('$2a$06$uDrK/2blP99mE1qXATTJceQH9IgzzVahht0A/qi1pKk.bV37D3VKy', 'common_default'),
 ('$2a$06$uDrK/2blP99mE1qXATTJceDozmiZnYJFR7O.DwLs39tg5q224gnri', 'common_default'),
 ('$2a$06$uDrK/2blP99mE1qXATTJceSOwwOcN7riVhcX8eC3N7htCNxmymgfu', 'common_default'),
 ('$2a$06$uDrK/2blP99mE1qXATTJce.CTnPfO0WBdY5zRyDCMhRi2au4ajjKu', 'common_default'),
 ('$2a$06$uDrK/2blP99mE1qXATTJcelcZgGQgYNbbLO1Q93ibbN8Tw7EGPSFu', 'common_default'),
 ('$2a$06$uDrK/2blP99mE1qXATTJceCkaEWvTklKi5O3sTXxBPBuK12sN9hTy', 'common_default'),
 ('$2a$06$uDrK/2blP99mE1qXATTJceNqUvYMubISn3DPwpZL37GsEOE6.owtK', 'common_default'),
 ('$2a$06$uDrK/2blP99mE1qXATTJceZLP9hlPh7WUXH9nPASgFWRZVRpt7t8O', 'common_default'),
 ('$2a$06$uDrK/2blP99mE1qXATTJce2IQLnczymNv1g98uGcnbo5dpXmIVYGu', 'common_default'),
 ('$2a$06$uDrK/2blP99mE1qXATTJceP7oadg7fV3fBTziOOTnxL17/F/J6rJm', 'common_default'),
 ('$2a$06$uDrK/2blP99mE1qXATTJce9RtKOTu.gOVvVw8sfNgM/Nx1M8y1Maa', 'common_default'),
 ('$2a$06$uDrK/2blP99mE1qXATTJceqW.Gdvrc5Ze.PTT26jdzg08DDLA.nIK', 'common_default'),
 ('$2a$06$uDrK/2blP99mE1qXATTJce4.ffbl4uxy5QBVFs3UeptSPY.w6yOLO', 'common_default'),
 ('$2a$06$uDrK/2blP99mE1qXATTJceW4MAh4zNaDffyDsW49NzZonqoNKXqTu', 'common_default'),
 ('$2a$06$uDrK/2blP99mE1qXATTJce6d19D6VBKNLnQ5eeE1emhfJ8N6.bGra', 'common_default'),
 ('$2a$06$uDrK/2blP99mE1qXATTJcexHs0dPSyPBD/gI0IIqSAwngvrf1c4Ky', 'common_default'),
 ('$2a$06$uDrK/2blP99mE1qXATTJceWIdXBlnRYZhp9m1bCrPlI4FHvJgaSQC', 'common_default'),
 ('$2a$06$uDrK/2blP99mE1qXATTJcep7hOuwkWaBpzGMMD0OcfOCFq9xoYrpy', 'common_default'),
 ('$2a$06$uDrK/2blP99mE1qXATTJcewFdI8Fpwbk4CzvaACVmOHm.cTBIUzzi', 'common_default'),
 ('$2a$06$uDrK/2blP99mE1qXATTJce8qRay5VSSjeCzk7fP78qlcxiolm5M.2', 'common_default'),
 ('$2a$06$uDrK/2blP99mE1qXATTJceH90xpfzHfuBCi2t7f..uPHNxZ.OQt16', 'common_default'),
 ('$2a$06$uDrK/2blP99mE1qXATTJcePeLWL2iOx7awXwDHaBxmwGbO1vUfIWy', 'common_default'),
 ('$2a$06$uDrK/2blP99mE1qXATTJceAysWQBugPQ52GKD.NevkW2uatrHgyUy', 'common_default'),
 ('$2a$06$uDrK/2blP99mE1qXATTJceMTdVJPKMYrYUKdqlei6TeMh0eeLEYXW', 'common_default'),
 ('$2a$06$uDrK/2blP99mE1qXATTJceDiBrPBevBguvobWARDf0CCTZqrQkM8u', 'common_default'),
 ('$2a$06$uDrK/2blP99mE1qXATTJceOUpjTUOEQTQ4Wpbx/n14pWq1V3MN8Ma', 'common_default'),
 ('$2a$06$uDrK/2blP99mE1qXATTJcecwsBOkQUFIxy9uXyKda35S4sM1rcpbK', 'common_default'),
 ('$2a$06$uDrK/2blP99mE1qXATTJceiePJ/YhJ9bRYdVF0QwkFzdrJ2.u5JJu', 'common_default'),
 ('$2a$06$uDrK/2blP99mE1qXATTJceI2tB1K3bPgFHiFvvcIfez6MLCM5kTre', 'common_default'),
 ('$2a$06$uDrK/2blP99mE1qXATTJceDryuuNXW8i747u.VAxQtacpE1JSGBqq', 'common_default'),
 ('$2a$06$uDrK/2blP99mE1qXATTJcezTctdIWegnMEaxQz7hmk.LlxWbaYb7e', 'common_default'),
 ('$2a$06$uDrK/2blP99mE1qXATTJceRBzaZh/bJ5wu9qH.W8uMbNNF5rBiJ9S', 'common_default'),
 ('$2a$06$uDrK/2blP99mE1qXATTJce0QjuNakrPORunmQ5DpXIPefTlRDsuSG', 'common_default'),
 ('$2a$06$uDrK/2blP99mE1qXATTJceEi2KaE..aw9.f5PpKNqhNVvvliiQMZe', 'common_default'),
 ('$2a$06$uDrK/2blP99mE1qXATTJce71./NFzWE07NYXJsGO98mpKa6efbnDS', 'common_default'),
 ('$2a$06$uDrK/2blP99mE1qXATTJce7hZEmMR3qhK15tjRL8bFEFNNPx6woZe', 'common_default'),
 ('$2a$06$uDrK/2blP99mE1qXATTJceuoiDfjqtjtBVkw/9mykrfzTO9CMbWIm', 'common_default'),
 ('$2a$06$uDrK/2blP99mE1qXATTJceev8ITWL5QOY0lc5HjkJlQBU8WfrgPnO', 'common_default'),
 ('$2a$06$uDrK/2blP99mE1qXATTJceyjFu.aZaG5s/QaZniHYew2Mv5osaF4i', 'common_default'),
 ('$2a$06$uDrK/2blP99mE1qXATTJceSoHIYMBSXIbEuMUb/C2rvuXX8v3JZiy', 'common_default'),
 ('$2a$06$uDrK/2blP99mE1qXATTJceWZrptdB4TXvGSj4YjVKno8ar.TqKKsm', 'common_default'),
 ('$2a$06$uDrK/2blP99mE1qXATTJceIZ70ltv1HMTx9EOvY/fujZ09qpGJio6', 'common_default'),
 ('$2a$06$uDrK/2blP99mE1qXATTJcefK9TOB5aloWvGX5oGrjM.CLhJnkspfq', 'common_default'),
 ('$2a$06$uDrK/2blP99mE1qXATTJcetzjr.otSDZfezrohwsQPzbz.guuLfB2', 'common_default'),
 ('$2a$06$uDrK/2blP99mE1qXATTJceIHlUkWt29Uuyit8Xlc0JIYMwfyvJQQm', 'common_default'),
 ('$2a$06$uDrK/2blP99mE1qXATTJcedambSwCp7Hj.b2i8NJiXHiAxHvqgNDi', 'common_default'),
 ('$2a$06$uDrK/2blP99mE1qXATTJcer5x19EIQtnB0qL2jy5k/Ql4iRMaZEy.', 'common_default'),
 ('$2a$06$uDrK/2blP99mE1qXATTJce3eYMMyQoUM4zItALCfVnkHLJ4nUe.ea', 'common_default'),
 ('$2a$06$uDrK/2blP99mE1qXATTJceBidyZlnmS2aBlT35sYRCm7BCMDds8Hi', 'common_default')
 );

  
  
  -- password_check.is_bad_password Function
  -- Purpose: Checks if a given plaintext password matches any of the known bad passwords
  --          stored in the `password_check.bad_passwords` table. This function is
  --          used by the `passcheck_hook` to enforce PCI DSS Requirement 8.3.8 (Good Practice)
  --          by disallowing easily guessable or compromised passwords.
  --
  -- Parameters:
  --   password (TEXT): The plaintext password to check against the bad passwords list.
  --
  -- Returns:
  --   BOOLEAN: TRUE if the password is found in the `bad_passwords` list, FALSE otherwise.
  --
  -- Notes:
  --   - The function converts the input password to lowercase before hashing for case-insensitive comparison.
  --   - It uses a fixed salt (`$2a$06$uDrK/2blP99mE1qXATTJce`) for hashing the input password.
  --     It is CRITICAL that all passwords inserted into `password_check.bad_passwords`
  --     are hashed using this EXACT SAME fixed salt to ensure accurate comparisons.
  CREATE OR REPLACE FUNCTION password_check.is_bad_password(
      password TEXT
  ) RETURNS BOOLEAN AS $$
  DECLARE
    l_salt TEXT := '$2a$06$uDrK/2blP99mE1qXATTJce'; -- The fixed Blowfish salt
    l_password_hash TEXT;
  BEGIN
  
    l_password_hash := crypt(lower(password), l_salt); -- Hashing with Blowfish for comparison

    RETURN EXISTS (
      SELECT 1 
      FROM 
        password_check.bad_passwords 
      WHERE 
        password_hash = l_password_hash);

    l_password_hash := crypt(lower(password), l_salt);

  END;
  $$ LANGUAGE plpgsql SECURITY DEFINER;
  
  
  -- password_check.add_bad_password Function
  -- Purpose: Adds a new plaintext password to the `password_check.bad_passwords` table.
  --          The provided password is first hashed using a fixed salt before insertion.
  --          This function allows administrators to expand the list of disallowed passwords.
  --
  -- Parameters:
  --   password (TEXT): The plaintext password to add to the bad passwords list.
  --
  -- Returns:
  --   VOID
  --
  -- Notes:
  --   - The function converts the input password to lowercase before hashing for consistency.
  --   - It uses a fixed salt (`$2a$06$uDrK/2blP99mE1qXATTJce`) for hashing the input password.
  --     This ensures compatibility with the `is_bad_password` function.
  --   - Attempts to insert duplicate hashes will be ignored due to the `password_hash` PRIMARY KEY constraint.
  CREATE OR REPLACE FUNCTION password_check.add_bad_password(
      password TEXT
  ) RETURNS VOID AS $$
  DECLARE
    -- Variable to store the default salt used with crypt.
    l_salt TEXT := '$2a$06$uDrK/2blP99mE1qXATTJce'; -- The default salt used to compare bad passwords
    l_password_hash TEXT;

  BEGIN

    l_password_hash := crypt(lower(password), l_salt);
    
    INSERT INTO 
      password_check.bad_passwords (password_hash, source)
    VALUES
      (l_password_hash, 'manual');

  END;
  $$ LANGUAGE plpgsql SECURITY DEFINER;
  
  
  -- password_check.remove_bad_password Function
  -- Purpose: Removes a plaintext password from the `password_check.bad_passwords` table.
  --          The provided password is first hashed using a fixed salt to find its corresponding
  --          entry for deletion.
  --
  -- Parameters:
  --   password (TEXT): The plaintext password to remove from the bad passwords list.
  --
  -- Returns:
  --   VOID
  --
  -- Notes:
  --   - The function converts the input password to lowercase before hashing for consistency.
  --   - It uses a fixed salt (`$2a$06$uDrK/2blP99mE1qXATTJce`) for hashing the input password.
  --     This ensures compatibility with the `is_bad_password` function.
  --   - If the password (or its hash) is not found, no action is performed.
  CREATE OR REPLACE FUNCTION password_check.remove_bad_password(
      password TEXT
  ) RETURNS VOID AS $$
  DECLARE
    -- Variable to store the default salt used with crypt.
    l_salt TEXT := '$2a$06$uDrK/2blP99mE1qXATTJce'; -- The default salt used to compare bad passwords
    l_password_hash TEXT;

  BEGIN

    l_password_hash := crypt(lower(password), l_salt);
    
    DELETE FROM 
      password_check.bad_passwords
    WHERE 
      password_hash = l_password_hash;

  END;
  $$ LANGUAGE plpgsql SECURITY DEFINER;


  -- clientauth hook function
  -- Purpose: This function is called by pg_tle after any authentication attempt.
  -- It is responsible for:
  --   1. Checking if an account is currently locked and preventing login (PCI DSS 8.3.4).
  --   2. Tracking failed authentication attempts and initiating lockout when thresholds are met.
  --   3. Recording successful login attempts and updating last activity.
  --   4. Enforcing password expiration (logic carried over from v0.4).
  --   5. Enforcing password change on first login (PCI DSS 8.3.6).
  CREATE OR REPLACE FUNCTION password_check.clientauth_hook(
      port pgtle.clientauth_port_subset, -- Contains connection details like user_name
      status INTEGER                     -- Authentication status (0 for success, -1 for failure)
  ) RETURNS VOID AS $$
  DECLARE
    l_username TEXT := port.user_name; -- Extract username from the port object
    current_valid_until TIMESTAMPTZ;
    user_exists BOOLEAN;
    current_locked_until_time TIMESTAMPTZ;
    current_failed_attempts INTEGER;
    current_lockout_threshold INTEGER;
    current_lockout_duration_minutes INTEGER;
    l_password_reset_required BOOLEAN; --Variable to hold the flag
    l_password_first_login BOOLEAN; -- Variable to hold the flag

  BEGIN
  
    RAISE INFO 'Test RAISE INFO';
  
    -- Check if the user already exists in pg_roles. This helps differentiate between
    -- attempts for existing users versus attempts for non-existent users (though pg_tle still calls the hook).
    SELECT EXISTS (SELECT 1 FROM pg_catalog.pg_roles WHERE rolname = l_username)
    INTO user_exists;
    RAISE NOTICE 'User exists: %',user_exists;

    -- 0. Determine Role-Based Policies (from password_check.profiles table)
    --    Fetch the lockout_threshold and lockout_duration_minutes based on the user's
    --    prioritized PCI role. If no specific role is found, default values are used.
    IF user_exists THEN

      SELECT
        lockout_threshold,
        lockout_duration_minutes,
        password_reset_required, --Fetch the flag from user_login_activity
        password_first_login
      INTO
        current_lockout_threshold,
        current_lockout_duration_minutes,
        l_password_reset_required, --Assign to variable
        l_password_first_login
      FROM
        password_check.profiles pr
      JOIN password_check.user_login_activity ula ON ula.username = l_username --Join to get the flag
      WHERE
        pr.role=password_check.get_member_priority_role(l_username);

      RAISE DEBUG 'Fetch password_reset_required: %, password_first_login: %', l_password_reset_required, l_password_first_login;

      IF NOT FOUND THEN
        -- Fallback to default values if user's role profile isn't explicitly defined
        current_lockout_threshold := 10;
        current_lockout_duration_minutes := 30;
        -- If user_exists but no profile found, assume password_reset_required is false unless explicitly set
        --Ensure flag is fetched even if profile not found
        SELECT 
          password_reset_required,
          password_first_login
        INTO
          l_password_reset_required,
          l_password_first_login
        FROM 
          password_check.user_login_activity 
        WHERE 
          username = l_username;
        
        IF l_password_first_login IS NULL THEN l_password_reset_required := FALSE; END IF; -- Default to FALSE if no activity record yet
        IF l_password_reset_required IS NULL THEN l_password_first_login := FALSE; END IF; -- Default to FALSE if no activity record yet

        RAISE DEBUG 'Profile not found, set defaut l_password_reset_required: %, l_password_first_login: %',l_password_reset_required, l_password_first_login;

      END IF;
    ELSE
      -- If user doesn't exist, use default lockout parameters for consistency
      current_lockout_threshold := 10;
      current_lockout_duration_minutes := 30;
      l_password_reset_required := FALSE; --Default to FALSE for non-existent users
      l_password_first_login := FALSE;

      RAISE DEBUG 'User doesn''t exist, l_password_reset_required: %',l_password_reset_required;

    END IF;

    --Test case 2: After a successful login, are the correct profile policies selected?
    RAISE DEBUG 'Test case 2: Role-Based Policies: current_lockout_threshold: %, current_lockout_duration_minutes: %, Priority Role: %', current_lockout_threshold, current_lockout_duration_minutes, password_check.get_member_priority_role(l_username);
    RAISE DEBUG 'Test case 2: l_password_reset_required: %, l_password_first_login: %', l_password_reset_required, l_password_first_login;


    -- 1. Handle already locked accounts: THIS IS THE PRIMARY LOCKOUT ENFORCEMENT POINT
    -- Check if the user is currently listed in the locked_accounts table.
    SELECT locked_until INTO current_locked_until_time
    FROM password_check.locked_accounts la
    WHERE la.username = l_username;
    
    IF FOUND THEN
        IF NOW() < current_locked_until_time THEN
            -- Account is locked and lockout period is still active. Immediately reject connection.
            RAISE EXCEPTION 'Account % has been locked due to too many failed authentication attempts. Try again after %.', l_username, current_locked_until_time;
        ELSE
            -- Account is locked but the lockout period has expired.
            -- Clean up the locked_accounts entry and reset failed attempts.
            DELETE FROM password_check.locked_accounts la WHERE la.username = l_username;
            UPDATE password_check.user_login_activity la
            SET failed_attempts = 0, last_activity = NOW()
            WHERE la.username = l_username;
            --Test Case 3: Account is removed from password_check.locked_accounts after the lockout period ends.
            RAISE DEBUG 'Test Case 3: Account is removed from password_check.locked_accounts after the lockout period ends. Rows found: %', (SELECT count(1) FROM password_check.locked_accounts la WHERE la.username = l_username); -- Corrected SELECT syntax
            RAISE NOTICE 'Account % was automatically unlocked as the lockout period expired.', l_username;
        END IF;
    END IF;

    -- Only proceed with tracking for existing users to avoid cluttering activity for non-existent users
    IF user_exists THEN
      -- Ensure user_login_activity record exists for the current user.
      -- If it doesn't, a new record is inserted.
      INSERT INTO password_check.user_login_activity (username) VALUES (l_username)
      ON CONFLICT (username) DO NOTHING;
    END IF;

    -- 2. Track authentication attempts based on status
    IF status = -1 THEN -- Authentication FAILED (status is -1 for authentication failures)
      -- Increment failed attempts counter and update last_activity timestamp.
      INSERT INTO password_check.user_login_activity (username, failed_attempts, last_activity)
      VALUES (l_username, 1, NOW())
      ON CONFLICT (username) DO UPDATE
      SET failed_attempts = password_check.user_login_activity.failed_attempts + 1,
          last_activity = NOW()
      WHERE password_check.user_login_activity.username = EXCLUDED.username
      RETURNING failed_attempts INTO current_failed_attempts;
      
      --Test case 4: After a failed login attempt, the failed_attempts column on table password_check.user_login_activity is incremented.
      RAISE DEBUG 'Test case 4: Failed login attempts for user %: %', l_username, current_failed_attempts; -- Corrected grammar
      RAISE NOTICE 'Failed login attempts for user %: %', l_username, current_failed_attempts; -- Corrected grammar
      
      -- If the failed attempts threshold is reached, insert/update the account in locked_accounts.
      IF current_failed_attempts >= current_lockout_threshold THEN
        INSERT INTO password_check.locked_accounts (username, locked_until, locked_by)
        VALUES (l_username, NOW() + (current_lockout_duration_minutes || ' minutes')::INTERVAL, 'SYSTEM')
        ON CONFLICT (username) DO UPDATE
        SET locked_until = NOW() + (current_lockout_duration_minutes || ' minutes')::INTERVAL,
            locked_by = 'SYSTEM'
        WHERE password_check.locked_accounts.username = EXCLUDED.username;
        
        -- Reset failed attempts in user_login_activity immediately after locking the account.
        -- This prevents the account from being immediately re-locked if it's unlocked manually
        -- or if the lockout period expires and the user tries to log in again.
        UPDATE password_check.user_login_activity la
        SET failed_attempts = 0, last_activity = NOW()
        WHERE la.username = l_username;
        
        -- The actual connection termination for a newly locked account will happen on the *next*
        -- login attempt, when the "1. Handle already locked accounts" section at the beginning
        -- of this hook detects the new entry in locked_accounts. This design ensures that
        -- the updates to locked_accounts and user_login_activity are committed before the
        -- connection is terminated by PostgreSQL (which would roll back any uncommitted changes).
      END IF;
    ELSIF status = 0 THEN -- Authentication SUCCESSFUL (status is 0 for successful authentication)
      
      --3. Handle password_reset_required flag (PCI DSS 8.3.6)
      -- If the user successfully authenticates but needs to reset their password, check if its the first time logging in.
      -- If not, reject the connection with a specific message.
      IF l_password_reset_required THEN
        IF l_password_first_login THEN
          RAISE WARNING 'Your password must be changed. Please execute "ALTER USER % WITH PASSWORD <YOUR_NEW_PASSWORD>" to set a new password.', l_username;
          RAISE INFO 'INFO: Your password must be changed. Please execute "ALTER USER % WITH PASSWORD <YOUR_NEW_PASSWORD>" to set a new password.', l_username;
          
        ELSE
          RAISE EXCEPTION 'Your password must be changed before you can log in. Please contact the Database Administrator to set a new password.';
          --RAISE EXCEPTION 'Your password must be changed before you can log in. Please execute psql -U % -d % -W -c "ALTER USER % WITH PASSWORD ''YOUR_NEW_PASSOWRD'';" to set a new password.', l_username, port.database_name, l_username;
        END IF;
      END IF;

      -- 3. Determine if password is still valid: (PCI DSS 8.3.9 & 8.6.3)
      --	. Check the valid_until date from password_check.password_history.
      --		. This query looks for the last value of "current_valid_until" for the current account.
      SELECT 
        ph.valid_until 
      INTO 
        current_valid_until
      FROM 
        password_check.password_history ph
      WHERE
        ph.username = l_username
      ORDER BY change_timestamp DESC
      LIMIT 1;
      
      IF FOUND THEN
      
        IF NOW() > current_valid_until THEN
          RAISE EXCEPTION 'The password has expired, please contact the admin.';
        END IF;
      
      END IF;

      -- On successful login, reset failed attempts and update last_activity/last_successful_login.
      -- Crucially, set password_first_login to FALSE. This will prevent the user from logging in again if it doesn't reset the password.
      UPDATE password_check.user_login_activity la
      SET failed_attempts = 0, last_activity = NOW(), last_successful_login = NOW(), password_first_login = FALSE
      WHERE la.username = l_username;


    END IF;

  END;
  $$ LANGUAGE plpgsql SECURITY DEFINER;



  -- password_check.passcheck_hook Function
  -- Purpose: This is the main pg_tle password check hook function responsible for
  --          enforcing comprehensive password policies during password creation or modification
  --          (e.g., via ALTER ROLE/USER). It integrates multiple PCI DSS requirements
  --          related to password strength, history, validity, and now, common/bad passwords.
  --
  -- Parameters:
  --   USERNAME (TEXT): The name of the PostgreSQL user/role whose password is being set or changed.
  --   PASSWORD (TEXT): The plaintext password being provided.
  --   PASSWORD_TYPE (PGTLE.PASSWORD_TYPES): The type of password (e.g., 'PLAINTEXT', 'MD5', 'SCRAM-SHA-256').
  --                                         Complexity and common password checks are only fully
  --                                         effective with 'PLAINTEXT' or 'MD5' types.
  --   VALID_UNTIL (TIMESTAMPTZ): The expiration date for the password.
  --   VALID_NULL (BOOLEAN): TRUE if VALID UNTIL NULL is specified, FALSE otherwise.
  --
  -- Returns:
  --   VOID: Raises an EXCEPTION if any password policy is violated.
  --
  -- Key Policy Enforcement Areas:
  --   1.  Role-Based Policy Determination: Fetches password policy parameters (min_length,
  --       complexity requirements, history_limit, max_validity_interval) from
  --       `password_check.profiles` based on the user's most prioritized PCI role.
  --   2.  New User Handling (PCI DSS 8.3.6): For newly created users (`pci_new_users` role),
  --       it sets `password_reset_required` and `password_first_login` flags to TRUE in
  --       `password_check.user_login_activity`, enforcing a mandatory password change on first login.
  --   3.  Password Complexity Checks (PCI DSS 8.3.6 and 8.6.3): Ensures the password meets
  --       defined criteria (minimum length, uppercase, lowercase, digit, special character).
  --   4.  Password Reusability Check (PCI DSS 8.3.7): Compares the new password against the
  --       user's history in `password_check.password_history` to prevent reuse of recent passwords.
  --       (Effective for 'PLAINTEXT' and 'MD5' password types).
  --   5.  Common/Bad Password Check (PCI DSS 8.3.8 Good Practice): Utilizes the
  --       `password_check.is_bad_password` function to verify the new password is not
  --       on a list of known weak, compromised, or default passwords.
  --       (Effective for 'PLAINTEXT' password types).
  --   6.  Password Validity Period Enforcement (PCI DSS 8.3.9 & 8.6.3): Ensures a `VALID UNTIL`
  --       date is set and does not exceed the maximum allowed validity interval for the role.
  --   7.  Password Reset Flag Clearance: Upon successful password change, it clears the
  --       `password_reset_required` and `password_first_login` flags in
  --       `password_check.user_login_activity`, indicating the user has complied with the reset.
  --   8.  Password History Management: Stores the new password's hash and prunes old history entries.
  CREATE OR REPLACE FUNCTION PASSWORD_CHECK.PASSCHECK_HOOK (
    USERNAME TEXT,
    PASSWORD TEXT,
    PASSWORD_TYPE PGTLE.PASSWORD_TYPES,
    VALID_UNTIL TIMESTAMPTZ,
    VALID_NULL BOOLEAN
) RETURNS VOID AS $_FUNCTION_$ -- ADDED THIS BLOCK LABEL
  #variable_conflict use_column
  DECLARE
    invalid_pw_reason TEXT := '';

    current_min_length INTEGER := 12;
    current_require_special_char BOOLEAN := TRUE;
    current_require_uppercase BOOLEAN := TRUE;
    current_require_lowercase BOOLEAN := TRUE;
    current_require_digit BOOLEAN := TRUE;
    current_history_limit INTEGER := 4;
    current_max_validity_interval INTERVAL;
    
    -- Flag to check if the user already exists in pg_roles.
    -- This helps differentiate between CREATE ROLE and ALTER ROLE operations.
    user_exists BOOLEAN;
    -- New variable to store the determined priority role
    user_priority_role TEXT;


    -- Variable to store the hashed version of the new password.
    new_password_hashed TEXT;
    
    -- Cursor to iterate through previous password hashes.
    history_cursor CURSOR (cur_history_limit INTEGER) FOR
      SELECT h.password_hash
      FROM password_check.password_history h
      WHERE h.username = passcheck_hook.username
      ORDER BY change_timestamp DESC
      LIMIT cur_history_limit; -- PCI DSS 8.3.7: password must be different from previous four.
    
    -- Variable to hold a hash from the history cursor.
    old_password_hash TEXT;

    -- Local variable for ambiguity resolution in INSERT/DELETE statements
    _username_param TEXT;

  BEGIN

    -- Check if the user already exists in pg_roles.
    -- This helps differentiate between CREATE ROLE and ALTER ROLE operations.
    SELECT EXISTS (SELECT 1 FROM pg_catalog.pg_roles WHERE rolname = passcheck_hook.username)
    INTO user_exists;
    RAISE DEBUG 'user_exists: %', user_exists;
    
    -- Determine the user's most prioritized PCI role
    user_priority_role := password_check.get_member_priority_role(username);
    
    RAISE DEBUG 'user_exists: %, user_priority_role: %', user_exists, user_priority_role;
    
    -- 1. Determine Role-Based Policies (from password_check.profiles table)
    -- For CREATE ROLE, we allow a default policy. For ALTER ROLE, we enforce role membership.
    -- user_exists = TRUE -> User already exists. It's an alter user statement.
    -- user_exists = FALSE -> User still doesn't exist. It's a create user statement.
    SELECT
      min_length,
      require_special_char,
      require_uppercase,
      require_lowercase,
      require_digit,
      history_limit,
      max_validity_interval
    INTO
      current_min_length,
      current_require_special_char,
      current_require_uppercase,
      current_require_lowercase,
      current_require_digit,
      current_history_limit,
      current_max_validity_interval
    FROM
      password_check.profiles
    WHERE
      role = user_priority_role;

    RAISE DEBUG 'Policy: % for user %', user_priority_role, username;


    IF user_exists and user_priority_role = 'pci_new_users'  THEN
      -- If the user exists but does not belong to any defined PCI role, prevent password change.
      RAISE EXCEPTION 'Password change not allowed for user %: User must be assigned to one of the defined PCI roles (pci_admin_users, pci_app_users, pci_standard_users).', username; -- Added pci_new_users
    ELSIF NOT user_exists and user_priority_role = 'pci_new_users'  THEN
      RAISE NOTICE 'Policy: Default for NEW user (CREATE ROLE)';
      RAISE NOTICE 'ACTION REQUIRED: Assign a PCI ROLE to the user IMMEDIATELY after creation.'; -- Clarified action
      --Delete old password History to prevent conflict with previously existing useres.
      DELETE FROM 
        password_check.password_history ph
      WHERE
        ph.username = passcheck_hook.username;

      --_username_param := username;
      
      RAISE DEBUG 'CREATE USER -> Enforce a reset upon the next user login. passcheck_hook.username: %', passcheck_hook.username;
      --CREATE USER -> Enforce a reset upon the next user login.
      INSERT INTO password_check.user_login_activity(username, password_reset_required, password_first_login)
      VALUES (passcheck_hook.username, true, true)
      ON CONFLICT (username) DO UPDATE
      SET 
        password_reset_required = true,
        password_first_login = true
      WHERE password_check.user_login_activity.username = EXCLUDED.username;

      
      RAISE DEBUG 'password_reset_required: %, password_first_login: %', (select password_reset_required from password_check.user_login_activity where password_check.user_login_activity.username = passcheck_hook.username), (select password_first_login from password_check.user_login_activity where password_check.user_login_activity.username = passcheck_hook.username);

    END IF;

    -- 2. Apply Password Complexity Checks (PCI DSS 8.3.6 and 8.6.3)
    -- These checks use the policy parameters determined by the user's role.
    
    -- Check if the password type is PASSWORD_TYPE_PLAINTEXT. The complexity of the password can only be checked if it is not encrypted.
    IF password_type != 'PASSWORD_TYPE_PLAINTEXT' THEN
      -- If strict enforcement is desired, replace RAISE WARNING with RAISE EXCEPTION.
      RAISE WARNING 'Password type % will not allow Complexity Checks (PCI DSS 8.3.6 and 8.6.3). Consider enforcing TEXT or MD5 for full complexity validation.', password_type; -- Clarified warning
    END IF;

    IF length(password) < current_min_length THEN
      invalid_pw_reason := invalid_pw_reason || 'Password must be at least ' || current_min_length || ' characters long. ';
    END IF;
    IF current_require_uppercase AND password !~ '[A-Z]' THEN
      invalid_pw_reason := invalid_pw_reason || 'Password must contain at least one uppercase letter. ';
    END IF;
    IF current_require_lowercase AND password !~ '[a-z]' THEN
      invalid_pw_reason := invalid_pw_reason || 'Password must contain at least one lowercase letter. ';
    END IF;
    IF current_require_digit AND password !~ '[0-9]' THEN
      invalid_pw_reason := invalid_pw_reason || 'Password must contain at least one number. ';
    END IF;
    IF current_require_special_char AND password !~ '[^a-zA-Z0-9\s]' THEN
      invalid_pw_reason := invalid_pw_reason || 'Password must contain at least one special character. ';
    END IF;
    
    -- Note on PASSWORD_TYPE_SCRAM_SHA_256 and Reusability/Dictionary Checks:
    -- SCRAM-SHA-256 generates a new salt every time a new password is set, making it
    -- impossible to compare directly with old password hashes for reusability checks
    -- using crypt(). This also impacts the ability to check against common/dictionary passwords
    -- directly within the hook if only the hash is available.
    IF password_type IN ('PASSWORD_TYPE_PLAINTEXT','PASSWORD_TYPE_MD5') THEN
      -- Hash the new password using crypt() for secure comparison.
      -- The gen_salt() function generates a new salt for each hash.
      new_password_hashed := crypt(password, gen_salt('bf')); -- 'bf' for Blowfish, a strong algorithm

    ELSE
      -- If the password type is SCRAM-SHA-256, we cannot perform crypt() based reusability checks.
      new_password_hashed := password; -- Assign original password (or a placeholder) as hash won't be comparable
      -- If strict enforcement is desired, replace RAISE WARNING by RAISE EXCEPTION.
      -- This warning does not affect how PostgreSQL stores the password, which is controlled by the
      -- 'password_encryption' parameter in postgresql.conf. The 'password_type' in the hook function
      -- merely informs if the password was already encrypted before being passed to the hook.
      -- Tools like psql's \password command encrypt the password before passing it on, often resulting
      -- in PASSWORD_TYPE_SCRAM_SHA_256.
      RAISE WARNING 'Password type % may not allow full password reusability (PCI DSS 8.3.7) or common/dictionary password checks (PCI DSS 8.3.8) within this hook. Consider enforcing TEXT or MD5 for these checks.', password_type;
    END IF;
    
    -- 3. Apply Password Reusability Check (PCI DSS 8.3.7)
    -- Only perform this check if the user already exists (i.e., it's an ALTER USER operation)
    -- and the password type allows for comparison. For CREATE USER, there's no history yet.
    IF user_exists AND password_type IN ('PASSWORD_TYPE_PLAINTEXT','PASSWORD_TYPE_MD5') THEN
      OPEN history_cursor(current_history_limit);
      LOOP
        FETCH history_cursor INTO old_password_hash;
        EXIT WHEN NOT FOUND;
      
        -- Compare the new password hash with the old password hash.
        -- crypt(password, old_password_hash) re-hashes 'password' using the salt from 'old_password_hash'
        -- and compares it to 'old_password_hash'. This is the standard way to verify passwords with crypt().
        IF crypt(password, old_password_hash) = old_password_hash THEN
          invalid_pw_reason := invalid_pw_reason || format('Password cannot be one of the previous %1$s passwords. ', current_history_limit);
          EXIT; -- No need to check further if a match is found
        END IF;
      END LOOP;
      CLOSE history_cursor;
    END IF;


    --4. ompare password choices to a list of unacceptable passwords. (PCI DSS 8.3.8 Compliance (Good Practice))
    IF password_type IN ('PASSWORD_TYPE_PLAINTEXT') THEN
      
      IF password_check.is_bad_password(password) THEN
        invalid_pw_reason := invalid_pw_reason || 'Password is too common, known to be insecure, or a default value. Please choose a different password.';
      END IF;
    ELSE
      RAISE WARNING 'Password type % common/dictionary password checks (PCI DSS 8.3.8) within this hook. Consider enforcing TEXT for these checks.', password_type;
    END IF;

  
    -- 5. Enforce Password Validity Period (PCI DSS 8.3.9 & 8.6.3)
    -- Ensure the account is not created/updated with "VALID UNTIL NULL".
    IF valid_null THEN
      invalid_pw_reason := invalid_pw_reason || 'New user password must have a "VALID UNTIL" date. "VALID UNTIL NULL" is not allowed. '; -- Added space for consistency
    -- Ensure the "VALID UNTIL" clause is not specified beyond the maximum allowed validity interval for the role.
    ELSE
      IF valid_until > (NOW() + current_max_validity_interval) THEN
        invalid_pw_reason := invalid_pw_reason || 'Account validity date cannot be more than ' || current_max_validity_interval || ' in the future for this role. ';
      END IF;
    END IF;
    
    -- 6. Final Check and Raise Exception
    -- If any validation failed, raise an exception to prevent the password change.
    IF invalid_pw_reason != '' THEN
      RAISE EXCEPTION 'Password validation failed for user %: %', username, invalid_pw_reason;
    ELSE
      -- Assign the parameter to the local variable for safe insertion/deletion
      _username_param := username;
      
      -- 7. Update Password History (only if validation passed)
      -- If the password change is allowed, record the new password's hash and its valid_until date in the history.
      -- This ensures we maintain the history for future reusability checks and track expiration.
      INSERT INTO password_check.password_history (username, password_hash, valid_until)
      VALUES (_username_param, new_password_hashed, NOW() + current_max_validity_interval);
      
      -- 8. Prune Old Password History
      -- This keeps the password_history table clean and adheres to the "previous four" requirement (plus the new one).
      -- Delete older entries for this user, keeping only the most recent 'current_history_limit' entries.
      DELETE FROM password_check.password_history ph_old
      WHERE ph_old.username = _username_param
        AND ph_old.change_timestamp < (
            SELECT ph_latest.change_timestamp
            FROM password_check.password_history ph_latest
            WHERE ph_latest.username = _username_param
            ORDER BY ph_latest.change_timestamp DESC
            OFFSET current_history_limit
            LIMIT 1
        );
      
      IF user_exists and user_priority_role != 'pci_new_users'  THEN

        RAISE DEBUG 'Set password_reset_required to FALSE. user_exists: %, user_priority_role: %', user_exists, user_priority_role;
        --Clear the password_reset_required flag upon successful password change
        UPDATE password_check.user_login_activity la
        SET 
          password_reset_required = FALSE,
          password_first_login = FALSE
        WHERE la.username = _username_param;
      END IF;

    END IF;
  
  END;
  $_FUNCTION_$ LANGUAGE PLPGSQL;
  
  -- Revoke and grant execute privileges to ensure the functions can be called by pg_tle.
  REVOKE ALL ON FUNCTION password_check.passcheck_hook(TEXT, TEXT, pgtle.password_types, TIMESTAMPTZ, BOOLEAN) FROM PUBLIC;
  GRANT EXECUTE ON FUNCTION password_check.passcheck_hook(TEXT, TEXT, pgtle.password_types, TIMESTAMPTZ, BOOLEAN) TO PUBLIC;
  -- Register the updated passcheck_hook function with pg_tle.
  SELECT pgtle.register_feature_if_not_exists('password_check.passcheck_hook', 'passcheck');
  
  -- Register the clientauth hook.
  REVOKE ALL ON FUNCTION password_check.clientauth_hook(pgtle.clientauth_port_subset, INTEGER) FROM PUBLIC;
  GRANT EXECUTE ON FUNCTION password_check.clientauth_hook(pgtle.clientauth_port_subset, INTEGER) TO PUBLIC;
  SELECT pgtle.register_feature_if_not_exists('password_check.clientauth_hook', 'clientauth');

  -- Grant execute privileges for the remove bad accounts helper function.
  REVOKE ALL ON FUNCTION password_check.remove_bad_password(TEXT) FROM PUBLIC;
  GRANT EXECUTE ON FUNCTION password_check.remove_bad_password(TEXT) TO PUBLIC;

  -- Grant execute privileges for the add_bad_password helper function.
  REVOKE ALL ON FUNCTION password_check.add_bad_password(TEXT) FROM PUBLIC;
  GRANT EXECUTE ON FUNCTION password_check.add_bad_password(TEXT) TO PUBLIC;
  
  -- Grant execute privileges for the is_bad_password helper function.
  REVOKE ALL ON FUNCTION password_check.is_bad_password(TEXT) FROM PUBLIC;
  GRANT EXECUTE ON FUNCTION password_check.is_bad_password(TEXT) TO PUBLIC;

  $_pgtle_$
);

-- The following ALTER SYSTEM commands are examples for configuration and require manual execution
-- outside of the update path script, typically after the extension update is applied.

-- ALTER SYSTEM SET pgtle.clientauth_users_to_skip TO 'postgres';
-- SELECT pg_catalog.pg_reload_conf();
--
-- ALTER SYSTEM SET pgtle.enable_clientauth TO 'on';
-- IMPORTANT: This setting requires a database restart to take full effect.
-- Context: SIGHUP. Note: A database restart is needed to enable the clientauth feature, i.e. to switch from off to on or require


-- Useful queries for verification after update:
-- SELECT name, setting, short_desc, context FROM pg_settings WHERE name LIKE 'pgtle%' ORDER BY 1;
-- SELECT * FROM pgtle.available_extensions();
-- SELECT * FROM pgtle.available_extension_versions();
-- SELECT * FROM pgtle.extension_update_paths('pci_password_check_rules');
-- ALTER EXTENSION pci_password_check_rules UPDATE TO '0.6';
-- SELECT pgtle.set_default_version('pci_password_check_rules', '0.6'); -- Example to revert default version
-- \dx -- To list installed extensions and their versions


-- Test Cases:
--
--	Test Case 1. Account get locked after 10 attempts. --Success
--		--Repeat 10 times
--		postgres@sasuke-v:~$ psql -U myuser2 -d heydbamaint
--		Password for user myuser2:
--		psql: error: connection to server on socket "/var/run/postgresql/.s.PGSQL.5432" failed: FATAL:  password authentication failed for user "myuser2"
--		
--		--After the 10th time, issue the correct password
--		postgres@sasuke-v:~$ psql -U myuser2 -d heydbamaint
--		Password for user myuser2:
--		psql: error: connection to server on socket "/var/run/postgresql/.s.PGSQL.5432" failed: FATAL:  Account myuser2 has been locked due to too many failed authentication attempts. Try again after 2025-07-18 13:13:13.032366+00.
--		
--		--as superuser
--		heydbamaint=# select * from password_check.locked_accounts;
--		username |         locked_until          | locked_by
---		---------+-------------------------------+-----------
--		myuser2  | 2025-07-18 13:13:13.032366+00 | SYSTEM
--
--	Test Case 2. After a successfull login, the correct profile policies are selected? --Success
--		postgres@sasuke-v:~$ psql -U myuser2 -d heydbamaint
--		--Debug Log Message shows the correct profile
--		2025-07-18 12:35:44.448 UTC [6016] DEBUG:  Test case 2: Role-Based Policies: current_lockout_threshold: 10, current_lockout_duration_minutes: 30, Priority Role: pci_standard_users
--		--On a different session as superuser (postgres)
--		heydbamaint=# select * from password_check.v_role_members_parameters where username='myuser2';
--		username |        role        | max_validity_interval | lockout_threshold | lockout_duration_minutes | inactive_threshold
---		---------+--------------------+-----------------------+-------------------+--------------------------+--------------------
--		myuser2  | pci_standard_users | 90 days               |                10 |                       30 | 90 days
--
--	Test Case 3: Account is removed from password_check.locked_accounts after the lockout period ends. --Success
--		--After entering a wrong password, having the account locked, it was removed from password_check.locked_accounts. -> I believe its fine, given the lockout period passed.
--		heydbamaint=# select * from password_check.locked_accounts;
--		username |         locked_until          | locked_by
--		----------+-------------------------------+-----------
--		myuser2  | 2025-07-18 13:13:13.032366+00 | SYSTEM
--		(1 row)
--		
--		postgres@sasuke-v:~$ psql -U myuser2 -d heydbamaint
--		Password for user myuser2:
--		psql: error: connection to server on socket "/var/run/postgresql/.s.PGSQL.5432" failed: FATAL:  password authentication failed for user "myuser2"
--
--		heydbamaint=# select * from password_check.locked_accounts;
--		username | locked_until | locked_by
--		----------+--------------+-----------
--		(0 rows)
--		
--		--Evidence shown in the log that the account was removed from password_check.locked_accounts
--		2025-07-18 13:59:58.990 UTC [6016] DEBUG:  Test Case 3: Account is removed from password_check.locked_accounts after the lockout period ends. Rows found: 0
--
--	
--	Test Case 4: After a Failed login attemp, the failed_attempts column on table password_check.user_login_activity is incremented --Success
--	Test Case 5: After a successfull login, the failed_attempts column on table password_check.user_login_activity is restarted. --Success
--		--as postgres on a different session
--		heydbamaint=# select * from password_check.user_login_activity order by username;
--		username |     last_successful_login     | failed_attempts |         last_activity
--		----------+-------------------------------+-----------------+-------------------------------
--		forum    | 2025-07-17 23:59:57.267669+00 |               0 | 2025-07-17 23:59:57.267669+00
--		myuser   | 2025-07-18 12:30:23.683435+00 |               0 | 2025-07-18 12:30:23.683435+00
--		myuser2  | 2025-07-18 12:33:34.208427+00 |               0 | 2025-07-18 12:33:34.208427+00
--		(3 rows)
--		postgres@sasuke-v:~$ psql -U myuser2 -d heydbamaint
--		Password for user myuser2:
--		psql: error: connection to server on socket "/var/run/postgresql/.s.PGSQL.5432" failed: FATAL:  password authentication failed for user "myuser2"
--		
--		--as postgres on a different session
--		heydbamaint=# select * from password_check.user_login_activity order by username;
--		username |     last_successful_login     | failed_attempts |         last_activity
--		----------+-------------------------------+-----------------+-------------------------------
--		forum    | 2025-07-17 23:59:57.267669+00 |               0 | 2025-07-17 23:59:57.267669+00
--		myuser   | 2025-07-18 12:30:23.683435+00 |               0 | 2025-07-18 12:30:23.683435+00
--		myuser2  | 2025-07-18 12:33:34.208427+00 |               1 | 2025-07-18 12:35:19.504637+00
--		(3 rows)
--
--		postgres@sasuke-v:~$ psql -U myuser2 -d heydbamaint
--		Password for user myuser2:
--		psql: error: connection to server on socket "/var/run/postgresql/.s.PGSQL.5432" failed: FATAL:  password authentication failed for user "myuser2"
--
--		--as postgres on a different session
--		heydbamaint=# select * from password_check.user_login_activity order by username;
--		username |     last_successful_login     | failed_attempts |         last_activity
--		----------+-------------------------------+-----------------+-------------------------------
--		forum    | 2025-07-17 23:59:57.267669+00 |               0 | 2025-07-17 23:59:57.267669+00
--		myuser   | 2025-07-18 12:30:23.683435+00 |               0 | 2025-07-18 12:30:23.683435+00
--		myuser2  | 2025-07-18 12:33:34.208427+00 |               2 | 2025-07-18 12:35:26.24181+00
--		(3 rows)
--
--		postgres@sasuke-v:~$ psql -U myuser -d heydbamaint
--		Password for user myuser:
--		psql: error: connection to server on socket "/var/run/postgresql/.s.PGSQL.5432" failed: FATAL:  password authentication failed for user "myuser"
--
--		--as postgres on a different session
--		heydbamaint=# select * from password_check.user_login_activity order by username;
--		username |     last_successful_login     | failed_attempts |         last_activity
--		----------+-------------------------------+-----------------+-------------------------------
--		forum    | 2025-07-17 23:59:57.267669+00 |               0 | 2025-07-17 23:59:57.267669+00
--		myuser   | 2025-07-18 12:30:23.683435+00 |               1 | 2025-07-18 12:35:34.192406+00
--		myuser2  | 2025-07-18 12:33:34.208427+00 |               2 | 2025-07-18 12:35:26.24181+00
--		(3 rows)
--
--		postgres@sasuke-v:~$ psql -U myuser2 -d heydbamaint
--		Password for user myuser2:
--		psql (16.9 (Ubuntu 16.9-0ubuntu0.24.04.1))
--		Type "help" for help.
--		
--		heydbamaint=>
--
--		--as postgres on a different session
--		heydbamaint=# select * from password_check.user_login_activity order by username;
--		username |     last_successful_login     | failed_attempts |         last_activity
--		----------+-------------------------------+-----------------+-------------------------------
--		forum    | 2025-07-17 23:59:57.267669+00 |               0 | 2025-07-17 23:59:57.267669+00
--		myuser   | 2025-07-18 12:30:23.683435+00 |               1 | 2025-07-18 12:35:34.192406+00
--		myuser2  | 2025-07-18 12:35:44.447696+00 |               0 | 2025-07-18 12:35:44.447696+00
--		(3 rows)
--	
--	Test Case 6: Check the password_check.manage_inactive_accounts will disable accounts inactive for more than the threshold time. --Success
--		heydbamaint=# select * from password_check.user_login_activity;
--		username |     last_successful_login     | failed_attempts |         last_activity
--		---------+-------------------------------+-----------------+-------------------------------
--		myuser   | 2025-07-18 12:30:23.683435+00 |               1 | 2025-07-18 12:35:34.192406+00
--		myuser2  | 2025-07-18 14:02:25.113683+00 |               0 | 2025-07-18 14:02:25.113683+00
--		forum    | 2025-04-17 23:59:57.267669+00 |               0 | 2025-07-17 23:59:57.267669+00
--		evandro  | 2025-04-19 14:09:42.494397+00 |               0 | 2025-07-18 14:11:34.676606+00
--		
--		heydbamaint=# select password_check.manage_inactive_accounts();
--		NOTICE:  Account evandro disabled due to inactivity.
--		manage_inactive_accounts
--		--------------------------
--		
--		(1 row)
--		
--		heydbamaint=# \du evandro
--			List of roles
--		Role name |  Attributes
---		----------+--------------
--		evandro   | Cannot login
--
--	Test Case 7: The user can't be created with a password from the Bad password list. --Success
--		heydbamaint=# create user myuser4 with password 'daewuu';
--		ERROR:  Password validation failed for user myuser4: Password must be at least 12 characters long. Password must contain at least one uppercase letter. Password must contain at least one number. Password must contain at least one special character. Password is too common, known to be insecure, or a default value. Please choose a different password.New user password must have a "VALID UNTIL" date. "VALID UNTIL NULL" is not allowed.
--	
--	Test Case 8: The user can't update its own password with a password from the Bad password list. --Success
--		heydbamaint=> select user;
--		user
--		---------
--		evandro
--		(1 row)
--		
--		heydbamaint=> alter user evandro with password 'daewuu';
--		ERROR:  Password validation failed for user evandro: Password must be at least 15 characters long. Password must contain at least one uppercase letter. Password must contain at least one number. Password must contain at least one special character. Password is too common, known to be insecure, or a default value. Please choose a different password.
--
--	Test Case 9: The superuser can't update a user's password with a password from the Bad password list. --Success
--		heydbamaint=# alter user evandro with password 'daewuu';
--		ERROR:  Password validation failed for user evandro: Password must be at least 15 characters long. Password must contain at least one uppercase letter. Password must contain at least one number. Password must contain at least one special character. Password is too common, known to be insecure, or a default value. Please choose a different password.