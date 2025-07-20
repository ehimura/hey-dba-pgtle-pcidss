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
 --0.4 changes:
-- Version 0.4 Update Path (Part 6: The Sands of Time – Enforcing Change Frequency and Dealing with Inactive Accounts)
-- This script updates the 'pci_password_check_rules' pg_tle extension from version 0.3 to 0.4.
-- Enforce
-- The PCI DSS Mandate: Time Waits for No Password (PCI DSS 8.3.9 & 8.6.3)
-- 	. Requirement 8.3.9: Change user passwords/passphrases at least every 90 days.
--	. Requirement 8.6.3: Application and System Accounts Password Changes.
--		. Introduce the current_max_validity_interval INTERVAL to control the "Valid Until" clause.
-- These requirements are met through the enforcement of the "VALID UNTIL" clause of the CREATE USER statement.
--
--
-- Changes:
--	The enforcement of the "VALID UNTIL" clause of the create role statement will make sure the passwords are always updated within the interval.
-- 	. Add column max_validity_interval to password_check.profiles
--  The enforcement of a NEW PASSWORD after the password validity has expired.
--	. Add column valid_until to password_check.password_history
--	. Add a UPDATE STATEMENT to update all records of password_check.password_history with the calculated valid_until for every row.
--	. passcheck_hook Function changes:
--		. Add variable current_max_validity_interval to receive the value max_validity_interval from the profile table
--		. Add logic to make sure "VALID UNTIL" is not set to NULL.
--		. Add logic to verify if the "VALID UNTIL" clause is not set above the maximum allowed for the role.
--		. Include the valid_until column on the password_check.password_history INSERT after a new password is set.
--	. Create the clientauth_hook
--		. Add logic to prevent the user from logging in if the password validity has expired.

-- It is compatible with PostgreSQL 16 and later.

-- IMPORTANT: Before running this script, ensure you have:
--	1. pci_password_check_rules version 0.3

--select pgtle.uninstall_update_path('pci_password_check_rules', '0.3', '0.4');

SELECT
	pgtle.install_update_path (
		'pci_password_check_rules', -- Name of your custom pg_tle extension
		'0.3',                      -- The version this update path is from
		'0.4',                      -- The version this update path goes to (new version)
		$_pgtle_$

  -- Add a column to the profiles table to control Time Waits for No Password (PCI DSS 8.3.9 & 8.6.3)
  ALTER TABLE password_check.profiles
    ADD COLUMN IF NOT EXISTS max_validity_interval INTERVAL DEFAULT '90 days';
  
  UPDATE password_check.profiles set max_validity_interval = '1 year' where role = 'pci_app_users';
  UPDATE password_check.profiles set max_validity_interval = '15 minutes' where role = 'pci_new_users';
  UPDATE password_check.profiles set max_validity_interval = '30 days' where role = 'pci_admin_users';
  
  -- Add a column to control the password validity. This differ from the "VALID UNTIL" clause of the CREATE USER statement and will control when the password must be changed rather than when the account will be unable to login.
  ALTER TABLE password_check.password_history
    ADD COLUMN IF NOT EXISTS valid_until TIMESTAMPTZ;

  --Update password_check.password_history's valid_until based on the max_validity_interval of the User's assigned roles (using a priority rule)
  UPDATE PASSWORD_CHECK.PASSWORD_HISTORY PH
  SET
	VALID_UNTIL = PH.CHANGE_TIMESTAMP + (
		WITH
			PROFILES AS (
				SELECT
					CASE P.ROLE
						WHEN 'pci_new_users' THEN 1
						WHEN 'pci_admin_users' THEN 2
						WHEN 'pci_app_users' THEN 3
						WHEN 'pci_standard_users' THEN 4
					END AS PRIORITY,
					P.ROLE,
					P.MAX_VALIDITY_INTERVAL
				FROM
					PASSWORD_CHECK.PROFILES P
				ORDER BY
					1
			),
			MEMBERS AS (
				SELECT
					R_MEMBER.ROLNAME AS MEMBER,
					R_ROLE.ROLNAME AS ROLE,
					PR.MAX_VALIDITY_INTERVAL,
					ROW_NUMBER() OVER (
						PARTITION BY
							R_MEMBER.ROLNAME
						ORDER BY
							PR.PRIORITY
					) AS RN
				FROM
					PG_CATALOG.PG_ROLES AS R_MEMBER
					JOIN PG_CATALOG.PG_AUTH_MEMBERS AS AM ON R_MEMBER.OID = AM.MEMBER
					JOIN PG_CATALOG.PG_ROLES AS R_ROLE ON AM.ROLEID = R_ROLE.OID
					JOIN PROFILES PR ON PR.ROLE = R_ROLE.ROLNAME
			)
		SELECT
			--member, 
			--role,
			M.MAX_VALIDITY_INTERVAL
		FROM
			MEMBERS M
		WHERE
			RN = 1
			AND M.MEMBER = PH.USERNAME
	);
  
  update password_check.password_history ph
  SET
    valid_until = ph.change_timestamp + '15 minutes'::INTERVAL
  WHERE 
    valid_until is null;
  
  ALTER TABLE password_check.password_history
    ALTER COLUMN valid_until SET NOT NULL;

  -- clientauth hook function
  -- This function is called by pg_tle after any authentication attempt.
  -- It checks if the account is locked and prevents login.
  -- It tracks FAILED authentication attempts and locks the account if a threshold is reached.
  CREATE OR REPLACE FUNCTION PASSWORD_CHECK.CLIENTAUTH_HOOK (
    PORT PGTLE.CLIENTAUTH_PORT_SUBSET, -- Now receives the port object
    STATUS INTEGER -- Now receives the authentication status
) RETURNS VOID AS $$
  DECLARE
    l_username TEXT := port.user_name; -- Extract username from the port object
    current_valid_until TIMESTAMPTZ;
  BEGIN
  
    -- 1. Determine if password is still valid: (PCI DSS 8.3.9 & 8.6.3)
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
    
  END;
  $$ LANGUAGE PLPGSQL SECURITY DEFINER;
  
  
  -- The main passcheck hook function that enforces password policies.
  CREATE OR REPLACE FUNCTION PASSWORD_CHECK.PASSCHECK_HOOK (
    USERNAME TEXT,
    PASSWORD TEXT,
    PASSWORD_TYPE PGTLE.PASSWORD_TYPES,
    VALID_UNTIL TIMESTAMPTZ,
    VALID_NULL BOOLEAN
) RETURNS VOID AS $_FUNCTION_$ -- ADDED THIS BLOCK LABEL
  DECLARE
    invalid_pw_reason TEXT := '';

    current_min_length INTEGER := 12;
    current_require_special_char BOOLEAN := TRUE;
    current_require_uppercase BOOLEAN := TRUE;
    current_require_lowercase BOOLEAN := TRUE;
    current_require_digit BOOLEAN := TRUE;
    current_history_limit INTEGER := 4;
    current_max_validity_interval INTERVAL;
    
    -- Add on 0.2: Flag to check if the user already exists in pg_roles
    -- This helps differentiate between CREATE ROLE and ALTER ROLE.
    user_exists BOOLEAN;

    -- Variable to store the hashed version of the new password.
    new_password_hashed TEXT;
    
    -- Cursor to iterate through previous password hashes.
    history_cursor CURSOR (cur_history_limit INTEGER) FOR
      SELECT h.password_hash
      FROM password_check.password_history h
      WHERE h.username = passcheck_hook.username
      ORDER BY h.change_timestamp DESC
      LIMIT cur_history_limit; -- PCI DSS 8.3.7: must be different from previous four.
    
    -- Variable to hold a hash from the history cursor.
    old_password_hash TEXT;

    -- Local variable for ambiguity resolution in INSERT/DELETE statements
    _username_param TEXT;

  BEGIN

    -- Check if the user already exists in pg_roles.
    -- This helps differentiate between CREATE ROLE and ALTER ROLE.
    SELECT EXISTS (SELECT 1 FROM pg_catalog.pg_roles WHERE rolname = passcheck_hook.username)
    INTO user_exists;
    
    -- 1. Determine Role-Based Policies (from password_check.profiles table)
    -- For CREATE ROLE, we allow a default policy. For ALTER ROLE, we enforce role membership.
    IF user_exists AND password_check.is_member_of_role(username, 'pci_admin_users') THEN
    
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
        role='pci_admin_users';
    ELSIF user_exists AND password_check.is_member_of_role(username, 'pci_app_users') THEN -- NOW FOR NON-HUMAN APP ACCOUNTS
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
        role='pci_app_users';
    ELSIF user_exists AND password_check.is_member_of_role(username, 'pci_standard_users') THEN
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
        role='pci_standard_users';
    --If the user does not exists (It's a CREATE ROLE), allow it to be created and set the default password rules.
    --Later, the user will not be allowed to CHANGE THE PASSWORD if not set to any of the PCI roles.
    ELSIF NOT user_exists THEN
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
        role='pci_new_users';
        
      RAISE NOTICE 'Policy: Default for NEW user (CREATE ROLE)';
      RAISE NOTICE 'Assign a PCI ROLE to the user IMMEDIATELY';

    ELSE
      -- If the user exists but does not belong to any defined PCI role, prevent password change.
      RAISE EXCEPTION 'Password change not allowed for user %: User must be assigned to one of the defined roles (pci_admin_users, pci_app_users, pci_standard_users).', username;
    END IF;

    -- 2. Apply Password Complexity Checks (PCI DSS 8.3.6 and 8.6.3)
    -- These checks use the policy parameters determined by the user's role.
    
    -- Check if the password type is PASSWORD_TYPE_PLAINTEXT. The Complexity of the password can only be checked if its not encrypted.
    IF password_type != 'PASSWORD_TYPE_PLAINTEXT' THEN
      -- If we want to prevent it from continuing, replace RAISE WARNING by RAISE EXCEPTION.
      RAISE WARNING 'Password type % will not allow Complexity Checks (PCI DSS 8.3.6 and 8.6.3)', password_type;
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
    
    -- PASSWORD_TYPE_SCRAM_SHA_256 WILL NOT PREVENT from password reusability.
    -- It generates a new salt every time a new password is set, what makes it impossible to compare with old passwords.
    IF password_type in ('PASSWORD_TYPE_PLAINTEXT','PASSWORD_TYPE_MD5') THEN
      -- Hash the new password using crypt() for secure comparison.
      -- The gen_salt() function generates a new salt for each hash.
      new_password_hashed := crypt(password, gen_salt('bf')); -- 'bf' for Blowfish, a strong algorithm
    ELSE
      -- This doesn't make any difference, but to allow the function to proceed.
      new_password_hashed := password;
      -- If we wish to prevent from PASSWORD_TYPE_SCRAM_SHA_256 to be used by the HOOK, just replace RAISE WARNING by RAISE EXCEPTION.
      -- This doesn't affect the way postgresql stores the password, as it is controled by the postgresql.conf parameter password_encryption.
      -- The password_type in the hook function only inform if the password was already encrypted before being stored. If the password is being updated via "ALTER USER" it will most certainly be PASSWORD_TYPE_PLAINTEXT or PASSWORD_TYPE_MD5. Tools like psql's \password will encrypt the password before passing it on, thus using PASSWORD_TYPE_SCRAM_SHA_256.
      RAISE WARNING 'Password type % may not prevent password reusability (PCI DSS 8.3.7) or common/dictionary passwords (PCI DSS 8.3.5). Please enforce TEXT or MD5', password_type;
      --RAISE EXCEPTION 'Password type % may not prevent password reusability (PCI DSS 8.3.7) or common/dictionary passwords (PCI DSS 8.3.5). Please enforce TEXT or MD5', password_type;
    END IF;
    
    -- 3. Apply Password Reusability Check (PCI DSS 8.3.7)
    -- Only perform this check if the user already exists (i.e., it's an ALTER USER operation).
    -- For CREATE USER, there's no history to check against yet.
    IF user_exists THEN

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

  
    -- Ensure the account is not created with "VALID UNTIL NULL"
    IF valid_null THEN
      invalid_pw_reason := invalid_pw_reason || 'New user password must have a "VALID UNTIL" date. "VALID UNTIL NULL" is not allowed.';
    -- Ensure the "VALID UNTIL" clause is not specified above the maximum value for the role.
    ELSE
      IF valid_until > (NOW() + current_max_validity_interval) THEN
        invalid_pw_reason := invalid_pw_reason || 'Account validity date cannot be more than ' || current_max_validity_interval || ' in the future for this role. ';
      END IF;
    END IF;
    
    -- 4. Final Check and Raise Exception
    -- If any validation failed, raise an exception to prevent the password change.
    IF invalid_pw_reason != '' THEN
      RAISE EXCEPTION 'Password validation failed for user %: %', username, invalid_pw_reason;
    ELSE
      -- Assign the parameter to the local variable for safe insertion/deletion
      _username_param := username;
      
      -- 5. Update Password History (only if validation passed)
      -- If the password change is allowed, record the new password's hash in the history.
      -- This ensures we maintain the history for future reusability checks.
      -- Add the valid_until date to ensure the password will be changed within the maximum interval.
      INSERT INTO password_check.password_history (username, password_hash, valid_until)
      VALUES (_username_param, new_password_hashed, NOW() + current_max_validity_interval);
      
      -- 6. Prune Old Password History (keep only the last 4 + 1 for the current new one, so 5 total)
      -- This keeps the password_history table clean and adheres to the "previous four" requirement.
      -- Delete older entries for this user, keeping only the most recent 'history_limit'
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

    END IF;
  
  END;
  $_FUNCTION_$ LANGUAGE PLPGSQL;
  
  -- Revoke and grant execute privileges to ensure the function can be called by pg_tle.
  REVOKE ALL ON FUNCTION password_check.passcheck_hook(TEXT, TEXT, pgtle.password_types, TIMESTAMPTZ, BOOLEAN) FROM PUBLIC;
  GRANT EXECUTE ON FUNCTION password_check.passcheck_hook(TEXT, TEXT, pgtle.password_types, TIMESTAMPTZ, BOOLEAN) TO PUBLIC;
  -- Register the updated passcheck_hook function with pg_tle.
  SELECT pgtle.register_feature_if_not_exists('password_check.passcheck_hook', 'passcheck');
  
  -- Register the clientauth hook.
  REVOKE ALL ON FUNCTION password_check.clientauth_hook(pgtle.clientauth_port_subset, INTEGER) FROM PUBLIC;
  GRANT EXECUTE ON FUNCTION password_check.clientauth_hook(pgtle.clientauth_port_subset, INTEGER) TO PUBLIC;
  SELECT pgtle.register_feature_if_not_exists('password_check.clientauth_hook', 'clientauth');
  
  $_pgtle_$
);

--ALTER SYSTEM SET pgtle.clientauth_users_to_skip TO 'postgres';
--SELECT pg_catalog.pg_reload_conf();
--
--ALTER SYSTEM SET pgtle.enable_clientauth TO 'on';
--Require a restart
--Context: SIGHUP. Note: A database restart is needed to enable the clientauth feature, i.e. to switch from off to on or require
--

--select name, setting, short_desc, context from pg_settings where name like 'pgtle%' order by 1;

--SELECT * FROM pgtle.available_extensions();
--SELECT * FROM pgtle.available_extension_versions();
--SELECT * FROM pgtle.extension_update_paths('pci_password_check_rules');

--ALTER EXTENSION pci_password_check_rules UPDATE TO '0.4';
--select pgtle.set_default_version('pci_password_check_rules', '0.4');
--\dx
