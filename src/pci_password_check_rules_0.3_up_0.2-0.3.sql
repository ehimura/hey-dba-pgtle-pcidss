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
-- Version 0.3 Update Path (Part 5: The Ghost of Passwords Past – Battling Reusability with pgtle)
-- This script updates the 'pci_password_check_rules' pg_tle extension from version 0.2 to 0.3.
-- It adds functionality to enforce PCI DSS 4.0.1 Requirement 8.3.7: password reusability.

--0.3 changes:
--	.Add table password_check.password_history.
--		. This table will store hashed versions of previous passwords for each user.
--	.Add column history_limit to table password_check.profiles.
--	.Function changes
--		.Add variable new_password_hashed
--			. This variable will hold the new hashed password.
--		.Add cursor history_cursor
--			. This cursor will be used in the search of historic passwords
--		.Add variable old_password_hash
--			. To be used to fetch the old password hash from the cursor
--		.Add a check to verify if the password_type is either PASSWORD_TYPE_PLAINTEXT or PASSWORD_TYPE_MD5 as PASSWORD_TYPE_SCRAM_SHA_256 won't prevent reusability or bad passwords check.
--		.Add a check for password_type != 'PASSWORD_TYPE_PLAINTEXT' before the Complexity check.
--		.Add the check for password history.
--		.Add variable current_history_limit (used locally)
--		.Modified the queries that fetches the profile parameters to include the history_limit.

-- It is compatible with PostgreSQL 16 and later.

-- IMPORTANT: Before running this script, ensure you have:
--	1. pci_password_check_rules version 0.2
--	2. IMPORTANT: Ensure the 'pgcrypto' extension is installed in your pgtle.passcheck_db_name database
--		(e.g., heydbamaint) for password hashing.
--		CREATE EXTENSION IF NOT EXISTS pgcrypto;


SELECT
	pgtle.install_update_path (
		'pci_password_check_rules', -- Name of your custom pg_tle extension
		'0.2',                      -- The version this update path is from
		'0.3',                      -- The version this update path goes to (new version)
		$_pgtle_$

  CREATE TABLE IF NOT EXISTS password_check.password_history (
    username TEXT NOT NULL,
    password_hash TEXT NOT NULL,
    change_timestamp TIMESTAMPTZ DEFAULT NOW() NOT NULL,
    PRIMARY KEY (username, change_timestamp) -- Composite primary key for uniqueness and ordering
  );
  
  -- Create an index on username for efficient lookups when checking history.
  CREATE INDEX IF NOT EXISTS idx_password_history_username ON password_check.password_history (username);
  
  
  -- Add a column to the profiles table to control the password reusability (8.3.7)
  ALTER TABLE password_check.profiles
    ADD COLUMN IF NOT EXISTS history_limit INTEGER DEFAULT 4 NOT NULL;


  -- The main passcheck hook function that enforces password policies.
  CREATE
  OR REPLACE FUNCTION password_check.passcheck_hook (
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
      --RAISE NOTICE '  user_exists: %', user_exists;
      
      -- 1. Determine Role-Based Policies (from password_check.profiles table)
      -- For CREATE ROLE, we allow a default policy. For ALTER ROLE, we enforce role membership.
      IF user_exists AND password_check.is_member_of_role(username, 'pci_admin_users') THEN
    	
    	  SELECT 
    	    min_length,
    	    require_special_char,
    	    require_uppercase,
    	    require_lowercase,
    	    require_digit,
            history_limit
    	  INTO
    	    current_min_length,
            current_require_special_char,
            current_require_uppercase,
            current_require_lowercase,
            current_require_digit,
            current_history_limit
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
            history_limit
    	  INTO
    	    current_min_length,
            current_require_special_char,
            current_require_uppercase,
            current_require_lowercase,
            current_require_digit,
            current_history_limit
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
            history_limit		
    	  INTO
    	    current_min_length,
            current_require_special_char,
            current_require_uppercase,
            current_require_lowercase,
            current_require_digit,
            current_history_limit
    	  FROM 
    	    password_check.profiles
    	  WHERE
    	    role='pci_app_users';

    	--If the user does not exists (It's a CREATE ROLE), allow it to be created and set the default password rules.
    	--Later, the user will not be allowed to CHANGE THE PASSWORD if not set to any of the PCI roles.
      ELSIF NOT user_exists THEN
        SELECT 
    	    min_length,
    	    require_special_char,
    	    require_uppercase,
    	    require_lowercase,
    	    require_digit,
            history_limit
    	  INTO
    	    current_min_length,
            current_require_special_char,
            current_require_uppercase,
            current_require_lowercase,
            current_require_digit,
            current_history_limit
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
        INSERT INTO password_check.password_history (username, password_hash)
        VALUES (_username_param, new_password_hashed);
  		
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

    $_pgtle_$
);


--SELECT * FROM pgtle.available_extensions();
--SELECT * FROM pgtle.available_extension_versions();
--SELECT * FROM pgtle.extension_update_paths('pci_password_check_rules');

--ALTER EXTENSION pci_password_check_rules UPDATE TO '0.3';
--select pgtle.set_default_version('pci_password_check_rules', '0.3');

