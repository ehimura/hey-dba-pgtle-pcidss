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
 
--0.5 changes:
-- Version 0.5 Update Path (Part 7: The Bouncer at the Gate – Implementing Account Lockout and Inactive Account Management)
-- This script updates the 'pci_password_check_rules' pg_tle extension from version 0.4 to 0.5.
--
-- Enforce
-- The PCI DSS Mandate: After a maximum of 10 unsuccessful authentication attempts, the account must be locked out for at least 30 minutes, or until an administrator manually unlocks it.
-- 	. Requirement 8.3.4: Account Lockout.
--	The PCI DSS Mandate: User accounts that have not been active for a maximum of 90 days must be either locked or disabled.
--	. Requirement 8.2.6: Lock or disable inactive user accounts after a maximum of 90 days.
--
-- Changes introduced in Version 0.5:
--	. New table `password_check.user_login_activity`: This table serves as the central repository for tracking user login attempts (successful and failed) and their last activity. It's crucial for both account lockout and inactive account management.
--	. New table `password_check.locked_accounts`: This table specifically tracks accounts that are currently locked due to exceeding failed authentication attempts. Entries are added upon lockout and removed when the lockout period expires or an administrator intervenes.
--	. Added columns to `password_check.profiles` table:
--		. `lockout_threshold` (INTEGER): Configurable maximum unsuccessful authentication attempts before lockout (PCI DSS 8.3.4.a).
--		. `lockout_duration_minutes` (INTEGER): Configurable minimum lockout duration in minutes (PCI DSS 8.3.4.b).
--		. `inactive_threshold` (INTERVAL): Configurable maximum inactivity period before an account is disabled (PCI DSS 8.2.6).
--	. New function `password_check.get_member_priority_role`: This helper function dynamically determines the most prioritized PCI role a user belongs to, allowing for flexible, role-based policy application.
--	. Updated `clientauth_hook`: This hook now handles real-time account lockouts, tracks failed login attempts, and updates user activity. It also continues to enforce password expiration from v0.4.
--	. New function `password_check.manage_inactive_accounts`: Designed to be called by an external scheduler (e.g., cron) to identify and disable inactive accounts based on the `inactive_threshold` (Requirement 8.2.6).
--	. New view `password_check.v_role_members_parameters`: Provides a consolidated view of all accounts/users with their priority role and all associated security control parameters.
--
-- Compatibility: This script is compatible with PostgreSQL 16 and later.

-- IMPORTANT: Before running this script, ensure you have:
--	1. pci_password_check_rules version 0.4 installed.

-- To uninstall this update path, if needed:
-- SELECT pgtle.uninstall_update_path('pci_password_check_rules', '0.4', '0.5');

SELECT
	pgtle.install_update_path (
		'pci_password_check_rules', -- Name of your custom pg_tle extension
		'0.4',                      -- The version this update path is from
		'0.5',                      -- The version this update path goes to (new version)
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
  CREATE TABLE IF NOT EXISTS password_check.user_login_activity (
    username TEXT PRIMARY KEY, -- REFERENCES pg_catalog.pg_roles(rolname) -- Conceptual FK, not enforced here to avoid circular dependencies during role creation/deletion
    last_successful_login TIMESTAMPTZ DEFAULT NULL,
    failed_attempts INTEGER DEFAULT 0 NOT NULL,
    last_activity TIMESTAMPTZ DEFAULT NULL -- For PCI 8.2.6
  );


  -- password_check.locked_accounts Table
  -- Purpose: This table specifically tracks user accounts that are currently locked due to
  -- exceeding the failed authentication attempts threshold (PCI DSS 8.3.4).
  -- Entries are added when an account is locked and removed when the lockout period expires
  -- or an administrator manually unlocks it.
  --
  -- Columns:
  --   username (TEXT): The name of the locked user/role. Primary key, references user_login_activity.
  --   locked_until (TIMESTAMPTZ): The timestamp until which the account remains locked.
  --                               Login attempts will be rejected until this time passes.
  --   locked_by (TEXT): Indicates who or what initiated the lockout (e.g., 'SYSTEM' for automated, or an admin's username).
  CREATE TABLE IF NOT EXISTS password_check.locked_accounts (
    username TEXT PRIMARY KEY REFERENCES password_check.user_login_activity(username),
    locked_until TIMESTAMPTZ NOT NULL,
    locked_by TEXT DEFAULT 'SYSTEM' NOT NULL -- Can be 'SYSTEM' or an admin username
  );


  -- Alter password_check.profiles Table
  -- Purpose: Adds new columns to the profiles table to centralize configurable parameters
  -- for account lockout and inactive account management per role. This allows administrators
  -- to define distinct security policies for different user groups.
  --
  -- New Columns:
  --   lockout_threshold (INTEGER): Defines the maximum number of unsuccessful authentication attempts
  --                                allowed before the account is locked out (PCI DSS 8.3.4.a). Default: 10.
  --   lockout_duration_minutes (INTEGER): Specifies the minimum duration in minutes for which an account
  --                                       will remain locked out (PCI DSS 8.3.4.b). Default: 30.
  --   inactive_threshold (INTERVAL): Sets the maximum period of inactivity (e.g., '90 days') after which
  --                                  a user account must be disabled (PCI DSS 8.2.6). Default: '90 days'.
  ALTER TABLE password_check.profiles
    ADD COLUMN IF NOT EXISTS lockout_threshold INTEGER DEFAULT 10,  -- PCI DSS 4.0.1 8.3.4.a: no more than 10 unsuccessful attempts
    ADD COLUMN IF NOT EXISTS lockout_duration_minutes INTEGER DEFAULT 30, -- PCI DSS 4.0.1 8.3.4.b: minimum 30 minutes
    ADD COLUMN IF NOT EXISTS inactive_threshold INTERVAL DEFAULT '90 days'; -- PCI DSS 4.0.1  8.2.6: Inactive user accounts are removed or disabled within 90 days of inactivity.

-- password_check.v_role_members_parameters View
-- Purpose: This view provides a consolidated list of all PostgreSQL users/accounts
-- and their most prioritized PCI role, along with all associated control parameters
-- (max_validity_interval, lockout_threshold, lockout_duration_minutes, inactive_threshold).
-- It simplifies querying and understanding the security policies dynamically applied to each user.
-- The priority for role assignment is defined within the 'profiles' CTE based on the order of roles.
--
-- Example of listing:
 --username |        role        | max_validity_interval | lockout_threshold | lockout_duration_minutes | inactive_threshold
-----------+--------------------+-----------------------+-------------------+--------------------------+--------------------
 --evandro | pci_admin_users    | 30 days               |                10 |                       30 | 90 days
 --myuser  | pci_admin_users    | 30 days               |                10 |                       30 | 90 days
 --myuser2 | pci_standard_users | 90 days               |                10 |                       30 | 90 days
CREATE OR REPLACE VIEW password_check.v_role_members_parameters AS
WITH profiles AS (
  SELECT 
      CASE p.role
        WHEN 'pci_admin_users' then 1
        WHEN 'pci_app_users' then 2
        WHEN 'pci_standard_users' then 3
        WHEN 'pci_new_users' then 4
      END as priority,
      p.role,
      p.max_validity_interval,
      p.lockout_threshold,
      p.lockout_duration_minutes,
      p.inactive_threshold
    FROM
      password_check.profiles p
    ORDER BY 1
    ),
    members as (
      SELECT 
        r_member.rolname as member,
        r_role.rolname as role,
        pr.max_validity_interval,
        pr.lockout_threshold,
        pr.lockout_duration_minutes,
        pr.inactive_threshold,
        ROW_NUMBER() OVER (PARTITION BY r_member.rolname ORDER BY pr.priority) as rn
      FROM pg_catalog.pg_roles AS r_member
      JOIN pg_catalog.pg_auth_members AS am ON r_member.oid = am.member
      JOIN pg_catalog.pg_roles AS r_role ON am.roleid = r_role.oid
      JOIN profiles pr ON pr.role = r_role.rolname
    )
    SELECT 
      m.member as username,
      m.role,
      m.max_validity_interval,
      m.lockout_threshold,
      m.lockout_duration_minutes,
      m.inactive_threshold
    FROM
      members m
    WHERE
      rn=1;


-- password_check.manage_inactive_accounts Function
-- Purpose: This function is responsible for identifying and disabling user accounts
-- that have been inactive for a period exceeding their configured 'inactive_threshold'.
-- It directly addresses PCI DSS Requirement 8.2.6.
--
-- Note: This function does NOT run automatically as part of the pg_tle hook system.
-- It is designed to be called periodically by an external scheduler, such as a cron job
-- on a Linux system or a similar job scheduling service in cloud environments.
--
-- Example Cron Job Entry (runs daily at 3 AM UTC in the 'heydbamaint' database as 'postgres' user):
-- 0 3 * * * psql -d heydbamaint -U postgres -c "SELECT password_check.manage_inactive_accounts();"
CREATE OR REPLACE FUNCTION password_check.manage_inactive_accounts() RETURNS VOID AS $$
DECLARE
  r RECORD;
BEGIN

  FOR r IN 
  SELECT
    l.username
  FROM
    password_check.user_login_activity AS l
    JOIN password_check.v_role_members_parameters AS v ON l.username = v.username
  WHERE
    l.last_successful_login < NOW() - v.inactive_threshold
    AND l.username NOT IN (
      SELECT
        rolname
      FROM
        pg_roles
      WHERE
        rolcanlogin = false
    ) -- Only process active logins (rolcanlogin = true)
  LOOP
    EXECUTE 'ALTER ROLE ' || quote_ident(r.username) || ' NOLOGIN;';
    RAISE NOTICE 'Account % disabled due to inactivity.', r.username;
  END LOOP;
END;
$$ LANGUAGE plpgsql SECURITY DEFINER;


  -- password_check.get_member_priority_role Function
  -- Purpose: This helper function determines the most prioritized PCI role a given user
  -- belongs to. It's used internally by other functions (like clientauth_hook and
  -- manage_inactive_accounts) to dynamically fetch and apply role-based security policies.
  -- The priority is defined within the 'profiles' CTE based on the order of roles.
  CREATE OR REPLACE FUNCTION password_check.get_member_priority_role(
      target_username TEXT
  ) RETURNS TEXT AS $$
  DECLARE
    -- Variable to store the determined priority role name
    group_role_name TEXT := 'pci_new_users'; -- Default to 'pci_new_users' if no specific PCI role is found
  BEGIN

    WITH profiles AS (
      SELECT 
      CASE p.role
        WHEN 'pci_admin_users' then 1
        WHEN 'pci_app_users' then 2
        WHEN 'pci_standard_users' then 3
        WHEN 'pci_new_users' then 4
      END as priority,
      p.role,
      p.max_validity_interval -- This column is not directly used in this function but is part of the profiles CTE
    FROM
      password_check.profiles p
    ORDER BY 1
    ),
    members as (
      SELECT 
        r_member.rolname as member,
        r_role.rolname as role,
        pr.max_validity_interval, -- This column is not directly used in this function but is part of the members CTE
        ROW_NUMBER() OVER (PARTITION BY r_member.rolname ORDER BY pr.priority) as rn
      FROM pg_catalog.pg_roles AS r_member
      JOIN pg_catalog.pg_auth_members AS am ON r_member.oid = am.member
      JOIN pg_catalog.pg_roles AS r_role ON am.roleid = r_role.oid
      JOIN profiles pr ON pr.role = r_role.rolname
    )
    SELECT 
      m.role
    INTO
      group_role_name
    FROM
      members m
    WHERE
      rn=1 AND
      m.member = target_username;
      
    -- If the user is not a member of any defined PCI role, assign 'pci_new_users' as the default.
    IF NOT FOUND THEN
      group_role_name := 'pci_new_users';
    END IF;

    RETURN group_role_name;

  END;
  $$ LANGUAGE plpgsql SECURITY DEFINER; -- Executed with the privileges of the user that owns the function.

  -- clientauth hook function
  -- Purpose: This function is called by pg_tle after any authentication attempt.
  -- It is responsible for:
  --   1. Checking if an account is currently locked and preventing login (PCI DSS 8.3.4).
  --   2. Tracking failed authentication attempts and initiating lockout when thresholds are met.
  --   3. Recording successful login attempts and updating last activity.
  --   4. Enforcing password expiration (logic carried over from v0.4).
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

  BEGIN
  
    -- Check if the user already exists in pg_roles. This helps differentiate between
    -- attempts for existing users versus attempts for non-existent users (though pg_tle still calls the hook).
    SELECT EXISTS (SELECT 1 FROM pg_catalog.pg_roles WHERE rolname = l_username)
    INTO user_exists;
	RAISE NOTICE 'User exists: %',user_exists; -- Corrected grammar

    -- 0. Determine Role-Based Policies (from password_check.profiles table)
    --    Fetch the lockout_threshold and lockout_duration_minutes based on the user's
    --    prioritized PCI role. If no specific role is found, default values are used.
    IF user_exists THEN
      SELECT 
        lockout_threshold,
        lockout_duration_minutes
      INTO
        current_lockout_threshold,
        current_lockout_duration_minutes
      FROM 
        password_check.profiles
      WHERE
        role=password_check.get_member_priority_role(l_username);

      IF NOT FOUND THEN
        -- Fallback to default values if user's role profile isn't explicitly defined
        current_lockout_threshold := 10;
        current_lockout_duration_minutes := 30;
      END IF;
    ELSE
      -- If user doesn't exist, use default lockout parameters for consistency
      current_lockout_threshold := 10;
      current_lockout_duration_minutes := 30;
    END IF;
	
	--Test case 2: After a successful login, are the correct profile policies selected?
	RAISE DEBUG 'Test case 2: Role-Based Policies: current_lockout_threshold: %, current_lockout_duration_minutes: %, Priority Role: %', current_lockout_threshold, current_lockout_duration_minutes, password_check.get_member_priority_role(l_username);


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

      -- On successful login, reset failed attempts and update last_activity and last_successful_login.
      UPDATE password_check.user_login_activity la
      SET failed_attempts = 0, last_activity = NOW(), last_successful_login = NOW()
      WHERE la.username = l_username;


    END IF;

  END;
  $$ LANGUAGE plpgsql SECURITY DEFINER;
  
  
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

    RAISE NOTICE 'Policy: % for user %', user_priority_role, username;


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
      RAISE WARNING 'Password type % may not allow full password reusability (PCI DSS 8.3.7) or common/dictionary password checks (PCI DSS 8.3.5) within this hook. Consider enforcing TEXT or MD5 for these checks.', password_type;
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

  
    -- 4. Enforce Password Validity Period (PCI DSS 8.3.9 & 8.6.3)
    -- Ensure the account is not created/updated with "VALID UNTIL NULL".
    IF valid_null THEN
      invalid_pw_reason := invalid_pw_reason || 'New user password must have a "VALID UNTIL" date. "VALID UNTIL NULL" is not allowed. '; -- Added space for consistency
    -- Ensure the "VALID UNTIL" clause is not specified beyond the maximum allowed validity interval for the role.
    ELSE
      IF valid_until > (NOW() + current_max_validity_interval) THEN
        invalid_pw_reason := invalid_pw_reason || 'Account validity date cannot be more than ' || current_max_validity_interval || ' in the future for this role. ';
      END IF;
    END IF;
    
    -- 5. Final Check and Raise Exception
    -- If any validation failed, raise an exception to prevent the password change.
    IF invalid_pw_reason != '' THEN
      RAISE EXCEPTION 'Password validation failed for user %: %', username, invalid_pw_reason;
    ELSE
      -- Assign the parameter to the local variable for safe insertion/deletion
      _username_param := username;
      
      -- 6. Update Password History (only if validation passed)
      -- If the password change is allowed, record the new password's hash and its valid_until date in the history.
      -- This ensures we maintain the history for future reusability checks and track expiration.
      INSERT INTO password_check.password_history (username, password_hash, valid_until)
      VALUES (_username_param, new_password_hashed, NOW() + current_max_validity_interval);
      
      -- 7. Prune Old Password History
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

  -- Grant execute privileges for the inactive account management function.
  REVOKE ALL ON FUNCTION password_check.manage_inactive_accounts() FROM PUBLIC;
  GRANT EXECUTE ON FUNCTION password_check.manage_inactive_accounts() TO PUBLIC;

  -- Grant execute privileges for the role priority helper function.
  REVOKE ALL ON FUNCTION password_check.get_member_priority_role(TEXT) FROM PUBLIC;
  GRANT EXECUTE ON FUNCTION password_check.get_member_priority_role(TEXT) TO PUBLIC;
  
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
-- ALTER EXTENSION pci_password_check_rules UPDATE TO '0.5';
-- SELECT pgtle.set_default_version('pci_password_check_rules', '0.4'); -- Example to revert default version
-- \dx -- To list installed extensions and their versions


-- Test Cases (These are for documentation and manual testing, NOT part of the SQL update script itself):
--
--	Test Case 1. Account gets locked after 10 attempts. --Success
--		--Repeat 10 times with incorrect password
--		postgres@sasuke-v:~$ psql -U myuser2 -d heydbamaint
--		Password for user myuser2: (incorrect password)
--		psql: error: connection to server on socket "/var/run/postgresql/.s.PGSQL.5432" failed: FATAL:  password authentication failed for user "myuser2"
--		
--		--After the 10th time, issue the correct password (or any password)
--		postgres@sasuke-v:~$ psql -U myuser2 -d heydbamaint
--		Password for user myuser2: (correct password)
--		psql: error: connection to server on socket "/var/run/postgresql/.s.PGSQL.5432" failed: FATAL:  Account myuser2 has been locked due to too many failed authentication attempts. Try again after 2025-07-18 13:13:13.032366+00.
--		
--		--As superuser, verify lockout in locked_accounts table:
--		heydbamaint=# select * from password_check.locked_accounts;
--		 username |         locked_until          | locked_by
--		----------+-------------------------------+-----------
--		 myuser2  | 2025-07-18 13:13:13.032366+00 | SYSTEM
--
--	Test Case 2. After a successful login, are the correct profile policies selected? --Success
--		postgres@sasuke-v:~$ psql -U myuser2 -d heydbamaint
--		--Debug Log Message shows the correct profile (check PostgreSQL logs)
--		2025-07-18 12:35:44.448 UTC [6016] DEBUG:  Test case 2: Role-Based Policies: current_lockout_threshold: 10, current_lockout_duration_minutes: 30, Priority Role: pci_standard_users
--		--On a different session as superuser (postgres), verify parameters from the view:
--		heydbamaint=# select * from password_check.v_role_members_parameters where username='myuser2';
--		 username |        role        | max_validity_interval | lockout_threshold | lockout_duration_minutes | inactive_threshold
--		----------+--------------------+-----------------------+-------------------+--------------------------+--------------------
--		 myuser2  | pci_standard_users | 90 days               |                10 |                       30 | 90 days
--
--	Test Case 3: Account is removed from password_check.locked_accounts after the lockout period ends. --Success
--		--After entering a wrong password, having the account locked, it was removed from password_check.locked_accounts.
--		heydbamaint=# select * from password_check.locked_accounts;
--		 username |         locked_until          | locked_by
--		----------+-------------------------------+-----------
--		 myuser2  | 2025-07-18 13:13:13.032366+00 | SYSTEM
--		(1 row)
--		
--		--Attempt login after lockout period has passed (e.g., more than 30 minutes later)
--		postgres@sasuke-v:~$ psql -U myuser2 -d heydbamaint
--		Password for user myuser2: (correct password)
--		psql: error: connection to server on socket "/var/run/postgresql/.s.PGSQL.5432" failed: FATAL:  password authentication failed for user "myuser2" -- (This indicates the password itself might be wrong, or another issue, but the lockout should be cleared)
--
--		--Verify locked_accounts table is empty (lockout cleared by the hook)
--		heydbamaint=# select * from password_check.locked_accounts;
--		 username | locked_until | locked_by
--		----------+--------------+-----------
--		(0 rows)
--		
--		--Evidence shown in the log that the account was removed from password_check.locked_accounts
--		2025-07-18 13:59:58.990 UTC [6016] DEBUG:  Test Case 3: Account is removed from password_check.locked_accounts after the lockout period ends. Rows found: 0
--
--	Test Case 4: After a failed login attempt, the failed_attempts column on table password_check.user_login_activity is incremented. --Success
--	Test Case 5: After a successful login, the failed_attempts column on table password_check.user_login_activity is restarted. --Success
--		--As postgres on a different session, observe initial state:
--		heydbamaint=# select * from password_check.user_login_activity order by username;
--		 username |     last_successful_login     | failed_attempts |         last_activity
--		----------+-------------------------------+-----------------+-------------------------------
--		 forum    | 2025-07-17 23:59:57.267669+00 |               0 | 2025-07-17 23:59:57.267669+00
--		 myuser   | 2025-07-18 12:30:23.683435+00 |               0 | 2025-07-18 12:30:23.683435+00
--		 myuser2  | 2025-07-18 12:33:34.208427+00 |               0 | 2025-07-18 12:33:34.208427+00
--		(3 rows)
--
--		--Attempt a failed login for myuser2:
--		postgres@sasuke-v:~$ psql -U myuser2 -d heydbamaint
--		Password for user myuser2: (incorrect)
--		psql: error: connection to server on socket "/var/run/postgresql/.s.PGSQL.5432" failed: FATAL:  password authentication failed for user "myuser2"
--		
--		--As postgres, verify incremented failed_attempts:
--		heydbamaint=# select * from password_check.user_login_activity order by username;
--		 username |     last_successful_login     | failed_attempts |         last_activity
--		----------+-------------------------------+-----------------+-------------------------------
--		 forum    | 2025-07-17 23:59:57.267669+00 |               0 | 2025-07-17 23:59:57.267669+00
--		 myuser   | 2025-07-18 12:30:23.683435+00 |               0 | 2025-07-18 12:30:23.683435+00
--		 myuser2  | 2025-07-18 12:33:34.208427+00 |               1 | 2025-07-18 12:35:19.504637+00
--		(3 rows)
--
--		--Attempt another failed login for myuser2:
--		postgres@sasuke-v:~$ psql -U myuser2 -d heydbamaint
--		Password for user myuser2: (incorrect)
--		psql: error: connection to server on socket "/var/run/postgresql/.s.PGSQL.5432" failed: FATAL:  password authentication failed for user "myuser2"
--
--		--As postgres, verify further increment:
--		heydbamaint=# select * from password_check.user_login_activity order by username;
--		 username |     last_successful_login     | failed_attempts |         last_activity
--		----------+-------------------------------+-----------------+-------------------------------
--		 forum    | 2025-07-17 23:59:57.267669+00 |               0 | 2025-07-17 23:59:57.267669+00
--		 myuser   | 2025-07-18 12:30:23.683435+00 |               0 | 2025-07-18 12:30:23.683435+00
--		 myuser2  | 2025-07-18 12:33:34.208427+00 |               2 | 2025-07-18 12:35:26.24181+00
--		(3 rows)
--
--		--Attempt a failed login for myuser:
--		postgres@sasuke-v:~$ psql -U myuser -d heydbamaint
--		Password for user myuser: (incorrect)
--		psql: error: connection to server on socket "/var/run/postgresql/.s.PGSQL.5432" failed: FATAL:  password authentication failed for user "myuser"
--
--		--As postgres, verify myuser's failed_attempts incremented:
--		heydbamaint=# select * from password_check.user_login_activity order by username;
--		 username |     last_successful_login     | failed_attempts |         last_activity
--		----------+-------------------------------+-----------------+-------------------------------
--		 forum    | 2025-07-17 23:59:57.267669+00 |               0 | 2025-07-17 23:59:57.267669+00
--		 myuser   | 2025-07-18 12:30:23.683435+00 |               1 | 2025-07-18 12:35:34.192406+00
--		 myuser2  | 2025-07-18 12:33:34.208427+00 |               2 | 2025-07-18 12:35:26.24181+00
--		(3 rows)
--
--		--Attempt a successful login for myuser2:
--		postgres@sasuke-v:~$ psql -U myuser2 -d heydbamaint
--		Password for user myuser2: (correct)
--		psql (16.9 (Ubuntu 16.9-0ubuntu0.24.04.1))
--		Type "help" for help.
--		
--		heydbamaint=>
--
--		--As postgres, verify myuser2's failed_attempts reset to 0 and last_successful_login updated:
--		heydbamaint=# select * from password_check.user_login_activity order by username;
--		 username |     last_successful_login     | failed_attempts |         last_activity
--		----------+-------------------------------+-----------------+-------------------------------
--		 forum    | 2025-07-17 23:59:57.267669+00 |               0 | 2025-07-17 23:59:57.267669+00
--		 myuser   | 2025-07-18 12:30:23.683435+00 |               1 | 2025-07-18 12:35:34.192406+00
--		 myuser2  | 2025-07-18 12:35:44.447696+00 |               0 | 2025-07-18 12:35:44.447696+00
--		(3 rows)
--	
--	Test Case 6: Check that password_check.manage_inactive_accounts will disable accounts inactive for more than the threshold time. --Success
--		--Initial state of user_login_activity (example):
--		heydbamaint=# select * from password_check.user_login_activity;
--		 username |     last_successful_login     | failed_attempts |         last_activity
--		----------+-------------------------------+-----------------+-------------------------------
--		 myuser   | 2025-07-18 12:30:23.683435+00 |               1 | 2025-07-18 12:35:34.192406+00
--		 myuser2  | 2025-07-18 14:02:25.113683+00 |               0 | 2025-07-18 14:02:25.113683+00
--		 forum    | 2025-04-17 23:59:57.267669+00 |               0 | 2025-07-17 23:59:57.267669+00 -- Inactive
--		 evandro  | 2025-04-19 14:09:42.494397+00 |               0 | 2025-07-18 14:11:34.676606+00 -- Inactive
--		
--		--Run the inactive account management function:
--		heydbamaint=# select password_check.manage_inactive_accounts();
--		NOTICE:  Account evandro disabled due to inactivity.
--		NOTICE:  Account forum disabled due to inactivity. -- Added forum to expected notice
--		 manage_inactive_accounts
--		--------------------------
--		
--		(1 row)
--		
--		--Verify disabled roles:
--		heydbamaint=# \du evandro
--			List of roles
--		 Role name |  Attributes
--		----------+--------------
--		 evandro   | Cannot login
--
--		heydbamaint=# \du forum
--			List of roles
--		 Role name |  Attributes
--		----------+--------------
--		 forum     | Cannot login
