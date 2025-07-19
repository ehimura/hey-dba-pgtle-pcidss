--Version 0.2 (Part 4: The Enigma of Complexity – Taming Passwords with pgtle (Part 2))
-- This script creates or updates a pg_tle extension named 'pci_password_check_rules'
-- to enforce PCI DSS 4.0.1 compliant password policies, including:
-- - Password complexity (length, character types) (PCI DSS 8.3.6)
-- - Separation of Roles via the password_check.profiles table.

--0.2 changes:
--	.Verify if the roles exists, if not create them
--	.Add table password_check.profiles for roles separation: 
--		.pci_admin_users,pci_app_users,pci_standard_users
--	.Function changes
--		.Add variable user_exists to help determine if this is a CREATE USER or ALTER USER.
--		.Add a lookup to the password_check.profiles to fetch the profile's password rules.
--		.Add a logic to prevent the user from changing its password if does not belong to any of the pre-defined ROLES.
--	.Add function is_member_of_role to verify if the new role is member of one of the profiles.

-- It is compatible with PostgreSQL 16 and later.

-- IMPORTANT: Before running this script, ensure you have:
-- 1. Configured your PostgreSQL DB Cluster Parameter Group:
--    - Added 'pg_tle' to the 'shared_preload_libraries' parameter.
--    - Set 'pgtle.enable_password_check' to 'on' or 'require'.
--    - Set 'pgtle.enable_clientauth' to 'on' or 'require'.
--    - Rebooted your PostgreSQL cluster if these parameters were changed.
-- 2. Created the necessary group roles (e.g., pci_admin_users, pci_app_users, pci_standard_users)
--    and granted appropriate memberships to your user accounts.
--    Note: The 'pci_app_users' role is now intended for non-human (service) accounts.


SELECT
	PGTLE.INSTALL_UPDATE_PATH (
		'pci_password_check_rules', -- Name of your custom pg_tle extension
		'0.1',
		'0.2', -- Incremented version to add role separation for non-human account handling
		$_pgtle_$

  --Check if the ROLES exists. It's a requirement that the roles exists in order to proceed.
  --pci_admin_users,pci_app_users,pci_standard_users
  do
  $$
  declare
    v_arr_rolnames text ARRAY;
    v_rolname text;
    
  begin
    v_arr_rolnames := '{"pci_admin_users","pci_app_users","pci_standard_users"}';
    
    FOREACH v_rolname IN ARRAY v_arr_rolnames
    LOOP
    
      if not exists (SELECT 1 FROM pg_catalog.pg_roles r WHERE r.rolname = v_rolname) then
        RAISE NOTICE 'Role % does not exist, creating it.', v_rolname;
  	  
  	  --format syntax: %[position][flags][width]type
  	  --The position is in the form n$
	  --flags (only takes effect when width is in specified)
	    -- minus sign (-) that instructs the format specifier’s output to be left-justified.
	  --width (optional)
	    -- minimum number of characters to use for displaying
  	  --type
	    --s formats the argument value as a string. NULL is treated as an empty string.
  	    --I treats the argument value as an SQL identifier.
  	    --L quotes the argument value as an SQL literal.
        EXECUTE format($e$
          CREATE ROLE %1$s
        $e$, v_rolname);
  	  
      end if;
      
    END LOOP;
    
  end
  $$
  ;

  --Create the table to hold the profiles.
  --The table must check if the group roles already exists (create a trigger).
  --Or maybe the table must not allow any update to its values, and make it fixed.
  CREATE TABLE IF NOT EXISTS password_check.profiles (
    role TEXT PRIMARY KEY,
  	min_length INTEGER DEFAULT 15 NOT NULL ,
  	require_special_char BOOLEAN DEFAULT true NOT NULL,
  	require_uppercase BOOLEAN DEFAULT true NOT NULL,
  	require_lowercase BOOLEAN DEFAULT true NOT NULL,
  	require_digit BOOLEAN DEFAULT true NOT NULL
  );
  
  INSERT INTO password_check.profiles (role,min_length) values ('pci_admin_users',15) ON CONFLICT (role) DO NOTHING;
  INSERT INTO password_check.profiles (role,min_length) values ('pci_app_users',15) ON CONFLICT (role) DO NOTHING;
  INSERT INTO password_check.profiles (role,min_length) values ('pci_standard_users',12) ON CONFLICT (role) DO NOTHING;
  INSERT INTO password_check.profiles (role,min_length) values ('pci_new_users',12) ON CONFLICT (role) DO NOTHING;

  -- Helper function to check if a given username is a member of a specified PostgreSQL role (group).
  CREATE OR REPLACE FUNCTION password_check.is_member_of_role(
      target_username TEXT,
      group_role_name TEXT
  ) RETURNS BOOLEAN AS $$
  DECLARE
    is_member BOOLEAN := FALSE;
  BEGIN
    SELECT EXISTS (
      SELECT 1
      FROM pg_catalog.pg_roles AS r_member
      JOIN pg_catalog.pg_auth_members AS am ON r_member.oid = am.member
      JOIN pg_catalog.pg_roles AS r_role ON am.roleid = r_role.oid
      WHERE r_member.rolname = target_username
        AND r_role.rolname = group_role_name
    ) INTO is_member;
    RETURN is_member;
  END;
  $$ LANGUAGE plpgsql SECURITY DEFINER; --Executed with the privileges of the user that owns the function.
  
  -- The main passcheck hook function that enforces password policies.
  CREATE OR REPLACE FUNCTION password_check.passcheck_hook(
      username TEXT,
      password TEXT,
      password_type pgtle.password_types,
      valid_until TIMESTAMPTZ,
      valid_null BOOLEAN
  ) RETURNS VOID AS $_FUNCTION_$ -- ADDED THIS BLOCK LABEL
  DECLARE
    invalid_pw_reason TEXT := '';
  
    current_min_length INTEGER := 12;
    current_require_special_char BOOLEAN := TRUE;
    current_require_uppercase BOOLEAN := TRUE;
    current_require_lowercase BOOLEAN := TRUE;
    current_require_digit BOOLEAN := TRUE;
  	
    -- Add on 0.2: Flag to check if the user already exists in pg_roles
  	-- This helps differentiate between CREATE ROLE and ALTER ROLE.
    user_exists BOOLEAN;
	
  BEGIN
    -- Check if the user already exists in pg_roles.
    -- This helps differentiate between CREATE ROLE and ALTER ROLE.
    SELECT EXISTS (SELECT 1 FROM pg_catalog.pg_roles WHERE rolname = passcheck_hook.username)
    INTO user_exists;
    
    --- 1. Determine Role-Based Policies ---
    --- For CREATE ROLE, we allow a default policy. For ALTER ROLE, we enforce role membership.
    IF user_exists AND password_check.is_member_of_role(username, 'pci_admin_users') THEN
  	
  	  SELECT 
  	    min_length,
  	    require_special_char,
  	    require_uppercase,
  	    require_lowercase,
  	    require_digit
  	  INTO
  	    current_min_length,
          current_require_special_char,
          current_require_uppercase,
          current_require_lowercase,
          current_require_digit
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
  	    require_digit
  	  INTO
  	    current_min_length,
        current_require_special_char,
        current_require_uppercase,
        current_require_lowercase,
        current_require_digit
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
  	    require_digit
  	  INTO
  	    current_min_length,
        current_require_special_char,
        current_require_uppercase,
        current_require_lowercase,
        current_require_digit
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
  	    require_digit
  	  INTO
  	    current_min_length,
        current_require_special_char,
        current_require_uppercase,
        current_require_lowercase,
        current_require_digit
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
	
    --- 2. Apply Password Complexity Checks (PCI DSS 8.3.6) ---
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

    --- 3. Final Check and Raise Exception / Update History ---
    IF invalid_pw_reason != '' THEN
      RAISE EXCEPTION 'Password validation failed for user %: %', username, invalid_pw_reason;

    END IF;
  
  END;
  $_FUNCTION_$ LANGUAGE plpgsql;
  
  REVOKE ALL ON FUNCTION password_check.passcheck_hook(TEXT, TEXT, pgtle.password_types, TIMESTAMPTZ, BOOLEAN) FROM PUBLIC;
  GRANT EXECUTE ON FUNCTION password_check.passcheck_hook(TEXT, TEXT, pgtle.password_types, TIMESTAMPTZ, BOOLEAN) TO PUBLIC;
  SELECT pgtle.register_feature_if_not_exists('password_check.passcheck_hook', 'passcheck');
$_pgtle_$
	);


--SELECT * FROM pgtle.available_extensions();
--SELECT * FROM pgtle.available_extension_versions();
--SELECT * FROM pgtle.extension_update_paths('pci_password_check_rules');
--ALTER EXTENSION pci_password_check_rules UPDATE TO '0.2';
