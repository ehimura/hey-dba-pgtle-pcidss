--Version 0.1 (Part 4: The Enigma of Complexity – Taming Passwords with pgtle (Part 2))
-- This script creates or updates a pg_tle extension named 'pci_password_check_rules'
-- to enforce PCI DSS 4.0.1 compliant password policies, including:
-- - Password complexity (length, character types) (PCI DSS 8.3.6)

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
	PGTLE.INSTALL_EXTENSION (
		'pci_password_check_rules', -- Name of your custom pg_tle extension
		'0.1', -- Incremented version for non-human account handling
		'Enforces PCI DSS 4.0.1 password complexity', -- Description of the extension
		$_pgtle_$
  
    CREATE SCHEMA IF NOT EXISTS password_check;
    REVOKE ALL ON SCHEMA password_check FROM PUBLIC;
    GRANT USAGE ON SCHEMA password_check TO PUBLIC;
    
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
    
    BEGIN
    
      --- 1. Apply Password Complexity Checks (PCI DSS 8.3.6) ---
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
      
      --- 2. Final Check and Raise Exception / Update History ---
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


--CREATE EXTENSION pci_password_check_rules;