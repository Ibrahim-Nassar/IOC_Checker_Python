#!/usr/bin/env python3
"""
Test API key persistence functionality.
"""

from api_key_store import save, load


def test_api_key_save_load_cycle():
    """Test that API keys can be saved and loaded correctly."""
    test_key = "test_key_12345"
    env_var = "TEST_PROVIDER_API_KEY"
    
    # Save the key
    save(env_var, test_key)
    
    # Load the key back
    loaded_key = load(env_var)
    
    assert loaded_key == test_key, f"Expected {test_key}, got {loaded_key}"


def test_api_key_clear():
    """Test that API keys can be cleared (empty string removes key)."""
    test_key = "test_key_to_clear"
    env_var = "TEST_CLEAR_API_KEY"
    
    # Save a key first
    save(env_var, test_key)
    assert load(env_var) == test_key
    
    # Clear the key
    save(env_var, "")
    
    # Verify it's cleared
    loaded_key = load(env_var)
    assert loaded_key is None, f"Expected None after clearing, got {loaded_key}"


def test_api_key_nonexistent():
    """Test loading a key that doesn't exist returns None."""
    loaded_key = load("NONEXISTENT_API_KEY")
    assert loaded_key is None


def test_api_key_whitespace_handling():
    """Test that whitespace is handled correctly."""
    test_key = "  test_key_with_spaces  "
    env_var = "TEST_WHITESPACE_API_KEY"
    
    # Save key with whitespace
    save(env_var, test_key)
    
    # Should load back trimmed
    loaded_key = load(env_var)
    assert loaded_key == test_key.strip() 