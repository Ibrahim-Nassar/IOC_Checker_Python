"""Tests for quota day rollover functionality."""
import pytest
from unittest.mock import patch, mock_open
from datetime import date, datetime, timedelta
import json

from quota import increment_provider, remaining, _today_key


class TestQuotaDayRollover:
    """Test quota management across day boundaries."""
    
    def test_today_key_format(self):
        """Test that _today_key returns correct format."""
        with patch('quota.date') as mock_date:
            mock_date.today.return_value = date(2023, 12, 25)
            assert _today_key() == "2023-12-25"
    
    def test_increment_provider_different_days(self):
        """Test increment_provider across different days."""
        mock_data = {}
        
        with patch('quota._load', return_value=mock_data), \
             patch('quota._save') as mock_save:
            
            # Day 1
            with patch('quota._today_key', return_value="2023-12-25"):
                increment_provider("VirusTotal", 10)
                
            # Day 2
            with patch('quota._today_key', return_value="2023-12-26"):
                increment_provider("VirusTotal", 5)
            
            # Check that data is properly separated by day
            expected_data = {
                "2023-12-25": {"VirusTotal": 10},
                "2023-12-26": {"VirusTotal": 5}
            }
            mock_save.assert_called_with(expected_data)
    
    def test_remaining_day_rollover(self):
        """Test remaining() calculation across day rollover."""
        # Setup data with usage from previous day
        mock_data = {
            "2023-12-25": {"VirusTotal": 400},  # Previous day usage
            "2023-12-26": {"VirusTotal": 100}   # Current day usage
        }
        
        with patch('quota._load', return_value=mock_data), \
             patch('quota._today_key', return_value="2023-12-26"):
            
            # Should only consider current day's usage (100)
            # Daily limit is 500, so remaining should be 400
            assert remaining("VirusTotal") == "400"
    
    def test_remaining_fresh_day(self):
        """Test remaining() calculation on a fresh day with no usage."""
        mock_data = {
            "2023-12-25": {"VirusTotal": 500}  # Previous day usage (full limit)
        }
        
        with patch('quota._load', return_value=mock_data), \
             patch('quota._today_key', return_value="2023-12-26"):
            
            # New day, no usage yet, should return full limit
            assert remaining("VirusTotal") == "500"
    
    def test_remaining_over_limit_previous_day(self):
        """Test remaining() when previous day went over limit."""
        mock_data = {
            "2023-12-25": {"VirusTotal": 600},  # Over limit previous day
            "2023-12-26": {"VirusTotal": 50}    # Current day usage
        }
        
        with patch('quota._load', return_value=mock_data), \
             patch('quota._today_key', return_value="2023-12-26"):
            
            # Should only consider current day (50), remaining = 500 - 50 = 450
            assert remaining("VirusTotal") == "450"
    
    def test_remaining_no_limit_provider(self):
        """Test remaining() for provider without daily limit."""
        mock_data = {}
        
        with patch('quota._load', return_value=mock_data):
            # Provider not in DAILY_LIMITS should return "n/a"
            assert remaining("NonExistentProvider") == "n/a"
    
    @patch('quota._PATH')
    def test_file_locking_across_days(self, mock_path):
        """Test that file locking works correctly across day boundaries."""
        with patch('quota._load', return_value={}), \
             patch('quota._save') as mock_save, \
             patch('quota._LOCK') as mock_lock:
            
            # Simulate concurrent access on day boundary
            with patch('quota._today_key', return_value="2023-12-25"):
                increment_provider("VirusTotal", 1)
            
            with patch('quota._today_key', return_value="2023-12-26"):
                increment_provider("VirusTotal", 1)
            
            # Lock should be acquired for both operations
            assert mock_lock.__enter__.call_count == 2
            assert mock_lock.__exit__.call_count == 2 