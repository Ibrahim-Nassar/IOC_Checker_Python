# Dialog Design Guidelines

This document provides guidelines for creating configuration dialogs in the IOC Checker application to ensure consistency, usability, and maintainability.

## Overview

All configuration dialogs should follow the same design patterns to provide a consistent user experience. Use the `dialog_templates.py` module for creating new configuration dialogs.

## Design Principles

### 1. Consistent Layout
- All dialogs should have the same basic structure:
  - Title at the top (bold, 12pt font)
  - Optional description text
  - Main content area
  - Button bar at the bottom

### 2. Required Buttons
- **Save Button**: Always present, positioned on the left
- **Cancel Button**: Always present, positioned on the right  
- **Test Button**: Optional, positioned between Save and Cancel

### 3. Button Behavior
- **Save**: Should validate input, save changes, show success/error message
- **Cancel**: Should close dialog without saving changes
- **Test**: Should validate current input and test functionality

### 4. Error Handling
- Always use try/catch blocks in button handlers
- Show user-friendly error messages using `messagebox.showerror()`
- Provide specific error details when possible

## Using Dialog Templates

### Basic Configuration Dialog

```python
from dialog_templates import ConfigurationDialog

class MyConfigDialog(ConfigurationDialog):
    def __init__(self, parent):
        super().__init__(parent, "My Configuration", 600, 400)
        
        # Add your content to self.content_frame
        self._setup_content()
        
        # Set up callbacks
        self.set_save_callback(self._save_config)
        self.set_test_callback(self._test_config)  # Optional
    
    def _setup_content(self):
        # Add your UI elements to self.content_frame
        pass
    
    def _save_config(self):
        # Implement save logic
        pass
    
    def _test_config(self):
        # Implement test logic (optional)
        pass

# Usage
dialog = MyConfigDialog(root)
dialog.show()
```

### API Key Configuration Dialog

```python
from dialog_templates import create_api_key_dialog

api_configs = [
    ("service1", "Service 1", "Description of service 1"),
    ("service2", "Service 2", "Description of service 2"),
]

current_keys = {
    "service1": "existing_key_value",
    "service2": ""
}

def save_api_keys():
    # Get keys from dialog
    keys = dialog.get_api_keys()
    # Save keys logic here
    print("Saved keys:", keys)

dialog = create_api_key_dialog(root, api_configs, current_keys, save_api_keys)
dialog.show()
```

### Provider Selection Dialog

```python
from dialog_templates import create_provider_selection_dialog

providers_info = [
    ("provider1", "Provider 1", "ENV_VAR1", "Description", ["ip", "domain"]),
    ("provider2", "Provider 2", None, "Free service", ["url", "hash"]),
]

current_selection = {"provider1": True, "provider2": False}

def save_provider_selection():
    selection = dialog.get_selected_providers()
    print("Selected providers:", selection)

dialog = create_provider_selection_dialog(root, providers_info, current_selection, save_provider_selection)
dialog.show()
```

## Best Practices

### 1. Window Sizing and Positioning
- Default sizes: 600x500 for complex dialogs, 400x300 for simple ones
- Always center dialogs relative to parent window
- Use transient and grab_set for modal behavior

### 2. Form Layout
- Use `ttk.LabelFrame` for grouping related fields
- Consistent padding: 20px for main frame, 10px for label frames
- Use descriptive labels and help text

### 3. Input Validation
- Validate input on save, not on every keystroke
- Show clear error messages for invalid input
- Disable save button if required fields are empty (optional)

### 4. Accessibility
- Use proper tab order for keyboard navigation
- Provide keyboard shortcuts for common actions
- Use appropriate widget types (Entry for text, Checkbutton for boolean, etc.)

### 5. State Management
- Always save dialog state when user clicks Save
- Preserve user input when possible (don't clear on validation errors)
- Show current state clearly (checkmarks, status indicators)

## Examples in Codebase

### API Key Configuration
See `_configure_api_keys()` in `ioc_gui_tk.py` for a complete implementation that:
- Shows current API key status
- Allows editing with show/hide functionality
- Saves to both memory and .env file
- Provides clear success/error feedback

### Provider Selection
See `show_providers_info()` in `ioc_gui_tk.py` for a provider selection dialog that:
- Allows filtering by IOC type
- Shows API key status for each provider
- Provides detailed descriptions
- Saves selection state

## Future Enhancements

When adding new configuration dialogs:

1. **Use the templates**: Start with `ConfigurationDialog` or specialized templates
2. **Follow the patterns**: Maintain consistency with existing dialogs
3. **Add validation**: Include proper input validation and error handling
4. **Test thoroughly**: Test save, cancel, and test functionality
5. **Update this document**: Add your dialog as an example if it introduces new patterns

## Migration Guide

For existing dialogs that don't follow these patterns:

1. Identify dialogs missing Save buttons
2. Refactor to use `ConfigurationDialog` base class
3. Add proper error handling
4. Ensure consistent button layout
5. Test all functionality

This ensures all configuration dialogs provide a professional, consistent user experience.
