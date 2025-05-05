#!/usr/bin/env python3
"""
PhantomSocket Configuration Tool

Utility for managing PhantomSocket configurations.
"""

import argparse
import os
import sys
import yaml
import json

from src.config import ConfigLoader


def create_config(args):
    """Create a new configuration file."""
    if os.path.exists(args.output):
        if not args.force:
            print(f"Error: {args.output} already exists. Use --force to overwrite.")
            return 1

    config = ConfigLoader()

    # Set active profile
    if args.profile:
        config.set_active_profile(args.profile)

    # Save configuration
    if config.save_config(args.output):
        print(f"Configuration saved to {args.output}")
        return 0
    else:
        print(f"Error: Failed to save configuration to {args.output}")
        return 1


def edit_config(args):
    """Edit an existing configuration file."""
    if not os.path.exists(args.config):
        print(f"Error: {args.config} does not exist.")
        return 1

    # Load configuration
    config = ConfigLoader(args.config)

    # Update configuration
    if args.set:
        for setting in args.set:
            if "=" not in setting:
                print(f"Error: Invalid setting format: {setting}")
                continue

            path, value = setting.split("=", 1)
            path_parts = path.split(".")

            if len(path_parts) < 2:
                print(f"Error: Invalid setting path: {path}")
                continue

            section = path_parts[0]
            key = ".".join(path_parts[1:])

            # Try to convert value to appropriate type
            try:
                # Try to parse as JSON
                value = json.loads(value)
            except json.JSONDecodeError:
                # If not valid JSON, keep as string
                pass

            config.set(section, key, value)

    # Change active profile
    if args.profile:
        config.set_active_profile(args.profile)

    # Save configuration
    if config.save_config(args.output or args.config):
        print(f"Configuration saved to {args.output or args.config}")
        return 0
    else:
        print(f"Error: Failed to save configuration")
        return 1


def show_config(args):
    """Show configuration information."""
    # Load configuration
    config = ConfigLoader(args.config)

    if args.profile:
        # Show specific profile
        profile_name = args.profile
        profile = config.get("profiles", {}).get(profile_name)

        if not profile:
            print(f"Profile '{profile_name}' not found.")
            return 1

        print(f"Profile: {profile_name}")
        print(yaml.dump(profile, default_flow_style=False))

    elif args.list_profiles:
        # List all profiles
        profiles = config.get("profiles", {})
        active_profile = config.get_active_profile()

        print("Available profiles:")
        for name in profiles:
            if name == active_profile:
                print(f"* {name} (active)")
            else:
                print(f"  {name}")

    elif args.get:
        # Get specific setting
        path = args.get
        path_parts = path.split(".")

        if len(path_parts) < 2:
            print(f"Error: Invalid setting path: {path}")
            return 1

        section = path_parts[0]
        key = ".".join(path_parts[1:])

        value = config.get(section, key)
        print(f"{path} = {value}")

    else:
        # Show entire configuration
        print(yaml.dump(config.config, default_flow_style=False))

    return 0


def main():
    """Main entry point."""
    parser = argparse.ArgumentParser(description="PhantomSocket Configuration Tool")

    subparsers = parser.add_subparsers(dest="command", help="Command")

    # Create command
    create_parser = subparsers.add_parser("create", help="Create a new configuration")
    create_parser.add_argument("output", help="Output configuration file")
    create_parser.add_argument("--profile", help="Set active profile")
    create_parser.add_argument(
        "--force", action="store_true", help="Overwrite existing file"
    )

    # Edit command
    edit_parser = subparsers.add_parser("edit", help="Edit configuration")
    edit_parser.add_argument("config", help="Configuration file to edit")
    edit_parser.add_argument(
        "--set", action="append", help="Set configuration value (section.key=value)"
    )
    edit_parser.add_argument("--profile", help="Set active profile")
    edit_parser.add_argument("--output", help="Output file (default: overwrite input)")

    # Show command
    show_parser = subparsers.add_parser("show", help="Show configuration")
    show_parser.add_argument(
        "config", nargs="?", help="Configuration file (default: use default locations)"
    )
    show_parser.add_argument("--profile", help="Show specific profile")
    show_parser.add_argument(
        "--list-profiles", action="store_true", help="List available profiles"
    )
    show_parser.add_argument("--get", help="Get specific setting (section.key)")

    args = parser.parse_args()

    if args.command == "create":
        return create_config(args)
    elif args.command == "edit":
        return edit_config(args)
    elif args.command == "show":
        return show_config(args)
    else:
        parser.print_help()
        return 1


if __name__ == "__main__":
    sys.exit(main())
