#!/usr/bin/env python3
"""
Extract a definition (function, struct, union, enum, typedef) from a C source file given a line number.

This tool uses tree-sitter to parse C code and find the innermost enclosing
definition for a given line number.
"""

import argparse
import sys
from pathlib import Path
from typing import Optional, Tuple

from tree_sitter import Parser, Language
import tree_sitter_c as tsc


MAX_DEFINITION_SEARCH_DEPTH = 128

# All C definition types we care about
DEFINITION_TYPES = {
    "function_definition",
    "type_definition",  # typedef
    "preproc_def",      # #define
    "preproc_function_def",  # #define with parameters
}

# For structs/unions/enums, we need to check if they have a body
# to distinguish definitions from mere references
COMPOUND_TYPES = {
    "struct_specifier",
    "union_specifier",
    "enum_specifier",
}


def find_innermost_definition(file_path: Path, line_number: int) -> Optional[Tuple[str, int, str]]:
    """Returns the code and starting line of the innermost enclosing definition.

    Args:
        file_path: Path to the C source file.
        line_number: 1-based line number whose containing definition is sought.

    Returns:
        (code, starting_line, definition_type) when a definition is found where:
            * code (str) is the exact source text of that definition.
            * starting_line (int) is the 1-based line on which it begins.
            * definition_type (str) is the type of definition found.
        None when the line is not inside any definition.
    """
    if not file_path.exists():
        raise FileNotFoundError(f"File not found: {file_path}")
    if file_path.is_dir():
        raise IsADirectoryError(f"Expected a file but received a directory: {file_path}")

    try:
        source_code = file_path.read_text(encoding="utf-8")
    except UnicodeDecodeError:
        # Fall back to UTF-8 with replacement characters
        source_code = file_path.read_text(encoding="utf-8", errors="replace")

    parser = Parser(Language(tsc.language()))
    tree = parser.parse(source_code.encode())

    target_row = line_number - 1  # 0-indexed rows

    def contains_row(node) -> bool:
        """
        Check if target_row is inside node's half-open row interval.

        Tree-sitter reports end_point as the position after the last
        byte of the node. When that position is at column 0 of the next
        line the node should not be considered to cover that row. We treat
        the interval as:

          [start_row, end_row)  if end_col == 0
          [start_row, end_row]  otherwise
        """
        start_row = node.start_point[0]
        end_row, end_col = node.end_point

        # Quick rejections
        if target_row < start_row or target_row > end_row:
            return False

        # If the end lands at column 0, the row itself is excluded
        if target_row == end_row and end_col == 0:
            return False

        return True

    # Depth-first search to find the INNERMOST definition
    # We'll collect all matching definitions
    matching_definitions = []
    typedef_children = set()  # Track nodes that are direct children of typedefs

    def traverse(node, depth=0, parent=None):
        if depth >= MAX_DEFINITION_SEARCH_DEPTH:
            return

        if not contains_row(node):
            return

        # Check if this is a definition we care about
        is_definition = False

        if node.type in DEFINITION_TYPES:
            is_definition = True
            # If this is a typedef, mark its direct struct/union/enum child
            if node.type == "type_definition":
                for child in node.children:
                    if child.type in COMPOUND_TYPES:
                        typedef_children.add(id(child))

        elif node.type in COMPOUND_TYPES:
            # For struct/union/enum, check if it has a body (field_declaration_list or enumerator_list)
            # This distinguishes "struct foo { ... }" from "struct foo *ptr"
            has_body = any(
                child.type in {"field_declaration_list", "enumerator_list"}
                for child in node.children
            )
            if has_body:
                is_definition = True

        if is_definition:
            snippet = source_code[node.start_byte : node.end_byte]
            starting_line = node.start_point[0] + 1
            size = node.end_byte - node.start_byte
            matching_definitions.append((snippet, starting_line, node.type, size, id(node)))

        # Continue searching children for more specific definitions
        for child in node.children:
            traverse(child, depth + 1, node)

    traverse(tree.root_node)

    if not matching_definitions:
        return None

    # Filter out structs/unions/enums that are part of a typedef
    # (we want the typedef, not the inner struct)
    filtered_definitions = [
        (snippet, line, dtype, size, node_id)
        for snippet, line, dtype, size, node_id in matching_definitions
        if node_id not in typedef_children
    ]

    # If we filtered everything out, it means we only had typedef'd structs,
    # so use the original list
    if not filtered_definitions:
        filtered_definitions = matching_definitions

    # Return the smallest (most specific) definition
    # Sort by size (smallest first) to get the innermost definition
    filtered_definitions.sort(key=lambda x: x[3])
    snippet, starting_line, def_type, _, _ = filtered_definitions[0]

    return (snippet, starting_line, def_type)


def main():
    parser = argparse.ArgumentParser(
        description="Extract a definition (function, struct, etc.) from a C source file given a line number."
    )
    parser.add_argument(
        "file_path",
        type=Path,
        help="Path to the C source file"
    )
    parser.add_argument(
        "line_number",
        type=int,
        help="Line number (1-based) to find the enclosing definition for"
    )
    parser.add_argument(
        "--show-type",
        action="store_true",
        help="Show the type of definition found"
    )

    args = parser.parse_args()

    try:
        result = find_innermost_definition(args.file_path, args.line_number)
        if result is None:
            print(f"No enclosing definition found for line {args.line_number}", file=sys.stderr)
            sys.exit(1)

        code, start_line, def_type = result

        if args.show_type:
            print(f"# {def_type} starting at line {start_line}")

        # Print with line numbers
        lines = code.splitlines()
        for i, line in enumerate(lines, start=start_line):
            print(f"{i}. {line}")

    except (FileNotFoundError, IsADirectoryError) as e:
        print(f"Error: {e}", file=sys.stderr)
        sys.exit(1)
    except Exception as e:
        print(f"Unexpected error: {e}", file=sys.stderr)
        sys.exit(1)


if __name__ == "__main__":
    main()