import inspect
from dataclasses import fields

from tpmstream.spec.structures import (
    algorithm_parameters_and_structures,
    attached_component_structures,
    attribute_structures,
    base_types,
    constants,
    context_data,
    creation_data,
    handles,
    interface_types,
    key_object_complex,
    nv_storage_structures,
    structures,
)

submodules = (
    algorithm_parameters_and_structures,
    attached_component_structures,
    attribute_structures,
    base_types,
    constants,
    context_data,
    creation_data,
    handles,
    interface_types,
    key_object_complex,
    nv_storage_structures,
    structures,
)

# provide all specified types in a single list
structures_types_set = set()
for module in submodules:
    structures_types_set.update(
        obj
        for name, obj in inspect.getmembers(module, inspect.isclass)
        if not obj.__name__.startswith("_") and obj.__name__.isupper()
    )
structures_types = sorted(structures_types_set, key=lambda e: e.__name__)


types_with_union_members = [t for t in structures_types if hasattr(t, "_selectors")]


def _sanity_check_union_types():
    """
    Sanity check valid selector values against union options
    a) verify that all selector values are mapped to union members
    b) verify that all union members can be selected
    """
    types_with_union_members = [t for t in structures_types if hasattr(t, "_selectors")]
    for parent_type in types_with_union_members:
        for union in (
            f for f in fields(parent_type) if hasattr(f.type, "_selected_by")
        ):
            selector_name = parent_type._selectors[union.name]
            selector = next(f for f in fields(parent_type) if f.name == selector_name)

            # a) check that all possible selector values are mapped to union members
            for selector_value in selector.type._valid_values:
                if None in union.type._selected_by.values():
                    # wildcard selector
                    continue
                assert (
                    selector_value in union.type._selected_by.values()
                ), f"Error for {parent_type.__name__}: selector {selector.type.__name__} {selector.name} can be {selector_value} but there is no such option in {union.type.__name__} {union.name}"

            # b) check that all union members can be selected by selector
            for union_choice in union.type._selected_by.values():
                if union_choice is union_choice:
                    # wildcard selector
                    continue
                assert (
                    union_choice in valid_values
                ), f"Error for {parent_type.__name__}: Union {union.type.__name__} {union.name} has member selected by {union_choice} but selector {selector.type.__name__} {selector.name} can never take this value"


_sanity_check_union_types()
