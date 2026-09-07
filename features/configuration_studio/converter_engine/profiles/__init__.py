from features.configuration_studio.converter_engine.profiles.base import Profile
from features.configuration_studio.converter_engine.profiles.tam_standard import (
    TAM_STANDARD,
)

# Registry of profiles selectable by key (e.g. from a future UI dropdown
# or service.convert_file(profile_key=...)). Add a new profile here once
# its module defines one — this is the single place the rest of the app
# looks a profile up by name, so nothing else needs to change to make a
# new profile selectable.
PROFILE_REGISTRY = {
    "tam_standard": TAM_STANDARD,
}

__all__ = ["Profile", "TAM_STANDARD", "PROFILE_REGISTRY"]
