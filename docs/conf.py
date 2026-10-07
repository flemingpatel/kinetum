"""Sphinx configuration for the offline Kinetum documentation product."""

from __future__ import annotations

import json
import pathlib


SOURCE_ROOT = pathlib.Path(__file__).resolve().parent
BUILD_FACTS_PATH = SOURCE_ROOT / "_kinetum_docs.json"

with BUILD_FACTS_PATH.open("r", encoding="utf-8") as build_facts_file:
    BUILD_FACTS = json.load(build_facts_file)

# Sphinx imports these framework-defined module globals as configuration keys.
# pylint: disable=invalid-name,redefined-builtin
project = "Kinetum"
author = "Fleming Patel"
copyright = "2026, Fleming Patel"
version = BUILD_FACTS["version"]
release = BUILD_FACTS["version"]

root_doc = "README"
source_suffix = {".md": "markdown"}
extensions = ["myst_parser", "sphinxcontrib.plantuml"]
templates_path = ["_templates"]
exclude_patterns: list[str] = []
language = "en"
nitpicky = True
keep_warnings = False
show_warning_types = True

myst_heading_anchors = 4
myst_enable_extensions = ["colon_fence", "deflist", "fieldlist"]
plantuml = [
    BUILD_FACTS["java"],
    "-Djava.awt.headless=true",
    "-DPLANTUML_SECURITY_PROFILE=SANDBOX",
    "-jar",
    BUILD_FACTS["plantuml"],
    "-graphvizdot",
    BUILD_FACTS["dot"],
]
plantuml_output_format = "svg_img"
plantuml_cache_path = str(SOURCE_ROOT / "_plantuml")

html_theme = "sphinx_rtd_theme"
html_static_path = ["_static"]
html_css_files = ["kinetum.css"]
html_show_sourcelink = False
html_copy_source = False
html_last_updated_fmt = None
html_additional_pages = {"index": "root-entry.html"}
html_search_language = "en"
# pylint: enable=invalid-name,redefined-builtin
