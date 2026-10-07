# Redistributed Documentation Asset Licenses

The generated Kinetum documentation website includes local static
assets emitted by Sphinx, the Read the Docs theme, and Doxygen. This directory
contains the license material that must travel with those bytes.

| Asset family | Version in the build | License file |
|--------------|----------------------|--------------|
| Sphinx HTML support files | 8.1.3 | `SPHINX_BSD_2_CLAUSE.txt` |
| Pygments syntax-highlighting CSS and markup | 2.21.0 | `PYGMENTS_BSD_2_CLAUSE.txt` |
| Read the Docs Sphinx theme | 3.1.0 | `SPHINX_RTD_THEME_MIT.txt` |
| jQuery emitted by Sphinx | 3.6.0 | `JQUERY_MIT.txt` |
| jQuery emitted by Doxygen | 3.6.0 | `DOXYGEN_OUTPUT_MIT.txt`; its exact short notice also remains embedded in `api/jquery.js` |
| Font Awesome webfont and CSS | 4.7.0 | `FONT_NOTICES.md`, `SIL_OPEN_FONT_LICENSE_1.1.txt`, and the theme MIT license |
| Lato webfonts | Theme-bundled static faces | `FONT_NOTICES.md` and `SIL_OPEN_FONT_LICENSE_1.1.txt` |
| Roboto Slab webfonts | Theme-bundled static faces | `FONT_NOTICES.md` and `APACHE-2.0.txt` |
| Doxygen navigation JavaScript | Doxygen 1.9.8 output | `DOXYGEN_OUTPUT_MIT.txt`; bundled component notices also remain embedded in the generated JavaScript |

`APACHE-2.0.txt` is copied byte-for-byte from Kinetum's root `LICENSE` during
site composition. PlantUML, MyST-Parser, sphinxcontrib-plantuml, Java, Graphviz,
and Doxygen are build tools. Their program bytes are not copied into the
generated site; PlantUML diagrams are rendered to static SVG.
