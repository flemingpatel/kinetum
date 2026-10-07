# Kinetum Validation Third-Party Notices

This private wheel contains Kinetum-authored validation code, resources, and
native helpers.
It does not embed DPDK, TRex, tcpdump, Matplotlib, OpenSSH, or operating-system
tool bytes. Pip installs declared Python dependencies separately. The operator
supplies system tools and the external traffic environment.

The source-build dependency producer and its policy/templates are not part of
this kit. The separately produced KinetumDPDK package owns its notices; only
the runtime product redistributes that dependency's selected linked bytes and
their static-closure attribution.
