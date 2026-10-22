# SPDX-License-Identifier: MIT
# Adapted from Riccardo Melioli Port_Checker; see upstream MIT LICENSE.
# AEGIS-X reviewed adaptation, 2026-10-22. Upstream originals retained.
# richkmeli/NASL-Plugins; semantics, scope gating and bounded I/O changed locally.
if (description)
{
  script_id(1337005);
  script_version("1.0");
  script_name(english:"AEGIS Community: Bounded TCP connection");
  script_set_attribute(attribute:"synopsis", value:"An opt-in, bounded observation of HTTP configuration or TCP reachability.");
  script_set_attribute(attribute:"description", value:"Independent community adaptation. Reports configuration observations, not proven exploitation. Requires the scoped AEGIS runner context. Redirects and authentication are not followed.");
  script_set_attribute(attribute:"solution", value:"Review the recorded observation against the application's security requirements.");
  script_set_attribute(attribute:"risk_factor", value:"None");
  script_set_attribute(attribute:"plugin_type", value:"remote");
  script_set_attribute(attribute:"plugin_publication_date", value:"2026/10/22");
  script_end_attributes();
  script_category(ACT_GATHER_INFO);
  script_family(english:"Web Servers");
  script_copyright(english:"Upstream attribution and licenses are preserved in the package.");
  script_require_keys("AEGIS/Community/Enabled");
  exit(0);
}
include("aegis_http_common.inc");
aegis_check(id:1337005, kind:"tcp");
