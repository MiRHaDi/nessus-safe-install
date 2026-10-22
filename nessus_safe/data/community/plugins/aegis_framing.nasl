# ------------------------------------------------------------------------------
# Copyright 2014 Schuberg Philis, Created by Glenn ten Cate
#
# Licensed under the Apache License, Version 2.0 (the "License");
# you may not use this file except in compliance with the License.
# You may obtain a copy of the License at
#
# http://www.apache.org/licenses/LICENSE-2.0
#
# Unless required by applicable law or agreed to in writing, software
# distributed under the License is distributed on an "AS IS" BASIS,
# WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
# See the License for the specific language governing permissions and
# limitations under the License.

# AEGIS-X reviewed adaptation, 2026-10-22. Upstream originals retained.
# schubergphilis/custom-nessus-plugins; semantics, scope gating and bounded I/O changed locally.
if (description)
{
  script_id(1337003);
  script_version("1.0");
  script_name(english:"AEGIS Community: Frame embedding policy");
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
aegis_check(id:1337003, kind:"framing");
