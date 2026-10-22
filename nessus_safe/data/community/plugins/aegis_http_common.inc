# SPDX-License-Identifier: Apache-2.0
# Copyright 2026 AEGIS-X contributors
# Self-contained bounded HTTP reader. Does not persist or report raw headers.

function aegis_trim(value)
{
  local_var s;
  s = ereg_replace(pattern:"^[ \t]+", replace:"", string:value);
  return ereg_replace(pattern:"[ \t]+$", replace:"", string:s);
}

function aegis_header(headers, name)
{
  local_var line, match, value, found;
  found = 0;
  foreach line (split(headers, sep:'\r\n', keep:0))
  {
    match = eregmatch(pattern:"^" + name + ":[ \t]*(.*)$", string:tolower(line));
    if (isnull(match)) continue;
    if (found) return "AEGIS_DUPLICATE";
    value = aegis_trim(value:match[1]);
    found = 1;
  }
  if (!found) return NULL;
  return value;
}

function aegis_result(id, status, port, method)
{
  display("AEGIS_RESULT\t", id, "\t", status, "\t", port, "\t", method, "\n");
}

function aegis_fetch(host, port, tls, method)
{
  local_var soc, request, response, chunk, i;
  if (tls) soc = open_sock_tcp(port, timeout:5, transport:ENCAPS_SSLv23);
  else soc = open_sock_tcp(port, timeout:5, transport:ENCAPS_IP);
  if (!soc) return NULL;
  request = string(method, ' / HTTP/1.1\r\nHost: ', host, '\r\nUser-Agent: AEGIS-Community-NASL/1.1\r\nConnection: close\r\n\r\n');
  send(socket:soc, data:request);
  response = "";
  for (i = 0; i < 4; i++)
  {
    chunk = recv(socket:soc, length:4096, timeout:3);
    if (!chunk) break;
    response += chunk;
    if ('\r\n\r\n' >< response) break;
  }
  close(soc);
  return response;
}

function aegis_check(id, kind)
{
  local_var host, port, tls, fixture, soc, response, expected_ip, method, supplied, authorized_host;
  local_var status, header, match, csp, ctype, line, total, secure, httponly, same;
  if (int(get_kb_item("AEGIS/Community/Enabled")) != 1) exit(0);
  host = tolower(get_kb_item("AEGIS/Host"));
  authorized_host = tolower(get_kb_item("AEGIS/AuthorizedHost"));
  port = int(get_kb_item("AEGIS/Port"));
  tls = int(get_kb_item("AEGIS/TLS"));
  fixture = int(get_kb_item("AEGIS/Fixture"));
  expected_ip = get_kb_item("AEGIS/ExpectedIP");
  if (!isnull(expected_ip) && get_host_ip() != expected_ip)
  { display('AEGIS_SCOPE_REFUSED\n'); exit(1); }
  if (fixture)
  {
    if (host != "fixture.invalid" || (port != 18081 && port != 18082))
    { display('AEGIS_SCOPE_REFUSED\n'); exit(1); }
  }
  else
  {
    if (isnull(authorized_host) || host != authorized_host ||
        !eregmatch(pattern:"^[a-z0-9]([a-z0-9.-]*[a-z0-9])?$", string:host) ||
        isnull(expected_ip) || (port != 80 && port != 443))
    { display('AEGIS_SCOPE_REFUSED\n'); exit(1); }
  }
  if (kind == "tcp")
  {
    soc = open_sock_tcp(port, timeout:5);
    if (!soc) { aegis_result(id:id, status:"unreachable", port:port, method:"TCP"); exit(0); }
    close(soc);
    aegis_result(id:id, status:"tcp_open", port:port, method:"TCP");
    exit(0);
  }
  # Fixture response is explicit test data; production always performs I/O.
  response = NULL;
  if (fixture) response = get_kb_item("AEGIS/FixtureResponse");
  supplied = !isnull(response);
  method = "fixture_data";
  if (isnull(response))
  {
    method = "HEAD";
    response = aegis_fetch(host:host, port:port, tls:tls, method:method);
    if (isnull(response)) { aegis_result(id:id, status:"unreachable", port:port, method:method); exit(0); }
  }
  if (!('\r\n\r\n' >< response) || !eregmatch(pattern:"^HTTP/[0-9.]+ [0-9]{3} ", string:response))
  { aegis_result(id:id, status:"incomplete_response", port:port, method:method); exit(0); }
  # Ignore body, redirects, authentication and all response values in output.
  match = eregmatch(pattern:"^HTTP/[0-9.]+ ([0-9]{3}) ", string:response);
  if (!supplied && (int(match[1]) == 405 || int(match[1]) == 501))
  {
    method = "GET";
    response = aegis_fetch(host:host, port:port, tls:tls, method:method);
    if (isnull(response)) { aegis_result(id:id, status:"unreachable", port:port, method:method); exit(0); }
    if (!('\r\n\r\n' >< response) || !eregmatch(pattern:"^HTTP/[0-9.]+ [0-9]{3} ", string:response))
    { aegis_result(id:id, status:"incomplete_response", port:port, method:method); exit(0); }
    match = eregmatch(pattern:"^HTTP/[0-9.]+ ([0-9]{3}) ", string:response);
  }
  if (int(match[1]) >= 500)
  { aegis_result(id:id, status:"upstream_error", port:port, method:method); exit(0); }
  # split() below stops at the first empty line so body text cannot be a header.
  header = "";
  foreach line (split(response, sep:'\r\n', keep:1))
  {
    if (line == '\r\n' || line == "") break;
    header += line;
  }
  # NASL split keep semantics are checked against positive/negative fixtures.
  status = "not_applicable";
  if (kind == "hsts")
  {
    if (!tls) status = "not_applicable_cleartext";
    else
    {
      csp = aegis_header(headers:header, name:"strict-transport-security");
      match = eregmatch(pattern:"(^|;)[ \t]*max-age[ \t]*=[ \t]*([0-9]+)[ \t]*(;|$)", string:csp);
      if (isnull(csp)) status = "missing";
      else if (csp == "AEGIS_DUPLICATE") status = "ambiguous_duplicate";
      else if (!isnull(match) && int(match[2]) > 0) status = "present_positive_max_age";
      else status = "invalid_or_disabled";
    }
  }
  if (kind == "nosniff")
  {
    csp = aegis_header(headers:header, name:"x-content-type-options");
    if (isnull(csp)) status = "missing";
    else if (csp == "nosniff") status = "present";
    else status = "invalid_or_duplicate";
  }
  if (kind == "framing")
  {
    ctype = aegis_header(headers:header, name:"content-type");
    csp = aegis_header(headers:header, name:"content-security-policy");
    if (isnull(ctype) || !("text/html" >< ctype)) status = "not_applicable_non_html_or_unknown";
    else if (eregmatch(pattern:"(^|;)[ \t]*frame-ancestors[ \t]+'(none|self)'[ \t]*(;|$)", string:csp))
      status = "present_csp_frame_ancestors";
    else
    {
      csp = aegis_header(headers:header, name:"x-frame-options");
      if (isnull(csp)) status = "missing";
      else if (csp == "deny" || csp == "sameorigin") status = "present_xfo";
      else status = "invalid_or_duplicate";
    }
  }
  if (kind == "legacy_xss")
  {
    csp = aegis_header(headers:header, name:"x-xss-protection");
    if (isnull(csp) || csp == "0") status = "legacy_filter_disabled_or_absent";
    else status = "legacy_filter_enabled_review";
  }
  if (kind == "csp")
  {
    csp = aegis_header(headers:header, name:"content-security-policy");
    if (isnull(csp)) status = "missing";
    else if (csp == "AEGIS_DUPLICATE") status = "multiple_policies_review";
    else if ("'unsafe-inline'" >< csp || "'unsafe-eval'" >< csp) status = "present_unsafe_keyword_review";
    else status = "present_policy_review";
  }
  if (kind == "referrer")
  {
    csp = aegis_header(headers:header, name:"referrer-policy");
    if (isnull(csp)) status = "missing_optional";
    else if (csp == "unsafe-url" || csp == "no-referrer-when-downgrade") status = "permissive_review";
    else if (csp == "no-referrer" || csp == "same-origin" || csp == "strict-origin" || csp == "strict-origin-when-cross-origin") status = "present";
    else status = "unclassified_or_duplicate_review";
  }
  if (kind == "cookies")
  {
    total = secure = httponly = same = 0;
    foreach line (split(header, sep:'\r\n', keep:0))
    {
      line = tolower(line);
      if (!eregmatch(pattern:"^set-cookie:", string:line)) continue;
      total++;
      if (eregmatch(pattern:";[ \t]*secure[ \t]*(;|$)", string:line)) secure++;
      if (eregmatch(pattern:";[ \t]*httponly[ \t]*(;|$)", string:line)) httponly++;
      if (eregmatch(pattern:";[ \t]*samesite[ \t]*=[ \t]*(strict|lax|none)[ \t]*(;|$)", string:line)) same++;
    }
    if (!total) status = "no_cookies_observed";
    else if ((!tls || secure == total) && httponly == total && same == total) status = "attributes_observed";
    else status = "cookie_attributes_review";
  }
  aegis_result(id:id, status:status, port:port, method:method);
  exit(0);
}
