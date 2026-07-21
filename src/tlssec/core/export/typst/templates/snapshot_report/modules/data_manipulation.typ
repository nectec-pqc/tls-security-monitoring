/*
* Transform array of dictionaries into
* array of a pair between key and array filtered by that key.
*
* For example,
*
*     #groupby((
*       (key: 5, value: 1),
*       (key: 5, value: 2),
*       (key: 4, value: 3),
*     ), item => item.key)
* 
* Results in
*
* (
*   (
*     5,
*     (
*       (key: 5, value: 1),
*       (key: 5, value: 2),
*     ),
*   ),
*   (
*     4,
*     (
*       (key: 4, value: 3),
*     ),
*   ),
* )
*
* Assumes array is already sorted by the key.
*/
#let groupby(items, key_function) = {
  if items.len() == 0 {return ()}

  let item = items.at(0)
  let current_key = key_function(item)
  let current_group_members = (item,)
  let groups = ()

  for item in items.slice(1) {
    let next_key = key_function(item)
    if next_key == current_key {
      current_group_members.push(item)
      continue
    }

    groups.push((current_key, current_group_members))
    current_key = next_key
    current_group_members = (item,)
  }
  groups.push((current_key, current_group_members))
  return groups
}


#let groupby_dict(items, key_function) = {
  let groups = (:)
  for item in items {
    let key = str(key_function(item))
    let members = groups.at(key, default: none)
    if members == none {
      groups.insert(key, (item,))
    } else {
      members.push(item)
      groups.insert(key, members)
    }
  }
  return groups
}


// TODO: simplify
#let find_testssl_matching_nmap(testssls, nmap) = {
  // Try requiring that (ip, port) match first
  let find_ip_port_match() = {
    let ip_port_matches = testssls.filter(testssl => (
      testssl.ip == nmap.ip
      and testssl.port == nmap.port
    ))
    if ip_port_matches == () {
      return none
    }
    if ip_port_matches.len() == 1 {
      return ip_port_matches.at(0)
    }
    // If (ip, port) match is not unique,
    // try further matching testssl target host with nmap hostname.
    let hostname_matches = ip_port_matches.filter(testssl => (
      testssl.raw.targetHost == nmap.hostname
    ))
    if hostname_matches.len() > 1 {
      panic(
        "Can not match nmap item to testssl item",
        "Multiple testssl item exist with",
        (
          target_host: nmap.hostname,
          ip: nmap.ip,
          port: nmap.port,
        ),
      )
    }
    if hostname_matches == () {
      return none
    }
    return hostname_matches.at(0)
  }
  let ip_port_match = find_ip_port_match()
  if ip_port_match != none {
    return ip_port_match
  }
  // If (ip, port) match requirement is too strong,
  // allow searching for (testssl target host = nmap hostname, port) match
  // ignoring IP matching. This makes sense when target is given as a name that
  // happens to resolve to different IP by testssl and nmap due to things like
  // load balancer.
  let hostname_port_matches = testssls.filter(testssl => (
    testssl.raw.targetHost == nmap.hostname
    and testssl.port == nmap.port
  ))
  if hostname_port_matches == () {
    return none
  }
  if hostname_port_matches.len() > 1 {
    panic(
      "Can not match nmap item to testssl item",
      "Multiple testssl item exist with",
      (
        target_host: nmap.hostname,
        port: nmap.port,
      ),
    )
    return none
  }
  return hostname_port_matches.at(0)
}


#let load() = {
  // NOTE: These paths are relative to project-root
  let nmap = yaml("/data/nmap_extracts.yaml")
  let testssl = yaml("/data/testssl_extracts.yaml")
  let ssh_audit = yaml("/data/ssh_audit_extracts.yaml")
  // TODO: panic when (hostname, ip, port) is not unique
  // Warn: "Current report format does not support displaying multiple observations of the same endpoint"

  // Pre-compute commonly reused derived data
  nmap = nmap.map(item => {
    item.insert(
      "display_hostname",
      (if item.hostname == none {"-"} else {item.hostname}),
    )
    item.insert(
      "display_service",
      ((if item.tls_mode == "implicit" {"ssl/"} else {""}) + item.application_protocol),
    )
    item.insert(
      "scan_result",
      (
        // TODO: panic when there are testssl or ssh_audit left over
        testssl: find_testssl_matching_nmap(testssl, item),
        ssh_audit: ssh_audit.find(x => (
          x.ip == item.ip
          and x.port == item.port
        )),
      ).filter(x => x != none),
    )
    item.insert(
      "label",
      label(item.display_hostname + "_" + item.ip + "_" + str(item.port)),
    )
    item.insert(
      "socket_reference",
      link(
        item.label,
        raw(item.ip + ":" + str(item.port)),
      ),
    )
    return item
  })
  nmap = nmap.sorted(key: item => (
    // Sort missing hostname last
    item.hostname == none,
    // Sort domain names with TLD first
    item.display_hostname.split(".").rev(),
    item.ip,
    item.port,
  ))
  // Compile data into format fit for reporting
  return groupby(nmap, item => (item.display_hostname, item.ip))
}
