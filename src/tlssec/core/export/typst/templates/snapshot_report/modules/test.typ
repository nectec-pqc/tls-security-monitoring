#import "data_manipulation.typ" as op

#let assert(result, expected, label: "") = {
  if result == expected [
    = #label pass
  ] else [
    = #label fail
    == result
    #repr(result)
    == expected
    #repr(expected)
  ]
}


#{
  let result = op.groupby((
    (key: 5, value: 1),
    (key: 5, value: 2),
    (key: 4, value: 3),
  ), item => item.key)
  let expected = (
    (
      5,
      (
        (key: 5, value: 1),
        (key: 5, value: 2),
      ),
    ),
    (
      4,
      (
        (key: 4, value: 3),
      ),
    ),
  )
  assert(result, expected, label: "groupby")
}


#{
  let result = op.groupby_dict((
    (key: 5, value: 1),
    (key: 5, value: 2),
    (key: 4, value: 3),
  ), item => item.key)
  let expected = (
    "5": (
      (key: 5, value: 1),
      (key: 5, value: 2),
    ),
    "4": (
      (key: 4, value: 3),
    ),
  )
  assert(result, expected, label: "groupby_dict")
}


#{
  let result = op.find_testssl_matching_nmap(
    (
      (ip: "1.1.1.1", port: 80, raw: (targetHost: "a.net")),
      (ip: "1.1.1.4", port: 22, raw: (targetHost: "a.net")),
      // NOTE: uncomment to add a duplicate and expect a panic
      //(ip: "1.1.1.4", port: 22, raw: (targetHost: "a.net")),
      (ip: "1.1.1.4", port: 22, raw: (targetHost: "b.net")),
    ),
    (ip: "1.1.1.4", port: 22, hostname: "a.net"),
  )
  let expected = (ip: "1.1.1.4", port: 22, raw: (targetHost: "a.net"))
  assert(result, expected, label: "find_testssl_matching_nmap - match all")
}


#{
  let result = op.find_testssl_matching_nmap(
    (
      (ip: "1.1.1.1", port: 80, raw: (targetHost: "a.net")),
      (ip: "1.1.1.4", port: 22, raw: (targetHost: "a.net")),
      // NOTE: uncomment to add a duplicate (hostname, port) and expect a panic
      //(ip: "1.1.1.2", port: 22, raw: (targetHost: "a.net")),
    ),
    (ip: "1.1.1.3", port: 22, hostname: "a.net"),
  )
  let expected = (ip: "1.1.1.4", port: 22, raw: (targetHost: "a.net"))
  assert(result, expected, label: "find_testssl_matching_nmap - match (hostname, port)")
}
