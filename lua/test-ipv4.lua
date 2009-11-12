dofile"setup.lua"

do
  print"test: ipv4, replace with identical"

  local n = net.init("link", DEV) 
  local iptag0 = n:ipv4{src="1.2.3.1", dst="1.2.3.2", protocol=2, len=20+4, options="AAAA"}
  n:eth{src="01:02:03:04:05:01", dst="01:02:03:04:05:02"}

  print("ipv4 initial", iptag0)
  dump(n)
  local block0 = n:block()

  local iptag1 = n:ipv4{src="1.2.3.1", dst="1.2.3.2", protocol=2, len=20+4, options="AAAA", ptag=iptag0}
  print("ipv4 final", iptag1)
  dump(n)
  local block1 = n:block()
  assert(iptag0 == iptag1)
  assert(block0 == block1)
end

do
  print"test: ipv4, replace eth with ipv4"

  local n = net.init("link", DEV) 
  local eth = n:eth{src="01:02:03:04:05:01", dst="01:02:03:04:05:02"}
  local ok,emsg=pcall(n.ipv4, n, {src="1.2.3.1", dst="1.2.3.2", protocol=2, len=20+4, options="AAAA", ptag = eth})
  assert(not ok, emsg)
  print("successfully failed", emsg)
end

do
  local n = net.init("link", DEV) 
  ok=pcall(n.ipv4, n, {src="1.2.3.1", dst="1.2.3.2", protocol=2, len=20+4, options="AAAA"})
  eth = n:eth{src="01:02:03:04:05:01", dst="01:02:03:04:05:02"}
  assert(ok, "net:ipv4 fails to construct ipv4 options correctly")
end


print""

do
    print"test: +ipv4 w/options"
    
    local n = net.init("link", DEV) 
    local ptag = n:ipv4{src="1.2.3.1", dst="1.2.3.2", protocol=2, len=20+4, options="AAAA"}
    n:eth{src="01:02:03:04:05:01", dst="01:02:03:04:05:02"}

    dump(n, 14+24)

    n:ipv4{src="1.2.3.1", dst="1.2.3.2", protocol=2, len=20+4, options="BB", ptag=ptag}

    dump(n, 14+24)

    n:ipv4{src="1.2.3.1", dst="1.2.3.2", protocol=2, len=20+0, ptag=ptag}

    dump(n, 14+20)

    n:ipv4{src="1.2.3.1", dst="1.2.3.2", protocol=2, len=20+8, options="DDDDD", ptag=ptag}

    dump(n, 14+28)
end

print""

do
    print"test: -ipv4 with invalid ptag"

    assert(not pcall(
        n.ipv4, n, {src="1.2.3.1", dst="1.2.3.2", protocol=2, len=20+8, options="DDDDD", ptag=999}
        )
    )
end

print""


