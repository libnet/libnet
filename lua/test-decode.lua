dofile"setup.lua"

do
    print"test: decode ipv4"

    local n = net.init("raw4", DEV) 

    n:udp{src=1, dst=2, payload=" "}
    n:ipv4{src="1.2.3.1", dst="1.2.3.2", protocol=17, len=20+4, options="AAAA"}

    local b0 = n:block()

    print"= constructed:"
    print(n:dump())
    hex_dump(b0)

    n:clear()
    print(n:dump())

    print"= decoded:"
    assert(n:decode_ipv4(b0))

    local ip1 = n:block(n:tag_below())
    local b1 = n:block()
    print(n:dump())
    hex_dump(b1)
    print""

    assert(b0 == b1)

    local bot = assert(n:tag_below())
    local top = assert(n:tag_above())

    assert(bot == 4)
    assert(n:tag_below(bot) == nil)
    assert(n:tag_above(bot) == 3)

    assert(top == 1)
    assert(n:tag_above(top) == nil)
    assert(n:tag_below(top) == 2)

    assert(n:tag_type(bot) == "ipv4 header", n:tag_type(bot))
    assert(n:tag_type(top) == "data", n:tag_type(top))

    assert(n:data{ptag=top, payload="\0"})

    local b2 = n:block()
    print(n:dump())
    hex_dump(b2)

    -- everything up to the checksum should be the same
    assert(b1:sub(1, 20+4+6) == b2:sub(1, 20+4+6))
    assert(b1:sub(20+4+7, 20+4+8) ~= b2:sub(20+4+7, 20+4+8))

    assert(n:block(n:tag_above()) == "\0")
    assert(n:block(n:tag_below()) == ip1)

    print"+pass"
end

print""

