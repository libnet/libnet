require"tostring"

-- Quote a string into lua form (including the non-printable characters from
-- 0-31, and from 127-255).
function quote(_)
    local fmt = string.format
    local _ = fmt("%q", _)

    _ = string.gsub(_, "\\\n", "\\n")
    _ = string.gsub(_, "[%z\1-\31,\127-\255]", function (x)
        --print("x=", x)
        return fmt("\\%03d",string.byte(x))
    end)

    return _
end

q = quote

-- binary to hex
function h(s)
    local function hex(s)
        return string.format("%02x", string.byte(s))
    end
    return "["..#s.."] "..string.gsub(s, ".", hex)
end

-- hex to binary
function b(s)
    if not s then
        return s
    end

    local function cvt (hexpair)
        n = string.char(tonumber(hexpair, 16))
        return n
    end

    local s = s:gsub("(..)", cvt)
    return s
end

