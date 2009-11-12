require"net"

DEV="en0"

-- Quote a string into lua form (including the non-printable characters from
-- 0-31, and from 127-255).
function q(_)
  local fmt = string.format
  local _ = fmt("%q", _)

  _ = string.gsub(_, "\\\n", "\\n")
  _ = string.gsub(_, "[%z\1-\31,\127-\255]", function (x)
    --print("x=", x)
    return fmt("\\%03d",string.byte(x))
  end)

  return _
end


function dump(n, size)
    local b = n:block()
    print(n:dump())
    print("[["..q(b).."]]")

    if size then
        assert(#b == size, "block's size is not correct")
    end
end


