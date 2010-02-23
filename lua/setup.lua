print"============================================"

local keepgoing = nil

for _,v in ipairs(arg) do
  if v == "-k" then
    keepgoing = true
  end
end

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

function h(_)
  local fmt = string.format
  _ = string.gsub(_, ".", function (x)
    return fmt("%02x",string.byte(x))
  end)

  return _
end

function dump(n, size)
  local b = n:block()
  print(">")
  print(n:dump())
  print("size="..#b)
  --print("q=[["..q(b).."]]")
  print("h=[["..h(b).."]]")

  if size then
    assert(#b == size, "block's size is not expected, "..size)
  end
end

function test(n, f)
    print""
    print""
    print("=test: "..n)

    if not keepgoing then
        f()
        print("+pass: "..n)
    else
        local ok, emsg = pcall(f)
        if not ok then
            print("! FAIL: "..n)
        else
            print("+pass: "..n)
        end
    end
end

function hex_dump(s)
    print(h(s))
end

