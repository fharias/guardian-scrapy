local tokens_key = KEYS[1]
local ts_key     = KEYS[2]
local rate  = tonumber(ARGV[1])  -- tokens por segundo
local burst = tonumber(ARGV[2])  -- capacidad máxima

local t = redis.call('TIME')
local now = tonumber(t[1]) * 1000 + math.floor(tonumber(t[2]) / 1000)

local tokens = tonumber(redis.call('GET', tokens_key))
local last   = tonumber(redis.call('GET', ts_key))
if tokens == nil or last == nil then
  tokens = burst
  last = now
end

local elapsed = math.max(0, now - last) / 1000
tokens = math.min(burst, tokens + elapsed * rate)

local allowed = 0
if tokens >= 1 then
  tokens = tokens - 1
  allowed = 1
end

local ttl = math.ceil(burst / rate * 1000) + 1000
redis.call('SET', tokens_key, tokens, 'PX', ttl)
redis.call('SET', ts_key, now, 'PX', ttl)

return { allowed, math.floor(tokens) }